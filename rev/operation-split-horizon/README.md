# Operation Split Horizon

**Category:** Rev | **Difficulty:** Hard | **Points:** 280 | **Flag:** `pwnsec{a41f2691c3f1bcf72d0ec060c70d6ce7}`

## Challenge Description

> From:    soc-lead@corptech.local
> To:      ir-team@corptech.local
> Subject: URGENT: IT does not distribute Shawarma via email
>
> Bad news: The promised "Free Double Meat Shawarma" was a lie. Worse news: Braa clicked it anyway.
>
> Instead of extra garlic sauce, his workstation received a payload. The attacker rooted around, found something shiny, and exfiltrated it. Attached is the network capture of Braa's poor life choices and the lure page itself.
>
> Please figure out what the attacker took so I know whether to fix it or just update my resume.
>
> URL: <http://`<redacted-ip>`/>
>
> **- @Nyx**

We're given a password-protected archive (password `infected`) containing one file: `challenge.pcap` — a packet capture of a Windows box getting owned. (The PCAP itself is >256 KB and isn't redistributed in this repo; the solve scripts here replay against it or against the decrypted intermediates included below.)

## Initial Analysis

The whole infection chain is in the capture. A TCP conversation summary immediately flags one host talking way more than the Windows background noise:

```bash
tshark -r challenge.pcap -q -z conv,tcp
```

Workstation `10.0.15.134` keeps hitting `<redacted-ip>` over HTTP while pretending the host is `cdn-assets-update.com`. The HTTP requests sketch the whole story:

```text
GET  cdn-assets-update.com  /index.html
GET  cdn-assets-update.com  /update/patch_kb5034441
POST cdn-assets-update.com  /api/register
GET  cdn-assets-update.com  /api/tasks/<session UUID>
POST cdn-assets-update.com  /api/result/<session UUID>
```

Export the HTTP objects and two are instantly interesting: the lure page `index.html` and the fake "update" `patch_kb5034441`.

The lure is a **ClickFix** page — JavaScript that assembles `cmd /c powershell -ep bypass -w hidden -enc <base64>` and nags the victim to run it. Decoding the base64 as UTF-16LE gives a PowerShell dropper that disables AMSI, bails if the machine has fewer than two CPUs (anti-sandbox), ROT13-decodes the download URL, and AES-decrypts the "patch." It also passes a marker, `c7e1f5b9d20468f6`, to the dropped binary — which matters later for the C2 key.

## The Core Concept

The title is a literal spoiler. **Split Horizon** means the stolen data is split across two different network channels: half of it rides out in an HTTP cookie, the other half rides out in DNS queries. Neither channel alone contains the answer — you have to recombine them.

But to get there you first have to speak the malware's private protocol. The chain is:

- **AES-256-CBC + HMAC** to decrypt `patch_kb5034441` into `svchost_update.exe`.
- A custom **XTEA-like loader** (spot the `0x9e3779b9` TEA constant) that decrypts stage 2, which manually maps stage 3 — a DLL (`stage3_810.bin`, included) holding the real network logic.
- A **ratcheting ChaCha20** C2 protocol where the key changes after *every* message, so packets must be processed strictly in order.
- A tiny custom **SBVM4** bytecode VM whose output derives the final keys.
- The fragment-routing scheme that splits the exfil packet across HTTP + DNS and tags each piece with a truncated HMAC instead of a sequence number.

## Solving It

**1. The AES key is XOR-split in the PowerShell.** The dropper stores four 16-byte arrays and XORs them in pairs to build an AES-256 key:

```python
key = bytes(a ^ b for a, b in zip(x1, m1)) + bytes(a ^ b for a, b in zip(x2, m2))
# 7d4a70319ceca0a4b6f109019b9ebaa2040bcf7fc854f0c1088819120f7a5526
```

The blob is `[16-byte IV][AES-CBC ciphertext][32-byte HMAC-SHA256]`, HMAC key = `SHA256(key || IV)` over `IV || ct`. Verify, decrypt, unpad → `svchost_update.exe`. Peeling the XTEA loader gives `stage2.bin`, which manually maps `stage3_810.bin` (the DLL with the protocol).

**2. Rebuild the C2 master key.** Stage 3's strings are unusually helpful (`SBv4 transcript root`, `record-key`, `advance`, `SBVM4 route`). Protocol constants are XOR-obfuscated with `5a 3b 7c 9d`, which decodes to `auth = "C2-AUTH-2026:"` and two salts. The DLL also hashes four NT API names with its own rotate/hash function. Combining it all:

```python
k1 = SHA256(auth + marker + salt1)[:16]
k2 = api_hash_bytes ^ salt2
master = HMAC_SHA256(k1 + k2, b"SBv4 transcript root")
```

[`decrypt_c2_v2.py`](decrypt_c2_v2.py) does this from `stage3_810.bin` + `challenge.pcap`.

**3. Decrypt and ratchet the C2 conversation.** Six HTTP bodies (frames 380/443/459/529/540/567) carry the protocol. Each record derives its own key, ChaCha20-decrypts (skipping the first 64-byte keystream block, so `seek(64)`), then ratchets the master forward:

```python
record_key = HMAC_SHA256(master, b"record-key" + direction + header)
cipher = ChaCha20.new(key=record_key, nonce=nonce); cipher.seek(64)
pt = cipher.decrypt(ct)
master = HMAC_SHA256(master, b"advance" + tag + SHA256(header + ct))   # ratchet
```

Decrypt a packet with the wrong (stale) master and you get garbage — that's the ratchet. The conversation reveals the attacker chose to steal `challenge-vault-entry` (user `ctf-lab-user`) with `blob_size = 102` (amid decoys like `netflix-password-dont-judge-me`). That **102** feeds the next step.

**4. Emulate SBVM4.** Frame 540 decompresses to a COFF object (`c2_540.dec`, included) whose `.rdata` holds a 0x7a-byte bytecode blob. [`vm_task3.py`](vm_task3.py) is a ~40-line interpreter (8 regs, 256-byte memory, load/add/xor/mul/rotate/jump/loop). Its 64-byte input is `transcript_digest(32) + env_hash(16) + blob_size=102(4 LE) + SHA256(session_uuid)[:12]`. The output is turned into two keys:

```python
context_key = SHA256(b"SBVM4 context" + vm_output)
route_key   = SHA256(b"SBVM4 route"   + vm_output)
```

Getting `blob_size = 102` (not some generic length) right is the easy place to trip.

**5. Un-split the horizon.** The final POST hides the loot in a cookie `X-Access-Package=...` — split on dots and URL-safe-base64-decode for **11 fragments**. Simultaneously the victim makes weird hex-subdomain DNS lookups like `ca2b0ae3cf01a55a053f25dd.cdn-assets-update.com` for **6 more fragments** (queries under `cdn-metrics-sync.com` are decoys). None of the 17 carry a sequence number — their first 4 bytes are truncated HMAC routing tags, so you brute the index for each:

```python
for idx in range(17):
    if HMAC_SHA256(route_key, b"fragment" + LE16(idx) + LE16(17) + frag[4:])[:4] == frag[:4]:
        ordered[idx] = frag[4:]
```

This both rejects the DNS decoys and reorders the HTTP/DNS pieces into a 133-byte packet.

**6. Final decrypt.** The packet is `[5-byte marker][12-byte nonce][100-byte ct][16-byte tag]`, ChaCha20 with `SHA256(context_key + nonce)`, again `seek(64)`. [`reconstruct_exfil.py`](reconstruct_exfil.py) runs the VM, orders the fragments, rebuilds the packet, and decrypts it. The plaintext is a 20-byte header + 80 bytes of UTF-16LE; the header's first word is the CRC32 of the body (a final integrity check). Decoding from offset 20:

```text
$ python3 reconstruct_exfil.py
... keyok True
$ python3 -c "print(open('exfil_plain.bin','rb').read()[20:].decode('utf-16le'))"
pwnsec{a41f2691c3f1bcf72d0ec060c70d6ce7}
```

## Flag

```text
pwnsec{a41f2691c3f1bcf72d0ec060c70d6ce7}
```

## Key Takeaways

- A single PCAP can hold an entire kill chain: lure, downloader, payload, C2 tasking, reports, and exfil.
- Never trust friendly names — `patch_kb5034441` and `svchost_update.exe` are the malware.
- Ratcheting key schedules force in-order processing; one packet out of sequence = garbage.
- COFF objects pushed over C2 are legitimate reversing targets, and tiny custom VMs usually aren't scary once you list the opcodes and feed the exact input layout.
- When the title says "Split Horizon," check whether data is divided across protocols — here you literally needed both HTTP cookies and DNS queries.
- Validate intermediates (HMAC routing tags, the derived route key, the final CRC32) so you *know* the recovered bytes aren't a coincidence.
