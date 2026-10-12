# Zigerions

**Category:** Rev | **Difficulty:** Hard | **Points:** 131 | **Flag:** `ctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}`

## Challenge Description

> life is what but a maze with no wrong answers
>
> flag format: psctf{...}
>
> **- @G0daPwN.exe**

We get a password-protected archive `zigerions.zip` (password `infected`) with a single 43 MB file: `Pickle_Riiiiick`.

## Initial Analysis

This challenge is a Russian-doll stack of fake-outs. The whole game is deciding which layers actually matter and which are elaborate time-wasters:

1. A Linux ELF (`Pickle_Riiiiick`) that just drops a Windows `update.exe`.
2. `update.exe` is a PyInstaller loader hiding an encrypted second EXE.
3. That EXE is VMProtect-packed and, when run, drops a Game Boy ROM **and** a tiny file named `svchost`.
4. The Game Boy ROM contains a huge, intimidating, and completely **fake** virtual machine.
5. `svchost` is a deliberately broken ELF that's really just a container for an AES key + ciphertext.
6. AES-128-ECB decryption of that ciphertext gives the flag.

Starting at the top:

```text
$ file Pickle_Riiiiick
Pickle_Riiiiick: ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

43 MB is absurd for a CTF binary, and it's *not stripped*, so symbols survive. Grepping them points right at the payload:

```text
0000000000401805 T main
00000000004ae0e0 D payload
0000000002d54c40 D payload_len
```

`main` reads `$HOME`, makes `$HOME/.cache/.icons/.hidden`, writes an embedded buffer to `update.exe`, chmods it, and prints "This is just the beginning welcome to my chaotic mind." It's a pure wrapper — we can carve `update.exe` straight out of the `.data` section at the `payload` offset without ever running it.

## The Core Concept

The hard part of Zigerions isn't any single algorithm — it's **resisting the rabbit holes**. VMProtect, a full playable Game Boy game, and a giant fake VM opcode table are all there to make you waste hours. The shortest path is to keep asking one question at every layer: *what does this thing actually read, write, or launch?*

- For the VMProtect EXE, you don't unpack it at all — you just run it under Wine with file/exec tracing and watch which files it drops.
- The `AURA.gb` Game Boy ROM is a decoy: its code calls `0x0af2`, where the first byte is `0xc9` (Game Boy `RET`), so the giant `VMOP_*` opcode table right after it is **never interpreted**. Convincing, but unreachable.
- The real prize is the 5,624-byte `svchost` file, which isn't an executable at all — it's an AES puzzle wearing an ELF costume.

## Solving It

**Layer 1 → `update.exe`.** The `.data` section starts at VA `0x4ae0c0` / file offset `0xae0c0`, so the `payload` symbol at VA `0x4ae0e0` sits at offset `0xae0e0`; `payload_len` is at offset `0x2954c40`:

```python
blob = Path("Pickle_Riiiiick").read_bytes()
payload_len = struct.unpack_from("<I", blob, 0x2954C40)[0]
Path("update.exe").write_bytes(blob[0xAE0E0:0xAE0E0 + payload_len])
```

Result: `update.exe`, a PE32+ Windows executable.

**Layer 2 → `layer2.exe`.** `pyi-archive-viewer` shows `update.exe` is a PyInstaller bundle, and its `stub` entry carries the unpacking constants:

```python
XOR_KEY = [0xA5, 0x3C, 0xFF, 0x00, 0x55, 0xAA]
MARKER  = b"<<<PAYLOAD_START>>>"
```

The stub finds the marker, reads a 4-byte LE size, XORs that many bytes with the repeating key, and reverses the result. [`extract_layers.py`](extract_layers.py) reproduces exactly that, producing a ~5.5 MB PE.

**Layer 3 → dropped files (via dynamic analysis).** `layer2.exe` has `.vmp0`/`.vmp1` sections — VMProtect. Rather than unpack it, run it under Wine with tracing:

```bash
WINEDEBUG=+process,+file,+exec xvfb-run -a wine layer2.exe > wine.log 2>&1
grep -E 'AURA\.gb|svchost|WriteFile|DeleteFile' wine.log
```

The log shows it writes a 32 KB `AURA.gb`, tries to launch it, deletes it, then writes a 5,624-byte `svchost`. `svchost` is left behind in `~/.wine/drive_c/users/<user>/AppData/Local/Temp/` so you can just copy it out. `AURA.gb` gets deleted fast; if you want to grab it to confirm it's a decoy, [`watch.c`](watch.c) is a tiny inotify tool that hard-links the file the instant it's written. (You don't need the ROM for the flag — it's the decoy.)

**The real target — `svchost`.** It looks like a Linux ELF but it's malformed on purpose: no `.text`, entry point inside `.rodata`, and the bytes at that "entry point" are the ASCII string `M68K_AES_FLAGKEY`. Its symbols are the giveaway:

```text
$ nm -n svchost.bin
0000000000401000 R __3   # the 16-byte key "M68K_AES_FLAGKEY"
0000000000401010 R __2   # AES round constants (01 02 04 08 10 20 40 80 1b 36)
0000000000401020 R __1   # AES S-box
0000000000401120 R __0   # inverse AES S-box
0000000000402220 D __4   # 48 bytes of ciphertext
```

So we have an AES key and AES tables, and *no IV stored anywhere* — that strongly implies ECB. [`solve.py`](solve.py) reads the key out of `svchost.bin` and decrypts the 48-byte `.data` object:

```python
key = b"M68K_AES_FLAGKEY"
ct  = bytes.fromhex("674e0e33...6c0d35b3")   # the __4 object
plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
```

```text
$ python3 solve.py
psctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}
```

The decrypted bytes end in nine `0x09` bytes — valid PKCS#7 padding, confirming the key and mode are right.

## Flag

The AES decryption yields the flag body with the challenge's stated `psctf{...}` prefix; the flag accepted on the platform was:

```text
ctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}
```

## Key Takeaways

- Layered "which doll matters?" challenges reward triage over brute force — ask what each layer reads/writes/launches and skip the scenery.
- You can defeat packers like VMProtect without unpacking them: run under Wine with `WINEDEBUG=+file,+exec` and just observe the dropped artifacts.
- A fake VM is a classic decoy. Check whether its interpreter is even reachable (here, a `RET` right before the opcode table meant it never ran).
- A file can claim to be an ELF and still just be a data container — bogus entry points and ASCII "code" are a tell.
- An AES key plus S-boxes and no IV is a loud hint for AES-ECB; PKCS#7 padding on the result is your correctness check.
