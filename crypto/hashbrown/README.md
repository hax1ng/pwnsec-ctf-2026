# Hashbrown

**Category:** Crypto | **Difficulty:** Elite | **Points:** 295 | **Flag:** `pwnsec{9df232265c0408af}`

## Challenge Description

> I mixed two hash recipes and let them share one secret seasoning.
>
> One side gives you a small menu of faulty SHA-256 executions. The other side will not reveal hashes directly, except for one digest that must be unlocked.
>
> Recover enough of the session state and submit a 1024-byte payload that matches the target.
>
> **- @Curiosity**

We're given the service source (`main.py` plus the hash implementations `sha256.py`, `sha256_faults.py`, `xxh3_custom.py`) and a live TCP service.

## Initial Analysis

The service (`main.py`) has a four-option menu and holds two secrets per session:

```python
sha_key = KNOWN_24_BYTE_PREFIX || RANDOM_31_BYTE_SUFFIX   # exactly 55 bytes
seed    = random 64-bit integer
```

The menu:

- **FaultSHA** — returns `faulty_sha256_digest(sha_key, name)`. A "fault" literally flips **one bit in the SHA-256 Python source** before `exec`-ing it (`sha256_faults.py`).
- **IIHashEqualBatch** — takes up to 4096 pairs of 257-byte messages and returns, per pair, a single bit: do the two custom-XXH3 digests match? It never reveals a digest.
- **UnlockDigest** — once, given the token `sha256(b"unlock:" + sha_key)`, reveals the XXH3 digest of 257 zero bytes.
- **GetFlag** — wants a 1024-byte payload whose XXH3 digest equals `sha256(b"target:" + sha_key + seed_le).digest()[:16]`.

The stages chain: recover the key → recover the seed → forge the preimage. No password lists or ordinary hash cracking — the whole challenge is undoing arithmetic that the weakened implementations accidentally expose.

## The Vulnerability / Core Concept

Three separate weaknesses, one per stage.

### 1. Two SHA faults expose both ends of an 8-round bridge

The key is 55 bytes — the largest message that still fits one padded 64-byte SHA block, so there's no carried-over state to worry about. Two faults are enough:

- **`r24`** turns `for t in range(64)` into `range(24)`: SHA stops after round 23, so the digest (minus the fixed feed-forward) is `state24`.
- **`thr35`** turns `if t <= 15` into `if t <= 35`. SHA then reads schedule words `W[16..35]` from past the end of the block; Python returns empty slices → `int()` → `0`. Every later schedule word only depends on this zeroed region, so `W[16..63] = 0`. All 64 rounds run, just with zero schedule words after 15.

Undo the final feed-forward by subtracting the SHA initial values mod `2^32`. The `thr35` state is then rewound through 48 rounds that each used a **known** word (zero) to land on `state16`. Now both `state16` and `state24` are known, bracketing an 8-round gap. Eight rounds is exactly enough for all eight registers to shift through, so the 8 injected schedule words `W[16..23]` are uniquely determined by rearranging the round equation for each `W[t]`.

Finally, run the message schedule backward:

```text
W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]   (mod 2^32)
```

`W[16..20]` directly reveal `W[9..13]`; the next three reveal `sigma0(W[6..8])`. SHA's `sigma0` is XORs/rotations/shift — a linear map over `GF(2)` — so build its 32x32 bit matrix, invert it, and recover `W[6..8]`. Assembling `W[0..15]` and stripping padding yields all **55 key bytes**, which produce the UnlockDigest token and reveal the XXH3 digest of 257 zero bytes (used later to pick the right seed candidate).

### 2. The equality oracle leaks the seed's carry classes

The SHA key expands (via `delta_words_from_key`) into 24 known 64-bit deltas; the 192-byte XXH3 secret is `secret[2i] = K[2i]+delta[2i]+seed`, `secret[2i+1] = K[2i+1]+delta[2i+1]-seed`, all mod `2^64`. So every secret word is known **except the seed**.

The accumulator update per 64-bit input word is essentially `d = x ^ k; acc[lane^1] += x; acc[lane] += low32(d)*high32(d)`. The trick: craft two messages where every unrelated term is identical, the raw `+x` changes cancel (choose opposite deltas in the same lane), and only two controlled multiplication terms can differ. The oracle then tells you whether `G(guess) == G(real_seed)` where `G(s) = Fq1(s) XOR Fq2(s)` and each `Fq` is `low32(C[q] ± s)`.

`G` has the form `x XOR (x+D)` or `x XOR (T-x)` — which is really a description of a **carry/borrow chain**. A tiny carry automaton (state = one carry bit) can both enumerate one seed representative per distinct `G` value and expand any discovered `G` back to its preimage bucket, avoiding `2^32` guesses. Pick the map with the smallest image, find the matching bucket, then intersect with a second carry map. Recover `seed mod 2^32` first, use it to fix the carries into each high half, then repeat for the top 32 bits. The 1024 final high-half candidates are disambiguated by locally hashing 257 zero bytes with each and comparing to the unlocked digest. Full seed recovery took ~54k equality pairs, well inside the 900 s budget.

### 3. The XXH3 finalizer is algebraically invertible — so forge the accumulator

GetFlag wants a real 1024-byte preimage, not just the recovered state. The merge finalizer per 64-bit half is:

```python
x ^= x >> 37;  x *= 0x165667919E3779F9;  x ^= x >> 32
```

All reversible (right-xor-shift undoes MSB-first; the odd multiplier is invertible mod `2^64`). Inverting both halves and subtracting the length constants leaves two target sums of `fold64(a,b) = low64(a*b) XOR high64(a*b)` terms. By choosing the target accumulator cleverly (zeroing one fold argument via `C XOR C = 0`), the 128-bit target splits into two independent 64-bit equations `fold64(c0,z0) + fold64(c1,z1) = wanted`. Each is solved with a Pollard-style **distinguished-point claw search** (~`2^32` work, no huge table) — the GPU helper for this (`fold_claw.cu`) is environment-specific and not included here.

Turning the accumulator into bytes exploits the same `low32(x^k)*high32(x^k)` structure: if an input word matches the secret word in either its low or high 32 bits, that product is zero. Per lane, use 14 words equal to their secret words plus 2 words with one matching half and one free half; all 16 products vanish and the two free halves let you dial in the exact 64-bit modular sum of raw words (remembering raw words from lane `i` land in `acc[i^1]`). Do that for all 8 lanes and the payload realizes the exact target accumulator.

## Exploitation

Full exploit: **`solve.py`** (end-to-end). Challenge source for reference: `main.py`, `sha256.py`, `sha256_faults.py`, `xxh3_custom.py`. `solve.py` has a local self-test mode that spawns `main.py` with deterministic secrets:

```bash
python3.13 -u solve.py                       # local self-test
python3.13 -u solve.py --remote --host CHALLENGE_HOST   # live
```

The Python side needs `pwntools` and `numpy`; the two fold claw searches were offloaded to a CUDA host. Successful run:

```text
[*] requesting r24 and thr35 SHA faults
[+] SHA key = 5b0de77c5ad3bef9...70b370fd4bfc0e
[+] unlocked zero digest = 2e29646b41adbb8f300054ab22b96979
[+] seed low32 = 4155ec1c (45195 equality pairs)
[+] seed high32 = fd5cc213 (53987 total equality pairs)
[+] full seed = fd5cc2134155ec1c
[*] solving two fold claws and realizing target accumulator
[+] forged 1024-byte payload
[+] flag: pwnsec{9df232265c0408af}
```

## Flag

```
pwnsec{9df232265c0408af}
```

## Key Takeaways

- A "fault" that flips a source bit before `exec` can expose intermediate SHA state; two well-chosen faults bracket an 8-round bridge whose injected words are then uniquely solvable — no brute force.
- A single padded SHA block (<=55 bytes) means no unknown carried state — pick message lengths accordingly.
- An equality-only oracle is still powerful: balancing a custom hash's `+x` terms turns it into a carry/borrow-class oracle, recoverable 32 bits at a time with a tiny carry automaton instead of `2^32` guesses.
- Invertible finalizers (right-xor-shift + odd multiply mod `2^n`) mean "recover the state" can become "forge a real preimage." Zeroing fold arguments via `k XOR k = 0` splits a 128-bit target into independent 64-bit claw searches.
- Distinguished-point claw search gives birthday-bound (~`2^32`) work for a 64-bit equation without a `2^32`-entry table.
