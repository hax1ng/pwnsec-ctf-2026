# ICXX

**Category:** Rev | **Difficulty:** Hard | **Points:** 500 | **Flag:** `pwnsec{ca77aefd5478d51f}`

> The boss of the **ICX family** by `@tjrgus`. It reuses the family's 23-bit CPU, shuffled
> ISA, and GMI executable format (see `icx-confusion` / `icx-regulate`), then stacks a
> microkernel, an HTTP server, request smuggling, BLS12-381 aggregate signatures, a
> GF(2^23) erasure code, and a leaked-bearer-token guest exploit on top. It genuinely wants
> pwn **and** web **and** crypto skills, all layered on a deliberately-broken binary.

## Challenge Description

> Allow me to introduce you all to the brand-new ICXX.
>
> - This challenge may require some pwn, web, and crypto skills.
>
> **- @tjrgus**

## Initial Analysis

The attachment is a single file, `icx-emu` — a stripped static x86-64 Rust PIE that `wc -c`
reports as **~1.27 GB**. That's the first red flag: the bulk is `.rodata` padding, and the
real `.text` is only ~1.16 MB. (The original solve used a `trim_elf.py` to produce a 33 MB
version Binary Ninja could actually open; not reproduced here.) Inside the binary is a whole
fictional platform: a 23-bit CPU, virtual memory, MMIO devices, an ICX/INI resource
filesystem, GMI executables, a capability-based guest OS, and a web server that accepts
**cryptographically authenticated updates**. It's a computer inside a computer.

The remote serves HTTP with three endpoints that matter:

- `GET /health` → `ready`
- `GET /9f3c7a12` → live session state (nonce, epoch, boot word, root commitment)
- `POST /submit` → arbitrary `application/octet-stream`; our goal is to make its JSON
  `output` field contain the flag.

Two nasty anti-analysis features show up early:

- **The binary is deliberately broken.** `e_entry == 0`, the startup arrays and the code at
  `0x145c0` are zeroed. It can't run as shipped — intentional sabotage to push you toward
  static analysis and remote exploitation.
- **It kills itself under analysis.** After repair it exits `144` (`128 + 16` = SIGSTKFLT)
  almost instantly — a `/proc` scan for debuggers/siblings fires on a busy host. The fix is
  elegant: **run it in Docker**. A fresh container has a pristine PID namespace, so the scan
  finds nothing and the server stays quiet.

ICX physical words are 24-bit encoded (parity + an `(address, phase)` permutation);
`icx_word.py` is that codec. `gmi.py` + `icx_isa.py` + `isa.json` are the GMI
parser/disassembler and the recovered (SplitMix64-shuffled) opcode table used to read guest
code.

## The Core Concept

There is no single bug — it's a seven-link chain, each link a different discipline:

1. **Repair the host ELF** enough to run it (reconstruct the entry/startup region).
2. **Cathedral erasure recovery** (`repair_cathedral.py`). A self-integrity routine
   (`0x8db30`) runs a GF(2^23) Reed-Solomon-style erasure code: 512 data symbols at file
   offset `0x289158`, 64 Cauchy parity checks, 32 **erased** (zeroed) symbols. Solving the
   Cauchy system over GF(2^23) with reduction polynomial `0x800021` restores them and yields
   the Cathedral digest `0xf192a63fd3365f3d`, which *feeds downstream computations*. Bypassing
   the check locally works but silently poisons the proof material → remote `E42`.
3. **HTTP request smuggling.** `POST /submit` scans the body for a nested `PUT /r/6d91 I/1`.
   A wrapped `0x800000`-byte content span makes the two parsers disagree about where the body
   ends: the GMI prefix becomes the guest `/submit` program, while the inner `PUT`
   authenticates the signed update.
4. **Aggregate BLS12-381 forgery.** The capsule carries two BLS12-381 G1 signatures. A 46-bit
   metadata field is pushed through `fmeta()` — a chain of CNOT gates, i.e. an **affine**
   (GF(2)-linear) map — and the admin batch coefficient is a linear function of it. Solving
   for the metadata that makes that coefficient **zero** removes the admin key; the remaining
   key is the generator (secret key 1), so `sig = H(message)` is trivially forgeable. The
   math is `solve_zero_meta()` in `forge_hash.py` (Gaussian elimination over GF(2)).
5. **Session-bound inner verifier.** A second gauntlet (`0x4909c0`) checks fields
   (`f0`, `f2`, `f3`, `rootcommit`, `field2e`, plus 256-word proof vectors) derived from the
   *live* per-boot state via SplitMix64 hash chains with domain tags `BACKING` / `GENERAT` /
   `TRACEPC` / `LEGACYSH`.
6. **Leaked Gate bearer token.** `/seed` loads first and consumes the only Gate read grant;
   `/submit` loads with capability mask 0, so a normal `bearer=0` read fails. But a **nonzero**
   bearer in IPC word 0 skips capability consumption and goes through the bearer validator —
   and the expected per-boot bearer is *leaked* into user-readable reply-ring metadata at
   guest VA `0x6ffc90`.
7. **Read `/flag` and exfiltrate** via the console-write system method `0x145a9c`, whose
   output the HTTP layer returns as the JSON `output` field.

## Solving It

The included scripts are the final working chain:

| Script | Role |
|---|---|
| `repair_cathedral.py` | Restore the 32 GF(2^23) erasures (needed for remote). |
| `forge_hash.py` | SplitMix64 `mix`/`imix`, the `fmeta` affine map, `solve_zero_meta`, and the BLS message hash `core`. |
| `make_token_exploit.py` | Build the guest `/submit` GMI (bearer-token reuse + console-write wrapper). |
| `make_forged_smuggle.py` | Assemble the smuggled body (BLS sigs + all verifier fields). |
| `solve.py` | Orchestrator: build both pieces, POST, print the flag. |
| `gmi_tool.py`, `gmi.py`, `icx_isa.py`, `isa.json`, `icx_word.py` | GMI build/validate, disassembler, ISA table, and the 23-bit word codec. |

**The oracle-read trick (the big time-saver).** Rather than reconstruct the entire SplitMix64
hash chain from decompiled code, set a hardware breakpoint at each `cmp` in a *fixed running*
oracle, read the expected value straight out of the register, and plug it into the payload.
Sequential field dependencies mean the first value unlocks the next check where the rest are
already in registers. `oracle_values.json` holds one such captured set (and
`make_forged_smuggle.py` falls back to baked defaults if it's absent). For the proof vectors,
`proof_A` passes through an identity map to the comparison buffer, so you just read the
expected 256-word buffer from the oracle and set `proof_A`/`proof_B` to it.

> Hardware breakpoints (`hbreak`) are mandatory here: `icx-emu` is multithreaded, and a
> software `int3` can be read by another thread and SIGSEGV the server. You only get 4.

**The BLS forgery** (`forge_hash.py` / `make_forged_smuggle.py`):

```python
meta = solve_zero_meta(nonce, epoch)   # null out the admin batch coefficient
# the surviving key is the generator (sk=1), so the signature is just the hash point:
raw2 = core(0x44454c4547415445, DELEGATE_DOMAIN + struct.pack('<QII', nonce, epoch, len(payload)) + payload)
h2   = int.from_bytes(raw2, 'little') % FR or 1
sig2 = compress_G1(multiply(G1, h2))
```

**The smuggle body** is the GMI prefix, then the nested request, then the signed capsule
padded so the whole thing spans exactly `0x800000` bytes:

```text
[GMI prefix: the guest /submit program]
PUT /r/6d91 I/1\r\nContent-Length: N\r\nX-6d91: EPOCH\r\n\r\n
[signed capsule + zero padding to exactly N bytes]
```

**The guest GMI** (`make_token_exploit.py`) patches the transport instruction so that, *only*
for a FILEREAD (request shape 5), IPC word 0 is loaded from the leaked bearer at `0x6ffc90`;
every other request keeps word 0 as zero (finalization and console methods reject the bearer
form). After the read fills the flag buffer, it emits the bytes with console-write `0x145a9c`
and calls the original `0xd1506` finalizer so the HTTP worker returns cleanly.

**Run it** (local Docker oracle first, then real remote state):

```bash
python3 solve.py http://127.0.0.1:1337      # local end-to-end against a Docker oracle
python3 solve.py https://CHALLENGE_HOST       # remote (fresh nonce each boot)
```

`solve.py` chains `make_token_exploit.py` → `make_forged_smuggle.py` → `POST /submit`:

```text
{"state":"halted","output":"pwnsec{ca77aefd5478d51f}\n"}
```

> The remote binary is the intact original, so its Cathedral check passes natively (the
> erasures were never zeroed there) — `repair_cathedral.py` only matters for a locally-run
> binary. The guest `/submit` GMI and the proof/seed blobs are challenge-extracted binary
> artifacts and are intentionally **not** bundled here; the scripts document how each is
> produced.

## Flag

```text
pwnsec{ca77aefd5478d51f}
```

## Key Takeaways

- **Dirty `/proc` kills binary-level anti-analysis.** A binary that self-destructs instantly
  (watch for `killpg` / signal delivery) usually just needs a clean Docker PID namespace.
  30 seconds of setup saves hours of patching.
- **Corrupted challenge binaries are a real genre.** Zeroed `_start`, zeroed startup, and a
  self-integrity check that detects repairs push you to static analysis. But if that check's
  output feeds later computation (as the Cathedral digest does), you must *fix* it, not
  bypass it, or remote silently rejects you.
- **The oracle-read trick.** Don't reverse a per-session hash chain — hardware-breakpoint the
  `cmp` sites and read the expected values from registers. Sequential fields fall like
  dominoes.
- **Recognize the crypto.** The limbs `0x73eda753299d7d48...00000001` are the BLS12-381 scalar
  field; `0xBF58476D1CE4E5B9` / `0x94D049BB133111EB` are SplitMix64. A verifier that uses the
  generator as the public key (sk=1) is a built-in backdoor: `sig = H(message)`.
- **Affine means invertible.** Any "scrambler" that is only XOR + bit moves is linear over
  GF(2); choosing an output (e.g. zero) is just Gaussian elimination.
