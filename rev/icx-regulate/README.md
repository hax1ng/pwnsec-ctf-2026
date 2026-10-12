# ICX: Regulate

**Category:** Rev | **Difficulty:** Hard | **Points:** 435 | **Flag:** `pwnsec{10f7636384e74c19}`

> Part of the **ICX family** by `@tjrgus`. Regulate shares its 23-bit word format and
> shuffled ISA with `icx-confusion`, but now there's a whole guest OS, a capability system,
> a portal/IPC layer, and an image validator to get past. If you've read the `icxx` writeup,
> the "borrow a kernel mark and launder it" idea here is the same spirit, one notch simpler.

## Challenge Description

> You are free to choose your own path, if freedom is truly yours.
>
> - This challenge may require some pwn skills.
>
> **- @tjrgus**

## Initial Analysis

The public bundle is tiny: `Dockerfile`, `docker-compose.yml`, `run.sh`, and `icx-emu` — a
stripped static x86-64 Rust PIE. It is not a normal program; it's an **emulator** bundling a
custom 23-bit CPU, a custom word/executable format (GMI), an embedded guest OS, a sandbox +
capability system, and virtual devices (terminal, filesystem).

`run.sh` writes the real flag into `/tmp/.icx-runtime`, which the guest sees as `/flag`, and
`docker-compose.yml` uses a fake local flag (`pwnsec{this_is_fake_flag}`) so you can exercise
the real read path locally without confusing a fake flag for the answer.

ICX uses **23-bit words**, stored in a GMI file as three little-endian bytes with the top bit
unused. The opcode map is deliberately shuffled (SplitMix64 / Fisher-Yates, seed
`0x8e7105c1e7704d3e`); recovering it gave enough to write a small assembler. The included
tooling captures exactly this:

- `opcodes.json` — the recovered opcode → name table.
- `icxasm.py` — a minimal assembler built on that table.
- `gdis.py` — a matching disassembler (operates on a decoded guest-word map).
- `gmi_tool.py` — build / checksum / guest-validation model for GMI images (shared with the
  `icxx` challenge).

## The Core Concept

Guest programs can't touch files or the console directly; they send requests to the kernel
through a **portal** — basically a row of mailboxes plus a producer counter and a doorbell.
Our uploaded process is unprivileged, so a straight `/flag` read is denied.

The weak point is that an ICX memory word carries more than a number: it can also carry a
hidden **mark** meaning "this word came from the kernel." When the portal consumer handles a
request, a `CACHEOP 9` path looks at the mark on **request word 0** — a marked word makes the
request trusted and the `/flag` capability rejection is bypassed. So the target isn't a secret
key or a return address; it's literally:

> Put a legitimate kernel mark on word 0 of an otherwise-valid read request.

The catch: the one instruction that can move a byte *and* propagate its mark, `OCTPACK`
(opcode `0x52`), is forbidden by the image validator. The trick that the "choose your own
path" flavour text hints at: hide `OCTPACK` as the immediate operand of an `LDI` (the
validator treats that word as data), then exploit a boundary hole in the control-flow checker
to **branch into that operand and execute it anyway**. The checker skips targets whose low
byte is `0xff` (and `0x00`), so we pad with NOPs until the hidden word lands on an address
ending in `ff`:

```python
def octpack_smuggled(self, src, base, offset):
    while ((0x120000 + len(self.w) + 2) & 0xff) != 0xff:
        self.emit(0x080000)                 # NOP
    self.br(0x49, "trigger")
    self.emit((0x24 << 16) | (14 << 12))    # LDI R14, <next word>
    self.label("hidden")
    self.rrr(0x52, src, base, offset)       # static view: just an immediate
    self.br(0x49, "after")
    self.label("trigger")
    self.br(0x49, "hidden")                 # runtime view: lands here -> OCTPACK runs
    self.label("after")
```

## Solving It

The full builder is `solve.py`; `run_remote.py` drives the finished image over TLS. The
exploit reuses the **stock userspace runtime** routines (registration `0x101194`, read
producer `0x101335`, response wait `0x10149f`, terminal write `0x10162c`, token lookup
`0x101061`) so every request it builds is genuinely well-formed. The steps:

1. **Get a kernel-marked zero.** Register a portal context, issue a denied `/flag` read, then
   a *successful* `S1\n` terminal write. The success status is a numerically boring zero — but
   it was produced by the kernel, so it carries the mark. Ring indices aren't reset per
   process, so the just-consumed response slot is computed at runtime from `metadata[5]`:
   `slot = (metadata[5]-1) mod 23`, address `0x6ffc05 + slot*8`.

2. **Prepare a genuine request without publishing it.** Fill the read wrapper's five-word
   marshal area (`/flag`, len 5, `FLAGBUF`, max `0xa0`, 0), copy the real context + metadata
   into *shadow* structures, and call only the producer (`0x101335`) against shadow metadata.
   It writes a real ring slot and valid authenticator, but bumps only our shadow producer
   index — so the kernel doesn't see it yet. Request word 0's physical address is
   `0x6ffb00 + (producer % 23) * 10`.

3. **Transplant the mark.** `POP` the marked zero (POP preserves marks where ordinary copies
   don't), then the smuggled `OCTPACK` writes that marked zero into byte 1 of request word 0.
   Word 0 holds the argument count `5`, whose second byte is already zero — so the number is
   unchanged, but its provenance is now "kernel." Classic tag laundering.

4. **Publish and ring the doorbell.** Copy shadow metadata back to the real metadata, fence,
   then hit the doorbell with the *exact* register ABI the producer expects:

   ```python
   A.ldi(1, CTX);  A.load(1, 1, 6)   # R1 = doorbell address
   A.ldi(0, SHMETA); A.load(0, 0, 0) # R0 = new producer index (used as consume bound!)
   A.store(0, 1, 0)                  # STORE R0, [R1]
   A.emit(0x080000)                  # NOP — safe speculative opcode after the async IRQ
   ```

   The interrupt handler reuses saved `R0` as the ring upper bound, so swapping the registers
   makes it reject the ring as corrupt. The trailing NOP matters too: the doorbell raises an
   async interrupt *after* the next opcode is fetched, and an `LDI` there would save its
   immediate as the resume PC and trip the same branch-into-continuation guard.

5. **Receive and print.** Wait for the trusted response (`0x10149f`) and dump `FLAGBUF` via
   the terminal wrapper (`0x10162c`).

Build and run:

```bash
python3 solve.py                        # writes exploit.gmi (8192 words / 24576 bytes)
./run_remote.py CHALLENGE_HOST --timeout 600
```

> **Note:** `solve.py` splices in a slice of the decoded stock runtime from
> `/tmp/sandbox_text.u32` so the helper calls exist at their original guest addresses. The
> finished, locally-verified image is included here as `exploit.gmi`
> (sha256 `ef2a4bcfcc3e36ff86286fd7217fa22f41c6bcc46cfe719ee90238f11607fe5e`), which
> `run_remote.py` sends as-is.

Local testing against the fake flag confirmed we were genuinely reading guest `/flag` and not
scraping a string from the binary:

```text
S1
pwnsec{this_is_fake_flag}
```

## Flag

```text
pwnsec{10f7636384e74c19}
```

## Key Takeaways

- When everything is custom — word size, ISA, executable format, OS, IPC, capabilities —
  don't try to "reverse the whole OS." Ask small questions: how is a normal request built,
  what property makes the kernel trust one, where can that property be obtained legitimately,
  and which instruction can transfer it?
- **Call the target's own code.** Reusing the stock producer to mint a genuine, authenticated
  request is far easier than hand-forging slots and MACs.
- A forbidden opcode can still run if the static validator and the runtime decoder disagree
  about what's code and what's data. `LDI` immediates + a `0xff` boundary hole = arbitrary
  instruction execution.
- Provenance tags (marks) are a security boundary only if attacker code can't move them.
  `POP` + `OCTPACK` turned the mark into just another thing to copy.
