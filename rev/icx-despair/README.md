# ICX: Despair

**Category:** Rev | **Difficulty:** Hard | **Points:** 316 | **Flag:** `pwnsec{f8a83c940a6aa78b}`

> Part of the **ICX family** by `@tjrgus`. Where `icx-confusion` was a single bug in a toy
> service, Despair is a full-on signal-processing / coding-theory gauntlet running *inside*
> the custom VM. There's no memory-corruption trick here — it's pure "reverse the pipeline
> and invert it."

## Challenge Description

> In that endless darkness, I fall into despair once again today.
>
> **- @tjrgus**

## Initial Analysis

The attachment looks like a password checker, but `file` and a quick peek reveal a
**stripped, statically-linked Rust PIE of about 261 MiB** — most of which is embedded data,
not x86-64 code. That's the first tell: `icx-emu` is an *emulator* for a made-up 24-bit
machine, and the "password check" happens inside the guest program it boots.

`run.sh` (included) shows how the real flag is handled on the server:

```sh
printf '%s' "$FLAG" > /tmp/.icx-runtime
unset FLAG
exec /bin/busybox nc -ll -p 1337 -e /app/icx-emu
```

Two consequences fall out immediately:

1. A correct key makes the binary read `/tmp/.icx-runtime` and print the flag.
2. The flag isn't in the download, so a local solve recovers the **accepted input**, and the
   real flag still has to come from the live instance.

The service prints a `>` prompt, echoes one line, then grinds for a *long* time — another
sign we're staring at an emulator doing a lot of guest work per attempt.

## The Core Concept

The guest is a 24-bit machine, so a guest instruction is a value like `0x7a8000` rather than
anything x86. Helpfully, the binary carries a plaintext JSON description of the instruction
formats (`isa_schema.json`, included). The opcode numbers are **shuffled at startup** using
SplitMix64 + Fisher-Yates with the seed `0x47c9a16ed3b8250f`; replaying that shuffle yields
the real opcode table (`opcode_map.txt`, and the small `disasm_icx.py` that consumes it).

Guest *memory* adds another layer: each logical 23-bit value is stored with a parity bit and
its three bytes permuted by `(address, phase)`. `decode_memory.py` undoes that encoding back
into ordinary 32-bit integers. One mapping is an easy foot-gun:

```text
guest virtual 0x100000..0x2fffff   ->   physical 0x580000..0x77ffff   (0x200000 words!)
```

Copy too few words and the emulator still runs — it just produces a wrong verifier state and
impossible QAM values. Copying the full two million words fixes it.

Once disassembled, the gate itself is simple to *state*: the key is **exactly 96 characters**
from a 32-symbol Base32-like alphabet (no confusing `I`/`O`/`0`/`1`):

```text
ABCDEFGHJKLMNPQRSTUVWXYZ23456789
```

...and those 96 symbols are pushed through a stack of reversible transforms that reads like a
software-defined-radio textbook:

```text
96 Base32 symbols
  -> FSE encoder            -> 500 witness bits
  -> CRC append             -> 529 bits
  -> LDPC parity append     -> 897 bits
  -> rate matching          -> 1025 bits
  -> interleave -> scramble
  -> 4-bit QAM mapping      -> 257 bytes  -> compare with target
```

The whole thing is really just a tower of shuffles. **Start at the 257 expected output bytes
and undo one shuffle at a time** and you walk all the way back to the FSE witness, and from
there to the key.

## Solving It

**A small emulator instead of the giant one.** The shipped emulator takes minutes per
attempt. `emu_icx.c` (included) is a compact interpreter for just the user-mode guest paths,
so we can restore a state saved right before the final gate and test a candidate in well
under a second. That made instrumenting every stage practical.

**Recover the expected bytes.** The descriptor at `0x0a6500` doesn't store the target
directly — for each position it's `expected[i] = descriptor_target[i] XOR H3(context,"TGT",i)`,
all masked to 23 bits. The hash (addition, multiply, XOR, 23-bit rotate) is reimplemented in
`solve_pipeline.py`.

**Invert the outer pipeline (`solve_pipeline.py`).** By tracing two very different inputs we
confirmed the source mappings, scramble bits and QAM keys depend only on the fixed challenge
state, not on our key. The QAM stage only ever touches four bits, so instead of an algebraic
inverse we just try all 16 nibbles and keep the one that matches:

```python
for i, out in enumerate(outputs):
    candidates = [x for x in range(16)
                  if qam(perm16(qkey[i], 0x51414d, x), qrot[i]) == out]
    assert len(candidates) == 1
    raw_nibble = candidates[0]
```

Scramble, interleave and rate-matching are each a single XOR-and-reindex to undo. CRC and
LDPC are *systematic*, so the first 500 bits of the recovered 897-bit block are exactly the
FSE witness. A self-test (feeding an all-`A` input through the inverse) reproduced the guest's
internal buffer with **zero** mismatches before we trusted it on the secret target. The
recovered witness is saved as `witness_bits.txt`.

**Undo the FSE layer (`solve_fse.py`).** FSE is a 128-state board game: a symbol picks a move,
the move emits 0–7 bits and lands on a new state. Rather than rebuild the table generator, we
dumped all `128 * 32 = 4096` transitions from the working guest helper at `0x0a3810`
(`fse_table.txt`), indexed them by *destination* state, and ran a small backwards
dynamic-programming search — keeping only paths whose emitted bits match the witness:

```python
states = {(final_state, 7): ""}
for char_index in range(96):
    next_states = {}
    for (new_state, bit_pos), prefix in states.items():
        for old_state, symbol, payload, nbits in inverse[new_state]:
            if payload_at(bit_pos, nbits) == payload & ((1 << nbits) - 1):
                next_states.setdefault((old_state, bit_pos + nbits),
                                        prefix + ALPHABET[symbol])
    states = next_states
```

It converges to exactly one candidate (initial state 70, final state 56):

```text
V6EAW6STMR7LJ7LAXKAV6SSHYK79SHDYS7QU6SYURV47UPBKBPSGXVST32DLHT6APSAMJPV8G3ZHT5SESS32Y5R6VSYGUG2W
```

**Validate.** Against the restored pre-gate state the compact emulator reports `gatecheck=000001`
(success) in ~0.6s. Sending the key to the live instance — which needs several minutes to
finish — returns the real flag:

```sh
printf '%s\n' "$KEY" |
    timeout 900 openssl s_client -quiet -connect "$HOST:443" -servername "$HOST"
```

## Flag

```text
pwnsec{f8a83c940a6aa78b}
```

## Key Takeaways

- A giant Rust binary that's mostly embedded data is almost always an **emulator**. Find the
  ISA description (here it was plaintext JSON) before trying to read it as x86.
- "Scary" DSP/coding-theory names (FSE, LDPC, CRC, rate matching, QAM) are usually just
  **reversible shuffles**. Undo them one layer at a time from the known output.
- When a layer is tiny (4-bit QAM, 128-state FSE), **brute the small space** instead of
  deriving a clever inverse. 16 nibbles and a 4096-row table are nothing.
- Reuse the target's own code as an oracle (the `0x0a3810` FSE helper) instead of
  reimplementing fiddly table builders — a recurring, high-leverage ICX trick.
- Watch the word-size / mapping-size details. `0x200000` vs `0x10000` words still "ran" but
  silently poisoned the result.
