# ICX: Confusion

**Category:** Rev | **Difficulty:** Medium | **Points:** 316 | **Flag:** `pwnsec{bd50223d7bac573d}`

> This is the entry point into the **ICX family** of challenges by `@tjrgus`. All of them
> (`icx-confusion`, `icx-despair`, `icx-regulate`, `icxx`) ship a Rust emulator for a
> made-up CPU whose words are *not* a normal byte width. Confusion is the gentlest of the
> bunch — a single type-confusion bug in a toy "archive" service — and it's a great warm-up
> for the 23-bit arithmetic and capability ideas that the harder siblings lean on heavily.

## Challenge Description

> The peaceful era is over. Survive the confusion that now remains.
>
> - This challenge may require some pwn skills.
>
> **- @tjrgus**

## Initial Analysis

The attachment is a custom virtual machine running a small "archive" service. After a
(deliberately slow) boot you get a tiny command prompt. The interesting commands are:

```text
new HEX       Create a Note containing the supplied bytes
view SLOT     Create a View of an existing object
edit V I X    Write value X at index I through a View
peek V        Display eight values through a View
pack A B      Turn Note A into a Job and attach Note B
run SLOT      Execute a Job
```

There are 16 object slots, and every object lives at a predictable VM address:

```text
object_address  = 0x110400 + slot * 0x20
payload_address = object_address + 1
```

The single most important architectural quirk — and the thing that trips people up on
*every* ICX challenge — is that ICX values are **23 bits wide**, not 24. The six-hex-digit
display is tempting bait. Every bit of arithmetic has to be reduced with:

```python
MASK = (1 << 23) - 1
```

Get this wrong and the Job authentication maths comes out *almost* right, which is far more
annoying to debug than being completely wrong. (`disasm_icx.py` and `isa.json`, included
here, are the small guest disassembler + instruction table used to reverse the service and
recover the two capability tokens below.)

## The Core Concept

This is a textbook **stale-reference / type-confusion** bug.

Think of a Note as a cardboard box, and a View as a sticky label that says "the contents of
this box are over here." The `pack` command empties the box and drops in a *completely
different* structure — a privileged **Job** — but it never peels off the old label. The View
still points into the same box, so writes that were meant to edit harmless Note bytes now
edit security-sensitive Job fields.

So we set up two Views before packing:

```text
new 41          # slot 1: carrier Note  -> becomes the Job
new 42          # slot 2: request Note
new 2f666c6167  # slot 3: the string "/flag"
new 00          # slot 4: destination buffer
view 1          # slot 5: View that will point into the future Job
view 2          # slot 6: View into the request Note
pack 1 2        # slot 1 is now a Job, but View 5 is still live
```

View 5 now edits the **Job header**; View 6 edits the attached Note that `run` turns into an
IPC request descriptor.

A Job's first eight words (leaked with `peek 5`) break down like this:

| Word | Purpose |
|---|---|
| `d[0]` | Encoded capability token |
| `d[2]` | Job generation |
| `d[3]` | Manifest: `version | (count << 5)` |
| `d[4]`, `d[5]` | Values used when sealing the token |
| `d[6]`, `d[7]` | Integrity / authentication state |

The capability isn't stored directly; it's XORed with a *seal* derived from the slot,
generation, and two of the leaked words. And `d[6]`/`d[7]` are an integrity check over the
header, so the moment we change the token or the manifest we have to recompute them — the
challenge gives us an integrity check, but it's an algorithm we can reverse, not a real
security boundary. The full 23-bit auth routine lives in `solve.py` as `job_auth()`.

Two capability tokens recovered while reversing the guest are all we need:

```text
0x7cebed   privileged flag-read gate
0x033e63   console / write gate
```

## Solving It

The manifest field controls which request words `run` copies into its IPC descriptor:
with `version=1`, our fields come from `request[1..]`, every one of which we can set through
View 6. The forge helper rewrites the token, manifest and both auth words, then pushes them
in through the stale View:

```python
def forge(token, version, count):
    d[0] = token ^ seal
    d[3] = version | (count << 5)
    d[6], d[7] = job_auth(job_slot, generation, d)
    for i in (0, 3, 6, 7):
        edit(5, i, d[i])
```

**Stage 1 — read `/flag` into VM memory.** Slot 3 holds `/flag` (payload at `0x110461`),
slot 4 is our scratch buffer (`0x110481`). We fill a five-field read descriptor, forge the
Job with the flag-read capability, and run it:

```python
for i, v in enumerate((0x110461, 5, 0x110481, 160, 0), 1):
    edit(6, i, v)
forge(0x7CEBED, version=1, count=5)
cmd('run 1')          # privileged service copies /flag to 0x110481
```

**Stage 2 — print it.** Reading the flag into memory isn't visible yet, so we reuse the
*same* Job with the console-write capability and a two-field descriptor pointing at the
buffer:

```python
edit(6, 1, 0x110481)
edit(6, 2, 160)
forge(0x033E63, version=1, count=2)
cmd('run 1')          # dumps 160 bytes — flag included
```

The console service may complain that the request "failed" afterwards, but that's too
late — the bytes are already on screen.

`solve.py` runs locally against an extracted `icx-emu`, or against the live TLS service:

```bash
python3 solve.py                      # local
python3 solve.py remote CHALLENGE_HOST  # remote (TLS on :443)
```

## Flag

```text
pwnsec{bd50223d7bac573d}
```

## Key Takeaways

- A reference **must** be invalidated when the type or lifetime of its target changes.
  `pack` forgot to, and that one omission is the whole challenge.
- Custom VMs love weird word sizes. ICX is 23 bits — mask everything, and remember this for
  the harder siblings.
- An integrity check you can *recompute* is not a security boundary. Capability tokens are
  worthless if the capability-bearing struct sits in attacker-writable memory.
- The pwn part here is literally four overwritten words. The hard part was reversing what
  those words mean — which is the recurring theme across the entire ICX series.
