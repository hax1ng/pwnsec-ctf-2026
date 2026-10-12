# Two Worlds, One Heart

**Category:** Rev | **Difficulty:** Easy | **Points:** 94 | **Flag:** `pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}`

## Challenge Description

> They say love is about speaking the same language.
>
> But what happens when the exact same words mean one thing to him, and something completely different to her?
>
> **- @Nyx**

We're given a password-protected archive `two-worlds--one-heart.zip` (password `infected`) containing a single Windows executable, `portal33.exe` (included here).

## Initial Analysis

The usual first pass tells us a lot:

```text
$ file portal33.exe
portal33.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 8 sections
```

So it's a **32-bit** stripped Windows console app. `strings` gives us the user-facing text but no flag:

```text
=== Two Worlds, One Heart ===
[?] Two hearts, the same words... Why don't they understand each other?
Enter the words that unite both worlds:
[+] Access Granted! Flag verified.
```

The import table has one eyebrow-raiser: `IsWow64Process`. WOW64 is the Windows layer that lets 32-bit programs run on 64-bit Windows — and "two worlds" plus a 32-bit/64-bit split is way too on-the-nose to be a coincidence.

Following cross-references in Binary Ninja from those strings and from `IsWow64Process` lands on the real main routine, which boils down to:

```c
BOOL is_wow64 = 0;
IsWow64Process(GetCurrentProcess(), &is_wow64);
if (!is_wow64) return 1;               // must be running under WOW64

read_input(input);
if (strlen(input) == 0x28 && x86_check(input)) {       // first check (32-bit)
    if (run_same_check_in_64_bit_mode(input))          // second check (64-bit)
        puts("[+] Access Granted! Flag verified.");
}
```

Two facts jump out: the input must be exactly **0x28 = 40 bytes**, and there are *two* checks — one before and one after a CPU-mode switch.

## The Core Concept

The verifier at virtual address `0x401600` starts with these bytes:

```text
31 c0 48 85 c0 74 58
```

Here's the whole trick: **those exact bytes decode to different instructions depending on whether the CPU is in 32-bit or 64-bit mode.**

**32-bit (x86) view:**

```asm
xor eax, eax        ; eax = 0
dec eax             ; byte 0x48 = dec eax  -> eax = 0xffffffff
test eax, eax
jz  0x40165f        ; eax != 0, so NOT taken -> falls into the first-half checker
```

**64-bit (x86-64) view:**

```asm
xor eax, eax        ; rax = 0
test rax, rax       ; byte 0x48 is now a REX.W prefix widening the test to rax
jz  0x40165f        ; rax == 0, so TAKEN -> jumps to the second-half checker
```

That single byte `0x48` is an *instruction* (`dec eax`) in 32-bit mode but a *REX.W prefix* in 64-bit mode. So the same code path validates the **first 20 bytes** of the flag in 32-bit mode and the **last 20 bytes** in 64-bit mode. One byte stream, two meanings — exactly the "same words, two worlds" flavor text.

To actually run 64-bit code from a 32-bit WOW64 process, the binary uses the classic **Heaven's Gate** technique at `0x4016b3`: a far return through code selector `0x33` enters 64-bit long mode, it `call`s the *same* verifier address `0x401600` again (now decoded as x86-64), then a far return through selector `0x23` drops back to 32-bit. That's why `IsWow64Process` gates everything — the trick needs both modes available. The verifier bytes are saved here as `polyglot_401600.bin` if you want to disassemble them both ways (`ndisasm -b32` vs `objdump -m i386:x86-64`).

## Solving It

Both checks are just XOR + fixed-width rotate chains compared against constants, and both operations are trivially reversible (XOR undoes itself; rotate-left undoes with rotate-right). No brute force needed.

**First 20 bytes (32-bit half)** — five little-endian 32-bit words, each XORed with the previous state, rotated left 11, compared to a constant. State starts at `0x1337c0de`:

```python
previous = 0x1337C0DE
answer = bytearray()
for target in [0xCDBD7302, 0x30833D2E, 0xB310EA05, 0xDEF1B433, 0x1C3B640E]:
    word = ror(target, 11, 32) ^ previous   # invert: ror then un-XOR
    answer += struct.pack("<I", word)
    previous = target
```

That recovers `pwnsec{h3_5p34k5_32_`.

**Last 20 bytes (64-bit half)** — two 64-bit words then one 32-bit word, same idea with different rotate amounts:

```python
qword0 = ror(0x87326027C52B7005, 19, 64) ^ 0x5A33C0D313379090
qword1 = ror(0x7E6E88ADD6EBC7E2, 29, 64) ^ 0x87326027C52B7005
dword2 = ror(0x5E929579,         13, 32) ^ (0x7E6E88ADD6EBC7E2 & 0xffffffff)
```

Packed little-endian, that's `5h3_5p34k5_64_l0v3!}`.

The full solver is in [`solve.py`](solve.py). Nicely, it also re-applies all the *original* rotate-left checks as assertions in `verify()`, so it proves the math was inverted correctly before we ever touch the binary:

```text
$ ./solve.py
pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}
```

Feeding that into `portal33.exe` under Wine (which provides a WOW64-style environment) prints `[+] Access Granted! Flag verified.`

## Flag

```text
pwnsec{h3_5p34k5_32_5h3_5p34k5_64_l0v3!}
```

## Key Takeaways

- Challenge flavor text can be *literal*: "same words, two worlds" was describing a 32/64-bit polyglot instruction stream.
- A byte like `0x48` is a full instruction in x86 but a REX prefix in x86-64 — the same bytes genuinely mean different things.
- `IsWow64Process` + far returns through selectors `0x33`/`0x23` is a strong Heaven's Gate fingerprint.
- Don't dismiss "garbage" disassembly — it may be valid code for the other mode. Disassemble suspicious bytes with *both* architectures.
- XOR and fixed-width rotations are reversible, so comparison chains like these solve directly, no brute force.
