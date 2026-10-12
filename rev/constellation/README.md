# Constellation

**Category:** Rev | **Difficulty:** Hard | **Points:** 194 | **Flag:** `pwnsec{c0d3ebc92d57e1db301dbf8a6a9595b3e003078fc977c204ab6ff6372353a6da60a423b3d9b57fd1c7618b976df1500f2d3b137d9b5e57e92909a140ae6ee99f}`

## Challenge Description

> The sky had forgotten some of its stars, but not the shape they once made.
>
> **- @tjrgus**

We get a password-protected `constellation.zip` (password `infected`) containing a Windows executable (`main.exe`) and a data file, `flag.flag`. The executable is roughly half a *gigabyte*, but its real PE sections are only about half a megabyte — the rest is deliberately awkward packed data. `flag.flag` (included here, 196,776 bytes) is the input the real puzzle operates on.

## Initial Analysis

The description is an unusually literal hint: some "stars" are missing, but the shape — the parity equations — still pins down where they were. That's a description of an **erasure code**.

The size mismatch is the first tell. `file` says PE32+ x86-64, but almost all 475 MB is packed blobs. Naive attempts (`strings`, `7z l`, `unzip -l`) find `PK` ZIP-looking signatures scattered through the file, but the whole thing is not a valid archive, and treating every `PK` as a real archive header is a trap — random packed bytes contain that sequence too.

The big lesson up front: **do not try to statically reverse 475 MB.** Let the native loader unpack its own data under Wine + GDB, break after each decoded layer exists in memory, patch the deliberately slow VM dispatch path, and dump the decoded objects. Then re-implement only the small useful parts in Python.

## The Core Concept

Peeled apart, the challenge is two halves glued together:

```text
main.exe
  -> trailer-verified keystream decrypt (outer host archive)
  -> three nested ZIP/graph layers
  -> a graph-based virtual machine
  -> which generates a coding model: GF(256) table, 32x224 parity matrix, shard permutations

flag.flag + that model
  -> un-shuffle shards, reconstruct the 32 erased shards per batch  (Reed-Solomon over GF(256))
  -> 471 serialized records
  -> decrypt records (home-made 32-bit XOR stream)
  -> a tiny custom filesystem archive
  -> extract the tree, run flag.py  ->  flag
```

The centerpiece is the erasure code. Think of 224 boxes of data plus 32 extra "parity" boxes, each a different weighted (GF(256)) combination of the data. Lose some boxes and the parity equations give you enough to solve for the missing ones. Every batch deliberately drops exactly 32 shards — exactly enough to still be solvable.

## Solving It

**Stage 1 — unpack the binary (included tools).** The outer host archive is appended to `main.exe` behind a 40-byte trailer with FNV-1a + an "avalanche" hash check, then XOR-keystream encrypted. [`decrypt_host.c`](decrypt_host.c) verifies that trailer and decrypts the outer host:

```bash
./decrypt_host main.exe decrypted_host.bin
```

That outer host is the first of several nested ZIP/graph layers. [`unwrap_host.py`](unwrap_host.py) peels them: each layer carries a tiny obfuscated `JKM1` "dependency ticket" that names a `JSC2` descriptor, which lists the data chunks, their sizes, and FNV checks needed to reassemble and XOR-decrypt the next ZIP. Because the chunk blobs are hundreds of MB, the heavy FNV/XOR work is delegated to [`blobtool.c`](blobtool.c):

```bash
cc -O2 -o /tmp/blobtool blobtool.c
python3 unwrap_host.py decrypted_host.bin out/ --blobtool /tmp/blobtool --check-chunks
```

**Stage 2 — the graph VM.** Inside the final layer are ~28,123 graph nodes; dumping one JSON object per node makes them tractable. The clever bit: the control-flow graph *is* the bytecode. Each node's `vals` holds `[opcode, operandA, operandB, _, node_id, next_id, branch_id]` — instructions aren't stored consecutively, they're "stars" linked by IDs. A ~4,096-register emulator starting at PC `0xebad4dea` runs it; it doesn't check or print a flag, it just *generates a coding model*:

```text
magic 63 8d a6 f1 | shard width 192 | data shards 224 | parity shards 32
GF(256) exponent table | 32x224 parity matrix | per-batch shard permutations
```

**Stage 3 — reconstruct the erased stars.** Parse `flag.flag`'s header (4 batches, 256 shards/batch, 192 bytes each, 32 erased per batch). Crucial gotcha: the physical shards are **shuffled**, and the erasure indexes refer to *post-shuffle* positions while the parity matrix refers to *logical* shard indexes. Sort each batch by its permutation value before placing shards:

```python
order = sorted(range(256), key=lambda i: (perm[batch*256 + i], i))
for output_position, logical_index in enumerate(order):
    chunk = read_192_bytes()
    if output_position not in erased_positions:
        shards[logical_index] = chunk
```

Then it's Gaussian elimination in GF(256) (addition = XOR, multiplication via the exp/log tables). Known data terms get XORed out, leaving a small system in the missing shards:

```python
def gf_mul(a, b):
    if a == 0 or b == 0: return 0
    return exp[(log[a] + log[b]) % 255]
```

Regenerating every still-present parity shard afterward and checking it matches is a far stronger correctness test than "does the output look plausible." Joining 224 data shards/batch and trimming to the header length gives an 83,371-byte stream.

**Stage 4 — records → filesystem → flag.** The stream is 471 records; each value is a 128-byte ciphertext with a chunk index encoded as `(enc_index & 0xffff) ^ 0x6d0`. Decryption is a home-made XOR stream, 4 bytes at a time, state `0x6db5271f`, **continuous across record boundaries** (reset it per-record and only the first record decrypts — a nice trap):

```python
def mix32(x):
    x = ((x ^ (x >> 16)) * 0x7feb352d) & 0xffffffff
    x = ((x ^ (x >> 15)) * 0x846ca68b) & 0xffffffff
    return (x ^ (x >> 16)) & 0xffffffff
```

The resulting 60,288 bytes are a dead-simple custom archive (`u32 magic1, magic2, entry_count`, then per entry a type byte, path, and for files a `u64` length + bytes). It unpacks to 42 directories and 97 files — and `flag.py` at the root. That script walks the extracted tree in sorted order, excludes itself, serializes each name/size/content, hashes it all with SHA3-512, and prints `pwnsec{<digest>}`:

```text
$ cd recovered_fs && python3 flag.py
pwnsec{c0d3ebc92d57e1db301dbf8a6a9595b3e003078fc977c204ab6ff6372353a6da60a423b3d9b57fd1c7618b976df1500f2d3b137d9b5e57e92909a140ae6ee99f}
```

## Flag

```text
pwnsec{c0d3ebc92d57e1db301dbf8a6a9595b3e003078fc977c204ab6ff6372353a6da60a423b3d9b57fd1c7618b976df1500f2d3b137d9b5e57e92909a140ae6ee99f}
```

## Key Takeaways

- A huge binary doesn't mean every byte needs manual reversing — let the loader unpack itself and dump the decoded objects.
- A graph-based VM becomes much clearer once you turn it into a small Python emulator.
- Erasure/Reed-Solomon recovery over GF(256) is friendlier than it sounds: XOR for addition, exp/log tables for multiply, Gaussian elimination for the unknowns.
- Watch for mismatched coordinate systems — the erased-position indexes and logical shard indexes lived in different spaces (pre- vs post-shuffle).
- Re-deriving known parity/records as a checksum catches mistakes before they cascade into later layers.
- The flavor text was accurate: enough of the constellation survived to reconstruct every missing star.
