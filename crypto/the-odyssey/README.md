# The Odyssey

**Category:** Crypto | **Difficulty:** Elite | **Points:** 239 | **Flag:** `pwnsec{a64eb3587e8bea86}`

## Challenge Description

> odysseus needed 20 years to go back home, would you take longer than him to solve this challenge?
>
> **- @ibrahim**
>
> Attachments: `the-odyssey.zip` (archive password: `infected`)

The archive ships `chall.py` and `util.py`. `util.py` implements a byte-sized
Keccak-style sponge; `chall.py` dumps three kinds of leaks and then asks for one
12-byte administrator tag. Send the right tag and the socket prints the flag.

## Initial Analysis

The primitive in `util.py` is a 25-byte (200-bit) Keccak:

- rate 16 bytes, `turn()` = 18 rounds, `edge()` stops 3 rounds early,
  `tail()` applies those last 3 rounds, `peek()` leaks 8 bytes, `tag()` returns 12.
- The secret sponge state is `opened(key, fog) = turn(key + fog)` with a 16-byte
  key and 9-byte fog. We never need `key` or `fog` — recovering the 25-byte
  *opened state* is enough to forge any tag.

For each of two 24-byte guest messages the server computes a pre-tail state
`before`, then flips one secret byte **position** by all 256 values of a secret
permutation `wire`, printing the 8-byte `peek(tail(state))` for each:

```python
state = before[:]
state[position] ^= wire[label]
scan[label] = peek(tail(state))
```

Both `position` and `wire` are hidden, and the scan table is deliberately damaged:
4 entries erased, 2 replaced by unrelated `stray()` outputs, 2 with a single
output bit flipped. The giant `wake` and `scar` lines are the clues that untangle
all of this. There are three leak types:

1. **`wake`** — hidden modular subset sums,
2. **`scar`** — noisy Reed–Muller codewords,
3. **`scan`** — outputs from the last three Keccak rounds.

## The Vulnerability / Core Concept

Everything hinges on the helper `shape()`, which evaluates all low-degree
Boolean monomials at a byte:

```python
small = [x for x in range(256) if x.bit_count() < 4]   # monomials of degree < 4
wide  = [x for x in range(256) if x.bit_count() < 5]    # degree < 5
```

Random XORs of these evaluations are **Reed–Muller codewords** — `small` gives
RM(3, 8), `wide` gives RM(4, 8). A random permutation of the 256 byte-labels
shuffles the evaluation order but *cannot destroy the code*, and RM duality
(`RM(r,8)^⊥ = RM(7−r,8)`) is what lets us recover the hidden byte geometry. The
attack peels the challenge apart in layers:

- **HSSP lattices** turn the `wake` subset sums back into binary codewords;
- **Reed–Muller duality** (Schur-square the codewords up to RM(6,8), take the
  dual RM(1,8)) recovers an affine byte coordinate `y` for every label;
- **Reed–Muller syndromes** from the `scar` planes locate all 8 damaged scans;
- **cube sums** (XOR over affine cubes) linearise the final 3 nonlinear Keccak
  rounds: since `chi` is quadratic, three rounds have degree ≤ 8, so a 7-dim
  cube sum is affine in the 200 state bits.

That turns a supposedly 128-bit-key problem into lattice reduction + GF(2) linear
algebra, ending in a 256-value offset loop and a direct tag forgery.

## Exploitation

Keep the TLS connection open while solving (the instance is fresh per connection):

```bash
ncat --ssl CHALLENGE_HOST 443 | tee instance.txt
```

**1. Recover the Reed–Muller coordinates (`recover_maps.sage`).** Each `wake` is
a hidden subset-sum problem mod `p = 2^512 − 569`: 24 columns are RM(3,8)
codewords, 2 are noise. A two-pass Nguyen–Stern LLL recovers the 26 hidden binary
component vectors per wake; a `2^13 + 2^13` meet-in-the-middle subset-sum table
decodes every value. The three wake groups overlap by exactly 12 genuine
codewords, so pairwise intersection drops the noise and leaves all 36 real
RM(3,8) words. Schur-squaring them spans RM(6,8) (rank 247); its dual is RM(1,8)
(dim 9 = constant + 8 affine coordinates), giving each label a unique byte `y` —
up to an unknown linear map `L` and offset `c`: `wire[label] = L(y) ⊕ c`.

```bash
sage-run recover_maps.sage instance.txt recovered.json
```

**2. Locate the damaged scans (`analyze_options.py`).** Each clean `scar` plane
is an RM(4,8) codeword with zero RM(3,8) syndrome. XORing the parity-check columns
of the received bits cancels all clean contributions; the surviving syndrome span
reveals all 8 bad columns. The 4 erasures (`-`) are obvious; among the other 4,
two are `stray()` outputs and two have a single flipped bit, so there are only
`C(4,2) = 6` gross-error pair guesses to try.

```bash
python3 analyze_options.py recovered.json
```

**3. Break the 3 rounds with cube sums (`prepare_cube.py` + `cube_enum.cpp`).**
For a candidate byte position, `prepare_cube.py` precomputes the full-cube sum
`T`, the 200 one-bit state derivatives `D_k`, and adapted 128-point hyperplane
cube sums that avoid the erasures/gross errors. Because `L` is unknown, a
hyperplane normal is transformed by `L^{-T}`; `cube_enum.cpp` (compiled with
`g++ -O3 -march=native -fopenmp`) enumerates candidate transformed normals for
the chosen forms, solving the first cube equations, carrying the kernel forward,
and allowing exactly the expected 0/1/2 unit-bit corrections. Wrong positions and
pairs almost always have no solution.

```bash
python3 prepare_cube.py recovered.json 6 0 134,190 candidate.txt
OMP_NUM_THREADS=20 ./cube_enum candidate.txt      # -> MATCH 6 e4 79 69 0
```

**4. Recover the full pre-tail state (`recover_state_affine.py` + `finish_state.py`).**
With the position and normals known, `recover_state_affine.py` rebuilds the 200
derivatives, solves the high-dimensional cube equations, and tries all `64^2`
locations for the two flipped output bits (leaving the 200-bit state in a small
affine family). `finish_state.py` adds lower (6-dim) cube sums from pairwise form
intersections to pin the state down to a handful of candidates, evaluates the
clean table `x -> peek(tail(...))` for each, and recovers the linear map `L` from
the clean `(y, x)` pairs — the survivor matches all 248 non-bad labels.

```bash
python3 recover_state_affine.py recovered.json candidate.txt.json 0xe4,0x79,0x69 statecands.json
python3 finish_state.py recovered.json statecands.json finalstate.json
```

**5. Strip the offset and forge the tag (`derive_tag.py`).** The only unknown
left is the byte offset `c`. For each of the 256 choices, `derive_tag.py` removes
it, inverts `edge()` on the known guest message to get a candidate opened state,
derives the *other* guest's edge state from it, and checks against its 248 clean
scans. The correct `c` matches all 248; the permutation inverse is direct (undo
round constant, invert `chi` via a 5-bit table, invert the lane rotation, invert
`theta` by solving its 40-bit column-parity map). From the opened state we rerun
the sponge on `admin = b"AdminSaysWEW" + seed` and read `tag()`.

```bash
python3 derive_tag.py recovered.json finalstate.json
# -> {"answer": "9de06712f80c41840ef7ec36", ...}
```

Submitting the 12-byte tag returned the flag. (Instance-specific labels, states,
normals and tags change every connection, so those literal values can't be reused.)

## Flag

```
pwnsec{a64eb3587e8bea86}
```

## Key Takeaways

- None of the three leaks looks friendly on its own — giant subset sums, noisy
  codewords, nonlinear Keccak output — but each preserves a layer of low-degree
  algebra that can be peeled off in turn.
- Reed–Muller structure survives permutation: Schur products climb the degree,
  and RM duality hands back a clean affine coordinate system even when the byte
  order is shuffled and partially corrupted.
- Cube sums (Boolean derivatives over affine cubes) are the classic way to kill a
  few rounds of a low-degree permutation — here three rounds of quadratic `chi`
  collapse to GF(2) linear algebra over the 200 state bits.
- You rarely need the "real" secret: recovering the 25-byte opened sponge state is
  enough to forge the admin tag, no `key`/`fog` required.
