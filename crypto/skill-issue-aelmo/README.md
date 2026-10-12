# skill issue '@'aelmo

**Category:** Crypto | **Difficulty:** Hard | **Points:** 185 | **Flag:** `pwnsec{a91f7010a581800b}`

## Challenge Description

> Ok mr aelmo we need to talk...
>
> **- @ibrahim**
>
> Attachments: `skill-issue----aelmo.zip` (archive password: `infected`)

The archive contains a single SageMath generator, `chall.py`. No network
interaction is required beyond grabbing one static output blob.

## Initial Analysis

`chall.py` builds a secret the hard way. It picks a random 2048-bit prime `p`
(never printed), derives three random 16x16 byte matrices `m0, m1, m2`, and
"mixes" each one entry-by-entry with public, seed-derived factors:

```python
def mix(m, d):
    return matrix(ZZ, n, n, [(1 + d[i] - d[j]) * ZZ(m[i, j]) for i in range(n) for j in range(n)])
```

The mixing diagonals `d0, d1, d2` come from the printed `seed` via SHAKE-256, so
we can recompute every factor `1 + d[i] - d[j]`. The three mixed blocks are then
stacked into a 48x48 **upper block-Toeplitz** matrix:

```text
X = [ x0 x1 x2 ]
    [  0 x0 x1 ]
    [  0  0 x0 ]
```

The server prints the seed, the flag length, and

```text
C = f(X) mod p,     f(t) = t^4097 + 3*t^257 + 11*t^17 + 42*t + 99
```

as a flat list of 2304 integers — but it never prints `p`. The flag is XOR-masked
with SHA-512 keyed on the *exact* prime:

```python
sealed = xor(flag, mask(p, len(flag)))
```

So an approximate `p` is worthless. We need the exact 2048-bit modulus, and the
sealed bytes live somewhere inside `m2`. Parsing the 2304 integers confirms the
block structure (three identical `c0` blocks on the diagonal, two identical `c1`
superdiagonal blocks, `c2` in the corner, zeros below).

## The Vulnerability / Core Concept

The design leaks far more than intended through two pieces of linear algebra:

1. **A tiny secret hiding in a public modular span.** Let `A = x0` and
   `C0 = f(A) mod p`. Because `A` commutes with any polynomial in itself,
   `A` commutes with `C0`. For a generic (cyclic) `C0`, *every* matrix that
   commutes with it over `GF(p)` is a polynomial in it, so

   ```text
   A ∈ span(I, C0, C0^2, ..., C0^15)  mod p.
   ```

   `A` is therefore a short integer vector living inside a public modular span.
   A two-stage **orthogonal lattice** attack (Nguyen–Stern flavour) pulls it out
   up to a scalar-identity ambiguity `A + tI`.

2. **The hidden modulus falls out of an integer commutator.** Scalar matrices
   vanish from a commutator, so `[C0, A + tI] = [C0, A] = 0 mod p`. Computing
   those commutator entries *over the integers* (not mod p) gives exact multiples
   of `p`. A GCD of a few of them recovers `p` exactly.

Once `p` and `x0` are known, a slick trick recovers `x1, x2`: since `X` carries
three copies of `A` on its block diagonal, `m(X)^3 = 0` where `m = charpoly(A)`.
Inverting the scalar polynomial `f` in the quotient ring `GF(p)[t]/(m(t)^3)`
gives a polynomial `g` with `g(f(t)) = t`, and `g(C) = g(f(X)) = X`. That hands
back all three blocks at once without building any huge Frechet-derivative matrix.

## Exploitation

The end-to-end driver is `solve.py`, which chains the four substantive stages.
Run it on a host with `sage-run` and `flatter` (the two lattice reductions are
the expensive part — roughly 9 minutes and 1 minute on this instance):

```bash
python3 solve.py remote_public.json remoteemb
```

**Stage 1 — project and extract the orthogonal lattice (`projected_embedding.sage`).**
We select 152 of the 256 matrix coordinates (deterministically from the seed,
always including every diagonal entry, the full first row, and the first four
full columns), build `V = [vec(I); vec(C0); ...; vec(C0^15)]` on those
coordinates, and find its integer orthogonal lattice using a large-penalty
embedding `[e_i | 2^5000 * V[:,i]]`. After `flatter` reduces it, 136 rows have an
exactly-zero 16-coordinate tail — those are the orthogonal relations.

**Stage 2 — second orthogonal complement (`make_second_embedding.py`).**
One of the 136 relations is the "long" one whose integer dot product with `A`
equals `±p`; we drop it and keep the 135 exact ones. Reducing a second embedding
`[e_i | 2^80 * E[:,i]]` surfaces two unusually short vectors: the trivial
identity, and the secret `A + tI`. On the live instance their
`(norm²-bits, max-coord)` were `(5, 1)` and `(35, 48805)`; the public mixing
factors pick out the real one (every off-diagonal entry must divide its factor
into a byte 0..255).

**Stage 3 — recover the prime and complete x0 (`recover_modulus.py`).**
With `B = A + tI` known on the projected coordinates (which include row 0 and
columns 0..3), compute four full integer commutator entries and GCD them:

```python
for j in range(4):
    e = sum(C[0][k]*partial[k*N+j] - partial[k]*C[k][j] for k in range(N))
p = gcd(abs(e0), abs(e1), abs(e2), abs(e3))
```

The script verifies `p` is a 2048-bit prime larger than every printed value,
reconstructs the full `B` from its first row via the cyclic centralizer, then
sweeps the diagonal-shift ambiguity `t` (byte bounds narrowed it to 111..163)
and keeps the unique `t = 127` for which `f(A) == C0 mod p`.

**Stage 4 — recover x1, x2 and unmask the flag (`finish_recover.sage`).**
Work in `R = GF(p)[t]/(m(t)^3)`, compute `y = f(t)` by modular powering (never
forming the degree-4097 polynomial), solve one 48x48 system for `g` with
`g(y) = t`, then evaluate `g` on the public cap blocks using 16x16 triples to
get `x0, x1, x2` simultaneously. Divide each signed entry by its seed-derived
mixing factor to recover the three byte slabs, locate the sealed bytes at the
seed-determined offset in `m2`, and XOR off the SHA-512 mask (now that `p` is
known).

## Flag

```
pwnsec{a91f7010a581800b}
```

A cached final run prints:

```text
[*] short second-kernel rows: [(5, 1), (35, 48805)]
[+] recovered p (2048 bits) = 1933285945531078796485996...
[+] unique diagonal shift 127
[+] inverted f modulo charpoly(x0)^3
[+] insertion offset 219
[+] flag bytes b'pwnsec{a91f7010a581800b}'
[FLAG] pwnsec{a91f7010a581800b}
```

## Key Takeaways

- A hidden modulus can be recovered indirectly: find a short secret vector in a
  public modular span, then use exact **integer** commutators to expose multiples
  of the modulus and GCD them.
- Large-penalty lattice embeddings are a practical way to extract integer
  orthogonal lattices when direct kernel saturation in Sage is too slow.
- The scalar-identity ambiguity (`A` vs `A + tI`) is natural in matrix-centralizer
  attacks; byte bounds plus the original polynomial equation remove it.
- For repeated block-triangular matrices, inverting a scalar polynomial modulo an
  annihilating polynomial (`m(X)^3 = 0`) is far cheaper than building large
  Frechet-derivative systems.
