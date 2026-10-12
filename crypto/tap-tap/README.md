# tap tap

**Category:** Crypto | **Difficulty:** Medium | **Points:** 122 | **Flag:** `pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}`

## Challenge Description

> tap tap, who's there?
>
> **- @Tsumi**

We get `chall.py`, which generates a sequence of big numbers, chops the low bits off each, prints the high bits plus a ciphertext, and quits.

## Initial Analysis

The whole generator fits in a few lines:

```python
p = 2**128 - randint(2**48, 2**50)       # prime just below 2^128
while not isPrime(p):
    p -= 1

n = 25
C = [randint(1, p) for _ in range(n)]    # 25 secret feedback coefficients
A = [randint(1, p) for _ in range(n)]    # 25 secret initial state words

for _ in range(180):                      # extend the sequence 180 steps
    A.append(sum(ci * ai for ci, ai in zip(C[::-1], A[::-1])) % p)

Y = [ai >> 48 for ai in A[::-1][:180]][::-1]   # leak only the top 80 bits

seed = sha256(''.join(map(str, A)).encode()).digest()
key  = shake_256(seed).digest(len(flag))
ct   = strxor(key, flag)
```

Three things are secret: the prime `p`, the 25 coefficients `C`, and the full sequence `A` (low bits included). The hashing itself is not broken — SHA-256 and SHAKE-256 are doing their job. The weakness is that their **input is a recoverable linear sequence**.

Each printed value is a 128-bit number with its bottom 48 bits sawn off:

```text
A[i+25] = 2^48 * Y[i] + z[i],   0 <= z[i] < 2^48
```

So we know 80 of the 128 bits of each output, for 180 consecutive outputs.

## The Vulnerability / Core Concept

This is a **Fibonacci-style LFSR over `GF(p)`** of order 25:

```text
A[t] = C[0]*A[t-25] + C[1]*A[t-24] + ... + C[24]*A[t-1]   (mod p)
```

If full outputs were printed, plain linear algebra would recover the coefficients. The twist is that only the high 80 bits leak and the recurrence is over an **unknown** prime. But "many modular linear equations, each off by a small error" is precisely what lattice reduction eats for breakfast. This is the **truncated-LFSR / truncated-LCG** family of attacks.

A couple of structural gifts make it tractable:

- **`p` lives just below `2^128`.** `p = 2^128 - (a 48-to-50-bit number)`, so even though `p` is secret we know exactly where to search for it. That lets us build the first lattice around the known power of two without `p` up front.
- **The sample count is a hint.** The sliding-window heuristic gives window size `r = t = ceil(2*n*k/h) = ceil(2*25*128/80) = 80`. With a margin of 10, `r = t = 90`, which needs `r + t - 1 = 179` consecutive leaks. The challenge hands over exactly 180. That's a strong nudge toward the intended lattice.

Parameters: `n = 25` (order), `k = 128` (full word size), `ell = 48` (hidden low bits), `h = 80` (leaked high bits).

## Exploitation

Full solver: **`solve_tap.py`**. It wraps the lattice engine from
[`truncated-fibonacci-lfsr-solver`](https://github.com/MrBanhMi/truncated-fibonacci-lfsr-solver)
with the challenge-specific parsing, sequence rebuild, and decryption.

**Step 1 — Find annihilating relations with a lattice.** Take length-90 sliding windows of the leaked values. Because the real sequence has order 25, enough shifted windows can't be independent; there are integer combinations that cancel modulo the real `p`. The hidden low bits add a small error, which lattice reduction (`flatter` + a short BKZ pass) exploits to return short vectors = **annihilating polynomials** (compact linear equations the sequence obeys). The true degree-25 recurrence polynomial divides each of them modulo `p`.

**Step 2 — Recover the unknown modulus `p`.** For pairs of recovered polynomials, compute their **resultant**. The resultant vanishes modulo a number when the two polynomials share a factor modulo it, so every useful resultant carries a big factor of `p^25`. Taking the GCD of several resultants lands on a ~3200-bit number (`25 * 128 = 3200`, exactly `p^25`). Restricting to the known interval below `2^128` pins it down:

```text
p = 340282366920938463463374127620052448857
```

**Step 3 — Recover the coefficients.** Reduce the annihilating polynomials mod `p` and take their polynomial GCD in `GF(p)[x]`. The shared degree-25 factor is the characteristic polynomial; its coefficients are the original 25 feedback taps.

**Step 4 — Put the low bits back.** With the recurrence known, each `A[i] = 2^48*Y[i] + z[i]` with `z[i] < 2^48` gives modular equations in the small unknowns. A second, smaller lattice (Kannan embedding) recovers them. The leak starts at `A[25]`, but the hash input also needs `A[0..24]` — since `C[0]` is nonzero mod `p`, run the recurrence **backward** 25 steps:

```text
A[i] = C[0]^-1 * (A[i+25] - C[1]*A[i+1] - ... - C[24]*A[i+24])  (mod p)
```

**Step 5 — Rebuild the key and decrypt.** Regenerate all 205 terms, verify every value has the printed high bits and satisfies the recurrence, then reproduce the seed exactly — note it hashes the decimal strings **with no separators**:

```python
seed = sha256("".join(map(str, A)).encode()).digest()
key  = shake_256(seed).digest(len(ct))
flag = bytes(x ^ y for x, y in zip(ct, key))
```

Run it (needs SageMath + `flatter`; the lattice reduction is the expensive part):

```bash
git clone https://github.com/MrBanhMi/truncated-fibonacci-lfsr-solver.git
PYTHONPATH="$PWD/truncated-fibonacci-lfsr-solver" sage-run solve_tap.py chall.py
```

```text
[*] gcd(resultants) has 3200 bits
[*] Modulus candidates: [340282366920938463463374127620052448857]
[+] p = 340282366920938463463374127620052448857
[+] flag = b'pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}'
```

## Flag

```
pwnsec{wR17in6_17_t0oK_m3_thRe3__d4y5_d1d_4I_50lv3_i7_1n_thRe3_53c0nDs??}
```

## Key Takeaways

- Chopping bits off a linear-recurrence output doesn't make it safe: every sample still satisfies the same recurrence, and 180 of them give a lattice tons of repeated structure.
- Resultants + GCD recover an unknown modulus from polynomials that share a factor modulo it (`p^25` shows up as a ~3200-bit GCD).
- A prime "near a power of two" is a gift — you know where to look even before recovering it.
- Once the generator state is recovered, strong final hashes (SHA-256/SHAKE-256) can't save it: the attacker reconstructs their exact input. And watch the exact serialization — decimal join with no separators.
