# Gap Gap

**Category:** Crypto | **Difficulty:** Medium | **Points:** 112 | **Flag:** `pwnsec{4a2da9c8b17309f8}`

## Challenge Description

> There are two gaps in this RSA key.
>
> One gap is in the private exponent. The other is hiding between a shared divisor and the modulus.
>
> **- @chamaaaa**

We're given `chall.py` (the RSA key generator) and a live service that prints a fresh `N`, `e`, `c`, and a partially redacted private exponent `d_leak` each connection.

## Initial Analysis

This looks like RSA, but the key generation is doing something very unusual. Instead of two independent random primes, it builds both primes out of a shared 600-bit prime `g`:

```python
g = getPrime(600)
p = 2 * g * a + 1          # so p - 1 = 2*g*a
q = 2 * g * b + 1          # so q - 1 = 2*g*b
h = p * b + a
lam = 2 * g * a * b        # Carmichael lambda, since gcd(a,b)=1
e = pow(d, -1, lam)
```

The service also hands us the private exponent `d` with a hole punched in it. The full `d` is 124 decimal digits; we get the first 47 and the last 47, with the middle 30 digits replaced by `*`:

```text
d_leak = '93561958556505568031598881410780016108913853954' + '*'*30 + '61501251584271136576288777262606558999703562879'
```

So the "two gaps" from the flavor text are literal:

1. a 30-digit **gap in the private exponent**, and
2. a hidden shared divisor `g` sitting **between `N-1` and the modulus** structure.

A small-looking `d` screams "Wiener", but that's a red herring here — `e` is an inverse modulo the ~1448-bit Carmichael value, not a normal full-size RSA relation, so Wiener's `e/N` approximation doesn't model this. The real levers are the shared divisor and the leaked digits.

## The Vulnerability / Core Concept

Two algebraic facts fall out of the generator, and together they break it.

**Fact 1 — `2*g` divides `e*d - 1`.** Because `d` is the private exponent, `e*d - 1 = k * lambda = k * (2*g*a*b)` for some integer `k`. So `e*d - 1` is a multiple of `2*g`, and in particular of the unknown 600-bit prime `g`.

**Fact 2 — `2*g` divides `N - 1` too.** Expand the modulus:

```text
N - 1 = (2*g*a + 1)(2*g*b + 1) - 1
      = 2*g*(2*g*a*b + a + b)
      = 2*g*h           (since h = p*b + a = 2*g*a*b + a + b)
```

So the same hidden `g` divides both the private-exponent relation and `N - 1`. That's the "gap between a shared divisor and the modulus."

Now the leaked digits turn this into a textbook **Coppersmith** problem. Let `x` be the unknown 30-digit middle block (`0 <= x < 10^30`, about 100 bits). Writing the known pieces as a prefix and suffix:

```text
d(x) = prefix*10^77 + suffix + 10^47 * x = d0 + B*x,   B = 10^47
```

For the correct `x`, the polynomial `F(x) = e*d(x) - 1` is `0 (mod g)`. We don't know `g`, but we know it's a ~600-bit factor of the known number `(N-1)/2`. That's exactly the setup for **univariate Coppersmith over an unknown divisor** (`small_roots` with a `beta` parameter).

**Why divide by two?** Working directly mod `N-1` fails: both `N-1` and the leading coefficient `e*10^47` are even, so the leading coefficient isn't invertible and Sage can't make the polynomial monic. Dividing the relation and the modulus by their common factor of 2 fixes it:

```text
M = (N-1)/2 = g*h
f(x) = (e*d0 - 1)/2 + (e*B/2)*x   (mod M)
```

`g` is 600 bits, `M` is ~2047 bits, so `g` is about `600/2047 ≈ 0.293` of the modulus. Using `beta = 0.292` with a ~100-bit root is comfortably inside the Coppersmith bound.

## Exploitation

Full solver: **`solve.sage`** (SageMath, for the lattice step) with **`verify.py`** as a fast pure-Python cross-check.

**Step 1 — Recover the 30 missing digits with Coppersmith.** This is the one heavy (lattice) step:

```python
B = 10^47
d0 = prefix * 10^77 + suffix
M = (N - 1) // 2
R.<x> = PolynomialRing(Zmod(M))
f = (e * d0 - 1) // 2 + (e * B // 2) * x
f = f * inverse_mod(Integer(f.leading_coefficient()), M)   # make it monic
roots = f.small_roots(X=10^30, beta=0.292, epsilon=0.02)
middle = Integer(roots[0])        # -> 394763461651477606961253008639
d = Integer(d0 + B * middle)      # full 124-digit private exponent
```

**Step 2 — Pull out the shared divisor with a GCD.** Both relations share `2*g`:

```python
g = gcd(e*d - 1, N - 1) // 2
assert g.nbits() == 600 and is_prime(g)
```

**Step 3 — Factor `N` from the `N-1 = 2*g*h` structure.** We have `h = (N-1)/(2*g)`, and since `h = lambda + (a+b)` with `a+b` tiny (~425 bits) compared to `h` (~1447 bits), `k` is simply the nearest integer to `e*d/h`:

```python
h = (N - 1) // (2*g)
k = Integer(round(QQ(e*d) / h))
lam = (e*d - 1) // k
s  = h - lam          # = a + b
ab = lam // (2*g)     # = a * b
Delta = s^2 - 4*ab
sqrt_Delta = Integer(Delta).isqrt()
a = (s + sqrt_Delta) // 2
b = (s - sqrt_Delta) // 2
p, q = 2*g*a + 1, 2*g*b + 1
```

`verify.py` does the same split even more directly: since `a+b < 2*g`, a single `divmod(h, 2*g)` separates the product `a*b` from the sum `a+b`.

**Step 4 — Decrypt.** With `p`, `q`, and the full `d` recovered, `m = c^d mod N`, and `long_to_bytes(m)` is the flag. The script asserts primality, `p*q == N`, `lcm(p-1,q-1) == lambda`, `e*d ≡ 1 (mod lambda)`, and re-encryption before trusting the result.

The lattice step was offloaded to a heavier host as required:

```bash
scp solve.sage verify.py <compute-host>:/tmp/
ssh <compute-host> 'sage-run /tmp/solve.sage /tmp/capture.txt'
```

**Gotcha worth remembering:** the static attachment tuple and the *live* service used **different** generated keys. The attachment decrypted cleanly to `pwnsec{mind_the_gap_between_lambda_and_phi}`, which looked like a win but was **rejected** — it's a decoy baked into the sample output. The accepted flag only came from solving the fresh per-connection tuple. The scripts here embed that live instance, so running them reproduces the real flag.

## Flag

```
pwnsec{4a2da9c8b17309f8}
```

Quick reproduction (no Sage needed — uses the digits Coppersmith already found):

```bash
$ python3 verify.py
plaintext = b'pwnsec{4a2da9c8b17309f8}'
```

## Key Takeaways

- Structured RSA primes (`p = 2*g*a + 1`) leak algebraic relations. Here the same hidden `g` divides both `e*d - 1` and `N - 1`.
- A partially known secret becomes a Coppersmith **small-root over an unknown divisor** problem when the correct value vanishes modulo a large unknown factor.
- Check that a polynomial's leading coefficient is invertible before making it monic — dividing out a common factor of 2 was the small but essential preprocessing step.
- Generator size constraints can turn an approximate relation into an exact one: `a + b < 2*g` lets a plain `divmod` recover the factors.
- In instance-based CTFs, a mathematically valid plaintext from the *static attachment* can still differ from the *live* accepted flag. Always solve the fresh capture.
