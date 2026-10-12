# The One Hit Wonder

**Category:** Crypto | **Difficulty:** Medium | **Points:** 291 | **Flag:** `pwnsec{51c280adbb0f9060}`

## Challenge Description

The challenge is an interactive service (`chall.py`) with a tiny menu:

```text
1) info    2) tap    3) log    4) check    5) quit
```

It generates a 1536-bit strong prime `p` and two secrets `u, v`, then lets you
"tap" the function `z(t) = v / (u + t) mod p` at up to **eight** distinct inputs
— but each tap only returns the **top 890 bits** of `z`. The `check` option asks
you to hand back the exact `u` and `v`; a wrong guess just prints `no`. Get it
right and it prints the flag.

## Initial Analysis

The relevant part of `chall.py`:

```python
p = int(getStrongPrime(1536))
n = p.bit_length()          # 1536
k = (58 * n) // 100         # 890 kept bits
u = randbelow(p)
v = randbelow(p - 1) + 1
...
z = (v * pow((t + u) % p, -1, p)) % p
h = top(z, k, n)            # z >> (1536 - 890)  -> drops the low 646 bits
```

Sizes:

```text
modulus      n = 1536 bits
returned     k =  890 bits  (per tap)
hidden       646 bits  (per tap)
samples      8
```

890 known bits out of 1536 sounds generous, but every sample hides a *different*
646-bit suffix, and `check` is one-shot — no brute force. The eight taps have to
cooperate.

## The Vulnerability / Core Concept

Write each unknown value as `z_i = h_i·B + r_i` with `B = 2^646` and
`0 ≤ r_i < B`. Centering the missing interval, set `C_i = h_i·B + B/2` and
`e_i = z_i − C_i`, so `−B/2 ≤ e_i < B/2`. The original relation becomes

```text
(C_i + e_i)(u + t_i) = v  mod p.
```

That is **bilinear** (it contains `e_i·u`), which ordinary hidden-number-problem
lattices can't attack directly.

The key move is to choose **consecutive taps** `t_i = i` for `i = 0..7` and take
repeated finite differences. Because `z_i = v/(u+i)`, the reciprocal
finite-difference identity makes the transformed values `S_j` collapse into a
very sparse recurrence. With `x = −u mod p`:

```text
(7 − j)·S_{j+1} = (x − j)·S_j   mod p,    j = 0..6.
```

This is the whole trick: the original problem had **two** unrestricted 1536-bit
secrets; the recurrence has only **one** large unknown `x`, and `v` has vanished
completely. Applying the same transform to the known centers `C_i` gives
`S_j = A_j + d_j`, where each transformed error `d_j` grew by at most 7 bits
(largest ≈ 653 bits), still tiny next to the 1536-bit modulus. Substituting into
the recurrence yields seven modular polynomials in one big unknown `x` and eight
small bounded errors `d_0..d_7` — exactly the shape multivariate Coppersmith
eats for breakfast.

## Exploitation

**Collect eight consecutive taps.** `solve_remote.py` connects to the live
service (host redacted to `CHALLENGE_HOST`), pulls `p, n, k`, and taps
`t = 0,1,...,7`. Crucially it keeps the TLS session open the whole time — the
prime and secrets are fresh per connection, so the `check` has to happen on the
same socket. While the heavy lattice work runs, it keeps the session alive with
the harmless `log` command.

**Solve the bounded errors with Cuso (`solve_difference.py`).** This is the core
solver. It rebuilds the finite-difference coefficients, bounds each `d_j`, and
feeds the seven recurrence relations to [Cuso](https://github.com/keeganryan/cuso)'s
multivariate Coppersmith routine:

```python
rels = [(7-i)*s[i+1] - (x-i)*s[i] == 0 for i in range(7)]
roots = cuso.find_small_roots(
    rels, bounds, modulus=p,
    use_graph_optimization=False,   # unhelpful for this sparse chain
    allow_partial_solutions=True,   # d_j recovered even if x isn't in the dict
)
```

At the real 1536-bit parameters, multiplicity 2 suffices — Cuso reaches a dual
lattice of rank 96, extracts 30 integer relations, and returns one partial root
with every `d_j`. This is the >5 s step, so it runs on the `remote` compute host
via `sage-run`.

**Recover `u` and `v` algebraically.** With the `d_j` known, reconstruct
`S_j = A_j + d_j`. The recurrence at `j = 0` gives `x = 7·S_1 / S_0 mod p`, hence
`u = −x`. The last coordinate is `S_7 = z_7 = v/(u+7)`, so `v = S_7·(u+7) mod p`.
No brute force.

**Verify, then check.** Before spending the single `check`, recompute all eight
prefixes locally:

```python
for t in range(8):
    z = v * pow((u+t) % p, -1, p) % p
    assert (z >> 646) == highs[t]
```

All eight match, `check` is sent on the still-open socket, and the service
returns the flag. (The attack was validated first on 256-bit and full 1536-bit
known-secret instances so nothing was wasted against the live endpoint.)

## Flag

```
pwnsec{51c280adbb0f9060}
```

## Key Takeaways

- The challenge isn't about guessing missing bits — it's about *choosing queries
  that expose structure*. Arbitrary taps look like unrelated truncated fractions;
  consecutive taps `0..7` turn them into a short recurrence.
- Finite differences of `v/(u+i)` kill the numerator `v` and leave a single large
  unknown — collapsing a nasty bilinear problem into a Coppersmith-friendly one.
- `allow_partial_solutions=True` matters: Cuso can return the bounded roots even
  when its Groebner step omits the unbounded variable.
- Dead ends worth remembering: treating products `u·e_i` as independent linear
  unknowns throws away shared structure and fails; directly eliminating `u, v`
  gives valid quadratics but needs impractical Coppersmith multiplicity; and SMT
  bit-vector solvers choke on nonlinear multiplication even at 256 bits.
