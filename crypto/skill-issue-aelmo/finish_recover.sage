#!/usr/bin/env sage-run
"""Recover x1/x2 and the flag once p and x0 are known.

If m is the characteristic polynomial of x0, then m(X)^3 = 0 for the
three-block upper Toeplitz matrix X.  We therefore invert the public scalar
polynomial f in GF(p)[t]/(m(t)^3), obtaining a polynomial g with
g(f(t)) == t mod m^3.  Evaluating g on the three public cap blocks yields all
three secret blocks at once.
"""
from sage.all import *
import hashlib
import json
import operator
import sys

N = 16


def stream(seed, tag, out_len):
    out = b""
    ctr = 0
    while len(out) < out_len:
        out += hashlib.shake_256(seed + tag + ctr.to_bytes(2, "little")).digest(64)
        ctr += 1
    return out[:out_len]


def mask(seed, k, out_len):
    k = int(k)
    kb = k.to_bytes((k.bit_length() + 7) // 8, "big")
    out = b""
    ctr = 0
    while len(out) < out_len:
        out += hashlib.sha512(
            b"iLOVEtea"
            + len(kb).to_bytes(2, "big")
            + kb
            + seed
            + ctr.to_bytes(4, "little")
        ).digest()
        ctr += 1
    return out[:out_len]


def diag(seed, tag):
    out = []
    ctr = 0
    while len(out) < N:
        for x in stream(seed, tag + ctr.to_bytes(2, "little"), 64):
            v = 2 + x % 241
            if v not in out and all(abs(v - y) != 1 for y in out):
                out.append(v)
                if len(out) == N:
                    break
        ctr += 1
    return out


def triple_mul(a, b):
    """Multiply upper block-Toeplitz triples (a0,a1,a2)."""
    a0, a1, a2 = a
    b0, b1, b2 = b
    return (
        a0 * b0,
        a0 * b1 + a1 * b0,
        a0 * b2 + a1 * b1 + a2 * b0,
    )


def cap_blocks(cap, F):
    # cap is the row-major list of the public 48 by 48 matrix.
    return tuple(
        matrix(F, N, N, [cap[i * (3 * N) + b * N + j]
                         for i in range(N) for j in range(N)])
        for b in range(3)
    )


def center_matrix(M, p):
    ans = []
    half = p // 2
    for x in M.list():
        z = ZZ(x)
        ans.append(z if z <= half else z - p)
    return ans


def main():
    pubfn = sys.argv[1] if len(sys.argv) > 1 else "local_public.json"
    recfn = sys.argv[2] if len(sys.argv) > 2 else "local_recovered_x0.json"
    outfn = sys.argv[3] if len(sys.argv) > 3 else "local_recovered_full.json"

    pub = json.load(open(pubfn))
    rec = json.load(open(recfn))
    p = ZZ(rec["p"])
    F = GF(p)
    A = matrix(F, N, N, rec["x0"])

    R = PolynomialRing(F, "t")
    t = R.gen()
    m = R(A.charpoly())
    assert m.degree() == N
    M = m**3
    print("[*] characteristic modulus degree", M.degree(), flush=True)

    # Never form the degree-4097 polynomial itself: modular powering keeps all
    # intermediates below degree 48.
    y = (power_mod(t, 4097, M)
         + 3 * power_mod(t, 257, M)
         + 11 * power_mod(t, 17, M)
         + 42 * t + 99) % M
    powers = [R.one()]
    for _ in range(1, 3 * N):
        powers.append((powers[-1] * y) % M)

    # Columns are the coefficient vectors of 1,y,...,y^47.  Solve for g such
    # that g(y)=t in the quotient ring.
    Y = matrix(F, 3 * N, 3 * N,
               lambda i, j: powers[j][i] if i <= powers[j].degree() else 0)
    target = vector(F, [0, 1] + [0] * (3 * N - 2))
    if Y.rank() != 3 * N:
        raise ValueError("f does not generate the full quotient algebra")
    gc = Y.solve_right(target)
    check = sum((gc[k] * powers[k] for k in range(3 * N)), R.zero()) % M
    assert check == t
    print("[+] inverted f modulo charpoly(x0)^3", flush=True)

    C = cap_blocks(pub["cap"], F)
    Z = zero_matrix(F, N)
    I = identity_matrix(F, N)
    value = (Z, Z, Z)
    for coefficient in reversed(gc):
        value = triple_mul(value, C)
        value = (value[0] + coefficient * I, value[1], value[2])

    xs = [center_matrix(B, p) for B in value]
    assert xs[0] == [ZZ(z) for z in rec["x0"]]

    seed = bytes.fromhex(pub["seed"])
    ds = [diag(seed, tag) for tag in (b"a", b"b", b"c")]
    slabs = []
    for b in range(3):
        raw = []
        for i in range(N):
            for j in range(N):
                scale = 1 + ds[b][i] - ds[b][j]
                z = xs[b][i * N + j]
                if z % scale:
                    raise ValueError("recovered block is not exactly divisible by mix scale")
                q = z // scale
                if not 0 <= q <= 255:
                    raise ValueError("recovered slab entry is outside byte range")
                raw.append(int(q))
        slabs.append(raw)
    print("[+] unmixed all three random slabs", flush=True)

    flag_len = int(pub["flag_len"])
    pos = int.from_bytes(stream(seed, b"2", 2), "little")
    pos %= N * N - flag_len + 1
    sealed = bytes(slabs[2][pos:pos + flag_len])
    # Sage's preparser interprets ``^`` as exponentiation.
    plain = bytes(operator.xor(x, y) for x, y in zip(sealed, mask(seed, p, flag_len)))
    print("[+] insertion offset", pos, flush=True)
    print("[+] flag bytes", repr(plain), flush=True)

    out = {
        "p": int(p),
        "x": [[int(z) for z in row] for row in xs],
        "m": slabs,
        "position": int(pos),
        "flag_hex": plain.hex(),
        "flag": plain.decode("utf-8"),
    }
    with open(outfn, "w") as fh:
        json.dump(out, fh)
    print("[+] wrote", outfn, flush=True)


# ``sage-run`` invokes Sage's file loader with ``__name__ == 'sage.all'``.
# Keep this as a script rather than an importable module.
main()
