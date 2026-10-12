#!/usr/bin/env python3
"""Restore the 32 erased GF(2^23) Cathedral symbols in the attachment."""

from pathlib import Path
import sys

MASK = (1 << 23) - 1
REDUCTION = 0x800021
BASE = 0x289158


def mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
        if a & (1 << 23):
            a ^= REDUCTION
    return out & MASK


def inv(a: int) -> int:
    if not a:
        raise ZeroDivisionError
    # The nonzero multiplicative group has order 2^23-1.
    out, base, exponent = 1, a, (1 << 23) - 2
    while exponent:
        if exponent & 1:
            out = mul(out, base)
        base = mul(base, base)
        exponent >>= 1
    return out


def parity(data: list[int], row: int) -> int:
    x = row + 1
    out = 0
    for col, value in enumerate(data):
        out ^= mul(value, inv((0x1000 + col) ^ x))
    return out


def main() -> None:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "icx-emu.repaired")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "icx-emu.fixed")
    image = bytearray(src.read_bytes())

    get3 = lambda off: int.from_bytes(image[off : off + 3], "little")
    data = [get3(BASE + 0x1000 + 3 * i) for i in range(512)]
    checks = [get3(BASE + 0x1600 + 3 * i) for i in range(64)]
    erased = [
        int.from_bytes(image[BASE + 0x16C0 + 2 * i : BASE + 0x16C2 + 2 * i], "little")
        for i in range(32)
    ]
    assert len(set(erased)) == 32 and all(data[i] == 0 for i in erased)

    # Cauchy parity equation used by native routine 0x8db30:
    #   check[r] = XOR_i data[i] / ((0x1000+i) XOR (r+1)).
    erased_set = set(erased)
    matrix: list[list[int]] = []
    for row in range(32):
        rhs = checks[row]
        for col, value in enumerate(data):
            if col not in erased_set:
                rhs ^= mul(value, inv((0x1000 + col) ^ (row + 1)))
        matrix.append(
            [inv((0x1000 + col) ^ (row + 1)) for col in erased] + [rhs]
        )

    # Reduced-row-echelon Gaussian elimination over GF(2^23).
    n = len(erased)
    for col in range(n):
        pivot = next(row for row in range(col, n) if matrix[row][col])
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        scale = inv(matrix[col][col])
        matrix[col] = [mul(v, scale) for v in matrix[col]]
        for row in range(n):
            if row == col or not matrix[row][col]:
                continue
            scale = matrix[row][col]
            matrix[row] = [a ^ mul(scale, b) for a, b in zip(matrix[row], matrix[col])]

    recovered = [matrix[i][-1] for i in range(n)]
    for col, value in zip(erased, recovered):
        data[col] = value
        off = BASE + 0x1000 + 3 * col
        image[off : off + 3] = value.to_bytes(3, "little")

    assert all(parity(data, row) == checks[row] for row in range(64))
    dst.write_bytes(image)
    dst.chmod(0o755)
    print(f"wrote {dst}; restored:")
    print(" ".join(f"{i}:{value:06x}" for i, value in zip(erased, recovered)))


if __name__ == "__main__":
    main()
