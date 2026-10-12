#!/usr/bin/env python3
"""Build the augmented-relation embedding from the first flatter output."""
import re
import sys


def parse_rows(path):
    ans = []
    with open(path) as fh:
        for line in fh:
            row = [int(x) for x in re.findall(r"-?\d+", line)]
            if row:
                ans.append(row)
    return ans


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "localemb"
    ncoords = 152
    first = parse_rows(prefix + "_flatter.txt")
    kernel = [r[:ncoords] for r in first
              if len(r) == ncoords + 16 and all(x == 0 for x in r[ncoords:])]
    if len(kernel) != ncoords - 16:
        raise ValueError(f"wanted 136 exact kernel rows, got {len(kernel)}")
    kernel.sort(key=lambda r: sum(x * x for x in r))

    # The unique longest relation has dot(A) = +/-p.  Retaining the 135
    # shorter, genuinely integral orthogonal relations leaves one extra short
    # direction (A+tI) in their orthogonal complement.
    exact = kernel[:135]
    print("[*] first-kernel norm^2 bits:",
          [sum(x*x for x in r).bit_length() for r in kernel[-5:]], flush=True)

    Q = 1 << 80
    out = prefix + "_second_embedding.txt"
    with open(out, "w") as fh:
        fh.write("[")
        for i in range(ncoords):
            row = [int(i == j) for j in range(ncoords)]
            row += [Q * exact[k][i] for k in range(len(exact))]
            if i:
                fh.write("\n")
            fh.write("[" + " ".join(map(str, row)) + "]")
        fh.write("]\n")
    print("[*] wrote", out, "as", ncoords, "x", ncoords + len(exact), flush=True)


if __name__ == "__main__":
    main()
