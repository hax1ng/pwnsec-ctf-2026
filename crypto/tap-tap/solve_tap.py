#!/usr/bin/env python3
# tap-tap solver: lattice-recover a truncated Fibonacci LFSR over GF(p), rebuild
# the full sequence, then reproduce the SHA-256/SHAKE-256 keystream and decrypt.
import ast
import re
import sys
from hashlib import sha256, shake_256

from scripts.lsb_truncated_fibonacci_lfsr_solver import solve_auto_from_outputs


def load_instance(path):
    src = open(path, "r", encoding="utf-8").read()
    matches = re.findall(r"'''\s*(\[[0-9, ]+\])\s*([0-9a-f]+)\s*'''", src, re.S)
    if len(matches) != 1:
        raise ValueError(f"could not uniquely parse challenge output ({len(matches)=})")
    ys = ast.literal_eval(matches[0][0])
    ct = bytes.fromhex(matches[0][1])
    return ys, ct


ys, ct = load_instance(sys.argv[1] if len(sys.argv) > 1 else "chall.py")
print(f"[*] Parsed {len(ys)} high-bit outputs and {len(ct)} ciphertext bytes")

result = solve_auto_from_outputs(
    n=25,
    k=128,
    h=80,
    ell=48,
    outputs=ys,
    start_index=25,
    margin=10,                 # r=t=90, so all 180 supplied samples are useful
    reduction="flatter+bkz",
    near_power=128,
    near_side="below",
    modulus_offset_bits=50,   # 2^128-p lies between about 2^48 and 2^50
    bkz_block=10,
    bkz_timeout=1200,
    poly_rows=40,
    max_resultants=20,
    verbose=True,
)

p = int(result["modulus"])
coeffs = [int(x) for x in result["feedback_coefficients"]]
initial = [int(x) for x in result["initial_state"]]
observed = [int(x) for x in result["full_observed_sequence"]]

# Case I only needs `d` exact observed terms to recover the state.  Regenerate
# all 205 terms from that state before reproducing the challenge's hash input.
A = initial[:]
while len(A) < 205:
    A.append(sum(coeffs[j] * A[-25 + j] for j in range(25)) % p)

assert len(A) == 205
assert A[25:25 + len(observed)] == observed
assert all((A[25 + i] >> 48) == ys[i] for i in range(180))
assert all(
    A[i] == sum(coeffs[j] * A[i - 25 + j] for j in range(25)) % p
    for i in range(25, 205)
)

seed = sha256("".join(map(str, A)).encode()).digest()
key = shake_256(seed).digest(len(ct))
flag = bytes(x ^ y for x, y in zip(ct, key))

print(f"[+] p = {p}")
print(f"[+] feedback coefficients = {coeffs}")
print(f"[+] initial state = {initial}")
print(f"[+] flag = {flag!r}")
