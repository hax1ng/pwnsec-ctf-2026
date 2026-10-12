#!/usr/bin/env python3
"""Invert the final FSE layer from the recovered 500-bit witness."""

from collections import defaultdict
from pathlib import Path

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

bits = [int(c) for c in Path("witness_bits.txt").read_text().strip()]
assert len(bits) == 500

# The encoder emits the final seven-bit state first, least-significant bit first.
final_state = sum(bits[i] << i for i in range(7))

# Each row is: old_state, symbol, new_state, payload, payload_bit_count.
inverse = defaultdict(list)
for line in Path("fse_table.txt").read_text().splitlines():
    tag, old, sym, new, payload, nbits = line.split()
    assert tag == "FSE"
    old, sym, new, payload, nbits = map(int, (old, sym, new, payload, nbits))
    inverse[new].append((old, sym, payload, nbits))


def payload_at(pos, nbits):
    """Read an LSB-first bit string from the witness as an integer."""
    if pos + nbits > len(bits):
        return None
    return sum(bits[pos + i] << i for i in range(nbits))


# The source is encoded from character 95 down to character 0.  Its transition
# records are then emitted in character order 0..95, so decode by walking the
# FSE state machine backwards from the final state.
states = {(final_state, 7): ""}
for char_index in range(96):
    nxt = {}
    for (new_state, pos), prefix in states.items():
        for old_state, symbol, payload, nbits in inverse[new_state]:
            if payload_at(pos, nbits) == (payload & ((1 << nbits) - 1)):
                key = (old_state, pos + nbits)
                # One path is sufficient; all surviving paths are equivalent
                # candidates until the fixed initial state/length check below.
                nxt.setdefault(key, prefix + ALPHABET[symbol])
    states = nxt
    print(f"after char {char_index + 1:2}: {len(states):5} states")

candidates = [s for (state, pos), s in states.items() if state == 70 and pos == 500]
print(f"final FSE state: {final_state}")
print(f"valid candidates: {len(candidates)}")
for candidate in candidates:
    print(candidate)

