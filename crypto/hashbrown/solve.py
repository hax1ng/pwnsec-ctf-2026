#!/usr/bin/env python3.13
"""Solver for PwnSec CTF 2026's Hashbrown challenge.

This file is intentionally usable both as a collection of local attack helpers and,
once the oracle wrapper is added, as the end-to-end exploit.
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

import numpy as np

from sha256 import K
from xxh3_custom import (
    EQUALITY_LEN,
    FORGE_LEN,
    INIT_ACC,
    KSECRET,
    MASK,
    P64_1,
    P64_2,
    PRIME_MX1,
    acc_for_1024_payload,
    custom_secret2,
    custom_xxh3_128,
    digest_from_acc,
    fold64,
    rle64,
    target_digest,
    wle64,
)


MASK32 = (1 << 32) - 1
SHA_IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


def ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def s0(x: int) -> int:
    return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3)


def s1(x: int) -> int:
    return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10)


def S0(x: int) -> int:
    return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22)


def S1(x: int) -> int:
    return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25)


def ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z)) & MASK32


def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def working_state(digest: bytes) -> list[int]:
    """Remove SHA-256's feed-forward from a one-block digest."""
    words = struct.unpack(">8I", digest)
    return [(words[i] - SHA_IV[i]) & MASK32 for i in range(8)]


def reverse_round(state: list[int], word: int, round_no: int) -> list[int]:
    """Invert one SHA-256 round when its schedule word is known."""
    A, B, C, D, E, F, G, H = state
    a, b, c = B, C, D
    e, f, g = F, G, H
    t2 = (S0(a) + maj(a, b, c)) & MASK32
    t1 = (A - t2) & MASK32
    d = (E - t1) & MASK32
    h = (t1 - S1(e) - ch(e, f, g) - K[round_no] - word) & MASK32
    return [a, b, c, d, e, f, g, h]


def bridge_words_8(start: list[int], end: list[int], first_round: int) -> list[int]:
    """Recover all eight injected words of an 8-round SHA-256 bridge.

    Eight rounds shift all eight independently-updated a/e words into the state.
    Consequently the start and end state uniquely determine the eight schedule
    words; no brute force is involved.
    """
    n = first_round

    # a[i] and e[i] denote the working variables at the start of round i.
    a: dict[int, int] = {
        n: start[0], n - 1: start[1], n - 2: start[2], n - 3: start[3],
        n + 8: end[0], n + 7: end[1], n + 6: end[2], n + 5: end[3],
    }
    e: dict[int, int] = {
        n: start[4], n - 1: start[5], n - 2: start[6], n - 3: start[7],
        n + 8: end[4], n + 7: end[5], n + 6: end[6], n + 5: end[7],
    }

    # e[t+1] = a[t-3] + a[t+1] - (Sigma0(a[t])+Maj(...)).
    # Work backwards from the known final four a/e pairs to get a[n+1..n+4].
    for t in range(n + 7, n + 3, -1):
        t2 = (S0(a[t]) + maj(a[t], a[t - 1], a[t - 2])) & MASK32
        a[t - 3] = (e[t + 1] - a[t + 1] + t2) & MASK32

    # The first four e values follow directly from the known initial a state.
    for t in range(n, n + 4):
        t2 = (S0(a[t]) + maj(a[t], a[t - 1], a[t - 2])) & MASK32
        e[t + 1] = (a[t - 3] + a[t + 1] - t2) & MASK32

    words = []
    for t in range(n, n + 8):
        t2 = (S0(a[t]) + maj(a[t], a[t - 1], a[t - 2])) & MASK32
        t1 = (a[t + 1] - t2) & MASK32
        word = (
            t1
            - e[t - 3]
            - S1(e[t])
            - ch(e[t], e[t - 1], e[t - 2])
            - K[t]
        ) & MASK32
        words.append(word)
    return words


def invert_linear32(func, y: int) -> int:
    """Invert an invertible GF(2)-linear 32-bit function."""
    # Build equations by transposing the images of the basis vectors.  Each
    # row is represented as 32 coefficient bits plus one RHS bit at bit 32.
    images = [func(1 << col) for col in range(32)]
    rows = []
    for bit in range(32):
        coeff = sum(((images[col] >> bit) & 1) << col for col in range(32))
        rows.append(coeff | (((y >> bit) & 1) << 32))

    pivot_row = 0
    for col in range(32):
        pivot = next((r for r in range(pivot_row, 32) if (rows[r] >> col) & 1), None)
        if pivot is None:
            raise ValueError("linear map is not invertible")
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        for r in range(32):
            if r != pivot_row and ((rows[r] >> col) & 1):
                rows[r] ^= rows[pivot_row]
        pivot_row += 1

    x = 0
    for row in rows:
        coeff = row & MASK32
        col = (coeff & -coeff).bit_length() - 1
        x |= ((row >> 32) & 1) << col
    assert func(x) == y
    return x


def recover_sha_key(digest_r24: bytes, digest_thr35: bytes) -> bytes:
    """Recover the entire 55-byte key from only the r24 and thr35 faults."""
    state24 = working_state(digest_r24)
    state64_zero_tail = working_state(digest_thr35)

    # In thr35, W[16..35] are empty slices (zero), and the recurrence beginning
    # at W[36] references only those zeros. Thus W[16..63] are all zero.
    state16 = state64_zero_tail
    for t in range(63, 15, -1):
        state16 = reverse_round(state16, 0, t)

    w16_23 = bridge_words_8(state16, state24, 16)
    W: list[int | None] = [None] * 24
    prefix = bytes.fromhex("5b0de77c5ad3bef911a29fb17c6634f48a1f91cae7ffde9f")
    for i in range(6):
        W[i] = int.from_bytes(prefix[4 * i : 4 * i + 4], "big")
    W[14] = 0
    W[15] = 55 * 8
    for i, value in enumerate(w16_23, 16):
        W[i] = value

    # Directly undo the first five expansion equations.
    W[9] = (W[16] - s1(W[14]) - s0(W[1]) - W[0]) & MASK32
    W[10] = (W[17] - s1(W[15]) - s0(W[2]) - W[1]) & MASK32
    W[11] = (W[18] - s1(W[16]) - s0(W[3]) - W[2]) & MASK32
    W[12] = (W[19] - s1(W[17]) - s0(W[4]) - W[3]) & MASK32
    W[13] = (W[20] - s1(W[18]) - s0(W[5]) - W[4]) & MASK32

    # The remaining equations reveal sigma0(W6), sigma0(W7), sigma0(W8).
    y6 = (W[21] - s1(W[19]) - W[14] - W[5]) & MASK32
    W[6] = invert_linear32(s0, y6)
    y7 = (W[22] - s1(W[20]) - W[15] - W[6]) & MASK32
    W[7] = invert_linear32(s0, y7)
    y8 = (W[23] - s1(W[21]) - W[16] - W[7]) & MASK32
    W[8] = invert_linear32(s0, y8)

    block = b"".join(int(x).to_bytes(4, "big") for x in W[:16])
    if block[55] != 0x80 or block[56:62] != bytes(6) or block[62:] != b"\x01\xb8":
        raise ValueError("recovered block has invalid SHA-256 padding")
    key = block[:55]
    if hashlib.sha256(key).digest() == b"":  # pragma: no cover (keeps lint happy)
        raise AssertionError
    return key


# ---------------------------------------------------------------------------
# Equality-oracle attack on the 64-bit XXH3 seed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SeedMap:
    """One pair of aligned secret words used by the seed collision gadget."""

    q1: int
    q2: int
    lane: int
    stripe1: int
    stripe2: int
    parameter: int
    subtract_map: bool


class EqualityOracle(Protocol):
    queries: int

    def equal_batch(self, pairs: list[tuple[bytes, bytes]]) -> list[bool]: ...


class LocalEqualityOracle:
    """Local reference oracle, useful for complete exploit self-tests."""

    def __init__(self, seed: int, delta_words: list[int]):
        self.seed = seed & MASK
        self.delta_words = delta_words
        self.queries = 0

    def equal_batch(self, pairs: list[tuple[bytes, bytes]]) -> list[bool]:
        self.queries += len(pairs)
        return [
            custom_xxh3_128(a, self.seed, self.delta_words)
            == custom_xxh3_128(b, self.seed, self.delta_words)
            for a, b in pairs
        ]


def secret_bases(delta_words: list[int]) -> list[int]:
    """Return C[i] where secret word i is C[i] +/- seed."""
    return [
        (rle64(KSECRET, 8 * i) + delta_words[i]) & MASK for i in range(24)
    ]


def aligned_secret_word(base: list[int], q: int, seed: int) -> int:
    return (base[q] + seed) & MASK if not (q & 1) else (base[q] - seed) & MASK


def available_seed_maps(base: list[int]) -> list[SeedMap]:
    """Maps supported by non-overlapping regular stripes of a 257-byte input.

    Stripe 3 overlaps the final stripe, so only stripes 0, 1, and 2 are used.
    """
    result: dict[tuple[int, int], SeedMap] = {}
    for lane in range(8):
        for s1_ in range(3):
            for s2_ in range(s1_ + 1, 3):
                q1, q2 = lane + s1_, lane + s2_
                if (q1, q2) in result:
                    continue
                a = base[q1] & MASK32
                b = base[q2] & MASK32
                opposite = (q1 ^ q2) & 1
                # Same signs: x -> x + (B-A). Opposite signs: x -> A+B-x.
                parameter = ((a + b) if opposite else (b - a)) & MASK32
                result[q1, q2] = SeedMap(
                    q1, q2, lane, s1_, s2_, parameter, bool(opposite)
                )
    return list(result.values())


def map_g_scalar(seed_low: int, base: list[int], smap: SeedMap) -> int:
    def f(q: int) -> int:
        c = base[q] & MASK32
        return ((c - seed_low) if q & 1 else (c + seed_low)) & MASK32

    return f(smap.q1) ^ f(smap.q2)


def map_g_array(seeds: np.ndarray, base: list[int], smap: SeedMap) -> np.ndarray:
    """Vectorized G(s) for millions of remaining 32-bit candidates."""
    s = seeds.astype(np.uint64, copy=False)

    def f(q: int) -> np.ndarray:
        c = np.uint64(base[q] & MASK32)
        value = c - s if q & 1 else c + s
        return (value & np.uint64(MASK32)).astype(np.uint32)

    return np.bitwise_xor(f(smap.q1), f(smap.q2))


def _map_paths(smap: SeedMap, target_g: int | None) -> tuple[list[tuple[int, int]], int, list[int]]:
    """Walk the carry automaton for x^(x+D) or x^(T-x).

    With no target, returns one (g,x) representative per image value. With a
    target, returns the fixed x bits and the free-bit positions describing its
    complete preimage bucket.
    """
    p = smap.parameter
    sub = smap.subtract_map
    representatives: list[tuple[int, int]] = []
    fixed_result = 0
    free_result: list[int] = []

    if target_g is not None:
        carry = 1 if sub else 0
        fixed = 0
        free: list[int] = []
        for i in range(32):
            pb = (p >> i) & 1
            expected_g = pb ^ carry ^ int(sub)
            if ((target_g >> i) & 1) != expected_g:
                raise ValueError("value is not in the map image")
            if i == 31:
                free.append(i)  # the discarded final carry leaves x[31] free
                continue
            if pb == carry:
                free.append(i)
                carry = pb
            else:
                next_pb = (p >> (i + 1)) & 1
                next_gb = (target_g >> (i + 1)) & 1
                next_carry = next_pb ^ next_gb ^ int(sub)
                xbit = (1 - next_carry) if sub else next_carry
                fixed |= xbit << i
                carry = next_carry
        return [], fixed, free


    def rec(i: int, carry: int, x: int, g: int) -> None:
        if i == 32:
            representatives.append((g, x))
            return
        pb = (p >> i) & 1
        gb = pb ^ carry ^ int(sub)
        g |= gb << i
        if i == 31:
            # Both final x choices differ only in the discarded carry; choose 0.
            rec(i + 1, 0, x, g)
        elif pb == carry:
            # The next carry is fixed and x[i] is free; choose x[i]=0.
            rec(i + 1, pb, x, g)
        else:
            # Addition has carry'=x; T-x has carry'=1-x.
            rec(i + 1, 0, x | (int(sub) << i), g)
            rec(i + 1, 1, x | ((1 - int(sub)) << i), g)

    rec(0, 1 if sub else 0, 0, 0)
    return representatives, fixed_result, free_result


def image_representatives(base: list[int], smap: SeedMap) -> np.ndarray:
    paths, _, _ = _map_paths(smap, None)
    a = base[smap.q1] & MASK32
    vals = [((a - x) if smap.q1 & 1 else (x - a)) & MASK32 for _, x in paths]
    return np.asarray(vals, dtype=np.uint32)


def map_image_size(smap: SeedMap) -> int:
    """Count image paths without allocating their representatives."""
    p, sub = smap.parameter, smap.subtract_map
    states = {(1 if sub else 0): 1}
    for i in range(31):  # bit 31's carry-out branches merge
        new: dict[int, int] = {}
        pb = (p >> i) & 1
        for carry, count in states.items():
            if pb == carry:
                new[pb] = new.get(pb, 0) + count
            else:
                new[0] = new.get(0, 0) + count
                new[1] = new.get(1, 0) + count
        states = new
    # Counts retain multiplicity when paths converge to the same current carry;
    # their earlier carry (and therefore g) histories remain distinct.
    return sum(states.values())


def map_bucket(target_g: int, base: list[int], smap: SeedMap) -> np.ndarray:
    _, fixed, free = _map_paths(smap, target_g)
    values = np.asarray([fixed], dtype=np.uint32)
    for bit in free:
        values = np.concatenate((values, values | np.uint32(1 << bit)))
    a = np.uint32(base[smap.q1] & MASK32)
    if smap.q1 & 1:
        return (a - values).astype(np.uint32)
    return (values - a).astype(np.uint32)


def anchor_pair(candidate_low: int, base: list[int], smap: SeedMap, bit: int) -> tuple[bytes, bytes]:
    """Collision iff G(candidate)==G(actual) (when two sign bits agree)."""
    a = bytearray(EQUALITY_LEN)
    b = bytearray(EQUALITY_LEN)
    k1 = aligned_secret_word(base, smap.q1, candidate_low) & MASK32
    k2 = aligned_secret_word(base, smap.q2, candidate_low) & MASK32
    toggle = 1 << bit
    off1 = smap.stripe1 * 64 + smap.lane * 8
    off2 = smap.stripe2 * 64 + smap.lane * 8
    a[off1 : off1 + 8] = wle64(k1)
    b[off1 : off1 + 8] = wle64(k1 | (toggle << 32))
    a[off2 : off2 + 8] = wle64(k2 | (toggle << 32))
    b[off2 : off2 + 8] = wle64(k2)
    return bytes(a), bytes(b)


def exact_low_pair(
    candidate_low: int, base: list[int], lane: int = 0
) -> tuple[bytes, bytes]:
    """A multiply-by-zero collision that validates all 32 low seed bits."""
    a = bytearray(EQUALITY_LEN)
    b = bytearray(EQUALITY_LEN)
    # Same lane in safe stripes 0 and 1; their raw-word changes sum to 2^64.
    k0 = aligned_secret_word(base, lane, candidate_low) & MASK32
    k1 = aligned_secret_word(base, lane + 1, candidate_low) & MASK32
    off0, off1 = lane * 8, 64 + lane * 8
    a[off0 : off0 + 8] = wle64(k0)
    b[off0 : off0 + 8] = wle64(k0 | (1 << 32))
    a[off1 : off1 + 8] = wle64(k1)
    b[off1 : off1 + 8] = wle64(k1 | (MASK32 << 32))
    return bytes(a), bytes(b)


def high_seed_bases(base: list[int], seed_low: int) -> list[int]:
    """32-bit affine bases for the high halves after the low-half carry/borrow."""
    out = []
    for q, c in enumerate(base):
        clo, chi = c & MASK32, c >> 32
        if q & 1:
            borrow = int(clo < seed_low)
            out.append((chi - borrow) & MASK32)
        else:
            carry = int(clo + seed_low > MASK32)
            out.append((chi + carry) & MASK32)
    return out


def anchor_high_pair(
    candidate_high: int,
    high_base: list[int],
    smap: SeedMap,
    bit: int,
) -> tuple[bytes, bytes]:
    """High-half version of anchor_pair; the toggles are in the low factor."""
    a = bytearray(EQUALITY_LEN)
    b = bytearray(EQUALITY_LEN)
    k1 = aligned_secret_word(high_base, smap.q1, candidate_high) & MASK32
    k2 = aligned_secret_word(high_base, smap.q2, candidate_high) & MASK32
    toggle = 1 << bit
    off1 = smap.stripe1 * 64 + smap.lane * 8
    off2 = smap.stripe2 * 64 + smap.lane * 8
    a[off1 : off1 + 8] = wle64(k1 << 32)
    b[off1 : off1 + 8] = wle64((k1 << 32) | toggle)
    a[off2 : off2 + 8] = wle64((k2 << 32) | toggle)
    b[off2 : off2 + 8] = wle64(k2 << 32)
    return bytes(a), bytes(b)


def exact_high_pair(candidate_high: int, high_base: list[int]) -> tuple[bytes, bytes]:
    """Validate all 32 high seed bits by zeroing the other product factor."""
    a = bytearray(EQUALITY_LEN)
    b = bytearray(EQUALITY_LEN)
    k0 = aligned_secret_word(high_base, 0, candidate_high) & MASK32
    k1 = aligned_secret_word(high_base, 1, candidate_high) & MASK32
    a[0:8] = wle64(k0 << 32)
    b[0:8] = wle64((k0 << 32) | 1)
    a[64:72] = wle64((k1 << 32) | 1)
    b[64:72] = wle64(k1 << 32)
    return bytes(a), bytes(b)


def _first_positive(
    oracle: EqualityOracle,
    candidates: np.ndarray,
    make_pair: Callable[[int], tuple[bytes, bytes]],
    batch_size: int = 4096,
) -> int | None:
    for start in range(0, len(candidates), batch_size):
        chunk = candidates[start : start + batch_size]
        pairs = [make_pair(int(x)) for x in chunk]
        bits = oracle.equal_batch(pairs)
        for x, yes in zip(chunk, bits):
            if yes:
                return int(x)
    return None


def identify_map_bucket(
    oracle: EqualityOracle,
    representatives: np.ndarray,
    base: list[int],
    smap: SeedMap,
) -> tuple[int, int]:
    """Find the target G bucket, trying high-factor toggle bits until signs agree."""
    for bit in range(32):
        hit = _first_positive(
            oracle,
            representatives,
            lambda c, bit=bit: anchor_pair(c, base, smap, bit),
        )
        if hit is not None:
            return map_g_scalar(hit, base, smap), bit
    raise RuntimeError("pathological complement secret halves; choose another map")


def recover_seed_low(oracle: EqualityOracle, delta_words: list[int], verbose: bool = True) -> int:
    """Recover seed mod 2^32 using adaptive XXH3 collision classes."""
    base = secret_bases(delta_words)
    maps = available_seed_maps(base)

    # Start with the coarsest carry map, querying one representative per bucket.
    sizes = [(map_image_size(m), m) for m in maps]
    _, smap = min(sizes, key=lambda item: item[0])
    used = {smap}
    reps = image_representatives(base, smap)
    if verbose:
        print(f"[*] seed map {smap.q1},{smap.q2}: {len(reps)} representatives")
    target_g, toggle = identify_map_bucket(oracle, reps, base, smap)
    candidates = map_bucket(target_g, base, smap)
    if verbose:
        print(f"[+] first seed bucket via bit {toggle}: {len(candidates)} candidates")

    # Intersect with other coarse carry maps. Their restrictions to the current
    # bucket generally have only tens/hundreds of distinct values.
    while len(candidates) > 2048:
        sample_step = max(1, len(candidates) // 100_000)
        sample = candidates[::sample_step][:100_000]
        ranked: list[tuple[int, SeedMap]] = []
        for other in maps:
            if other in used:
                continue
            ng = len(np.unique(map_g_array(sample, base, other)))
            if ng > 1:
                ranked.append((ng, other))
        if not ranked:
            break
        ranked.sort(key=lambda item: item[0])

        chosen = None
        for _, other in ranked[:5]:
            gvals = map_g_array(candidates, base, other)
            unique, first = np.unique(gvals, return_index=True)
            if len(unique) > 1:
                chosen = (other, gvals, candidates[first])
                break
            used.add(other)
        if chosen is None:
            break
        other, gvals, group_reps = chosen
        # Exact testing costs half the candidate set on average. Do not use a
        # weak partition whose representative scan is likely more expensive.
        if len(group_reps) * 3 >= len(candidates):
            break
        used.add(other)
        before = len(candidates)
        target_g, toggle = identify_map_bucket(oracle, group_reps, base, other)
        candidates = candidates[gvals == np.uint32(target_g)]
        if verbose:
            print(
                f"[+] intersect map {other.q1},{other.q2}/bit {toggle}: "
                f"{before} -> {len(candidates)}"
            )

    # Random order makes the expected exact-validation cost N/2.
    np.random.default_rng().shuffle(candidates)
    hit = None
    remaining = candidates
    while len(remaining):
        proposal = _first_positive(
            oracle, remaining, lambda c: exact_low_pair(c, base, 0)
        )
        if proposal is None:
            break
        confirmations = oracle.equal_batch(
            [exact_low_pair(proposal, base, lane) for lane in (1, 3, 5)]
        )
        if all(confirmations):
            hit = proposal
            break
        remaining = remaining[remaining != np.uint32(proposal)]
    if hit is None:
        raise RuntimeError("no low seed candidate survived exact collision tests")
    if verbose:
        print(f"[+] seed low32 = {hit:08x} ({oracle.queries} equality pairs)")
    return hit


def _equal_low_factor_bit(base: list[int], seed_low: int, smap: SeedMap) -> int | None:
    k1 = aligned_secret_word(base, smap.q1, seed_low) & MASK32
    k2 = aligned_secret_word(base, smap.q2, seed_low) & MASK32
    diff = k1 ^ k2
    for bit in range(32):
        if not ((diff >> bit) & 1):
            return bit
    return None


def recover_seed_high(
    oracle: EqualityOracle,
    delta_words: list[int],
    seed_low: int,
    unlocked_digest: bytes | None = None,
    verbose: bool = True,
) -> int:
    """Recover the upper seed half; known low bits remove the sign ambiguity."""
    full_base = secret_bases(delta_words)
    high_base = high_seed_bases(full_base, seed_low)
    maps = [
        m
        for m in available_seed_maps(high_base)
        if _equal_low_factor_bit(full_base, seed_low, m) is not None
    ]
    if not maps:
        raise RuntimeError("no usable high-half carry map")

    _, smap = min(
        ((map_image_size(m), m) for m in maps), key=lambda item: item[0]
    )
    used = {smap}
    candidates = image_representatives(high_base, smap)
    toggle = _equal_low_factor_bit(full_base, seed_low, smap)
    assert toggle is not None
    if verbose:
        print(
            f"[*] high seed map {smap.q1},{smap.q2}: "
            f"{len(candidates)} representatives"
        )
    hit = _first_positive(
        oracle,
        candidates,
        lambda c: anchor_high_pair(c, high_base, smap, toggle),
    )
    if hit is None:
        raise RuntimeError("high seed target bucket was not found")
    target_g = map_g_scalar(hit, high_base, smap)
    candidates = map_bucket(target_g, high_base, smap)
    if verbose:
        print(f"[+] first high seed bucket via bit {toggle}: {len(candidates)} candidates")

    while len(candidates) > 2048:
        sample_step = max(1, len(candidates) // 100_000)
        sample = candidates[::sample_step][:100_000]
        ranked: list[tuple[int, SeedMap]] = []
        for other in maps:
            if other in used:
                continue
            ng = len(np.unique(map_g_array(sample, high_base, other)))
            if ng > 1:
                ranked.append((ng, other))
        if not ranked:
            break
        ranked.sort(key=lambda item: item[0])
        chosen = None
        for _, other in ranked[:5]:
            gvals = map_g_array(candidates, high_base, other)
            unique, first = np.unique(gvals, return_index=True)
            if len(unique) > 1:
                chosen = (other, gvals, candidates[first])
                break
            used.add(other)
        if chosen is None:
            break
        other, gvals, group_reps = chosen
        if len(group_reps) * 3 >= len(candidates):
            break
        used.add(other)
        toggle = _equal_low_factor_bit(full_base, seed_low, other)
        assert toggle is not None
        before = len(candidates)
        hit = _first_positive(
            oracle,
            group_reps,
            lambda c: anchor_high_pair(c, high_base, other, toggle),
        )
        if hit is None:
            raise RuntimeError("high seed intersection bucket was not found")
        target_g = map_g_scalar(hit, high_base, other)
        candidates = candidates[gvals == np.uint32(target_g)]
        if verbose:
            print(
                f"[+] intersect high map {other.q1},{other.q2}/bit {toggle}: "
                f"{before} -> {len(candidates)}"
            )

    np.random.default_rng().shuffle(candidates)
    if unlocked_digest is not None:
        hit = next(
            (
                int(c)
                for c in candidates
                if custom_xxh3_128(
                    bytes(EQUALITY_LEN), (int(c) << 32) | seed_low, delta_words
                )
                == unlocked_digest
            ),
            None,
        )
    else:
        # This collision is only a coarse final filter for some +/- seed
        # constants. Callers should normally pass the unlocked zero digest.
        hit = _first_positive(
            oracle,
            candidates,
            lambda c: exact_high_pair(c, high_base),
        )
    if hit is None:
        raise RuntimeError("no high seed candidate survived exact collision test")
    if verbose:
        print(f"[+] seed high32 = {hit:08x} ({oracle.queries} total equality pairs)")
    return hit


# ---------------------------------------------------------------------------
# 1024-byte XXH3 target preimage
# ---------------------------------------------------------------------------


def undo_xor_right(value: int, shift: int, bits: int = 64) -> int:
    x = value
    s = shift
    while s < bits:
        x ^= x >> s
        s *= 2
    return x & ((1 << bits) - 1)


def unavalanche(value: int) -> int:
    x = undo_xor_right(value, 32)
    x = (x * pow(PRIME_MX1, -1, 1 << 64)) & MASK
    return undo_xor_right(x, 37)


def remote_fold_claw(c0: int, c1: int, target: int) -> tuple[int, int]:
    """Run the ~2^32 Pollard claw search on remote's GPU."""
    here = os.path.dirname(os.path.abspath(__file__))
    source = os.path.join(here, "fold_claw.cu")
    remote_source = "/tmp/hashbrown_fold_claw.cu"
    remote_binary = "/tmp/hashbrown_fold_claw"
    subprocess.run(["scp", "-q", source, f"remote:{remote_source}"], check=True)
    compile_command = (
        f"test -x {remote_binary} && "
        f"test {remote_binary} -nt {remote_source} || "
        f"/usr/local/cuda/bin/nvcc -O3 -arch=sm_61 {remote_source} -o {remote_binary}"
    )
    subprocess.run(["ssh", "remote", compile_command], check=True)
    proc = subprocess.Popen(
        [
            "ssh",
            "remote",
            remote_binary,
            f"{c0:016x}",
            f"{c1:016x}",
            f"{target:016x}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    transcript = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(f"[gpu] {line}", end="", flush=True)
        transcript.append(line)
    status = proc.wait()
    output = "".join(transcript)
    if status:
        raise RuntimeError(f"fold-claw process exited {status}: {output!r}")
    match = re.search(r"(?m)^([0-9a-f]{16}) ([0-9a-f]{16})$", output)
    if not match:
        match = re.search(
            r"(?m)^CLAW x=([0-9a-f]{16}) y=([0-9a-f]{16})(?:\s|$)", output
        )
    if not match:
        raise RuntimeError(f"invalid fold-claw output: {output!r}")
    z0, z1 = (int(match.group(i), 16) for i in (1, 2))
    if (fold64(c0, z0) + fold64(c1, z1)) & MASK != target:
        raise RuntimeError("GPU claw result did not verify")
    return z0, z1


def forge_accumulator(
    sha_key: bytes,
    seed: int,
    delta_words: list[int],
    claw_solver: Callable[[int, int, int], tuple[int, int]] = remote_fold_claw,
) -> list[int]:
    """Find an accumulator whose merge is the challenge's target digest.

    Pairs 0/1 have their high merge product zeroed and solve a 64-bit low
    two-sum. Pairs 2/3 analogously solve the high two-sum. Each generic two-sum
    is a 2^32 claw, handled by the small distinguished-point GPU helper.
    """
    sec = custom_secret2(seed, delta_words)
    A = [rle64(sec, 11 + 16 * i) for i in range(4)]
    B = [rle64(sec, 19 + 16 * i) for i in range(4)]
    C = [rle64(sec, 117 + 16 * i) for i in range(4)]
    D = [rle64(sec, 125 + 16 * i) for i in range(4)]

    wanted = target_digest(sha_key, seed)
    pre_high = unavalanche(int.from_bytes(wanted[:8], "big"))
    pre_low = unavalanche(int.from_bytes(wanted[8:], "big"))
    need_low = (pre_low - FORGE_LEN * P64_1) & MASK
    need_high = (pre_high - (~(FORGE_LEN * P64_2) & MASK)) & MASK

    print("[*] GPU fold-claw 1/2: low merge", flush=True)
    z0, z1 = claw_solver(C[0] ^ A[0], C[1] ^ A[1], need_low)
    print("[+] GPU fold-claw 1/2 solved and verified", flush=True)
    print("[*] GPU fold-claw 2/2: high merge", flush=True)
    z2, z3 = claw_solver(A[2] ^ C[2], A[3] ^ C[3], need_high)
    print("[+] GPU fold-claw 2/2 solved and verified", flush=True)
    acc = [
        C[0], B[0] ^ z0,
        C[1], B[1] ^ z1,
        A[2], D[2] ^ z2,
        A[3], D[3] ^ z3,
    ]
    if digest_from_acc(acc, seed, FORGE_LEN, delta_words) != wanted:
        raise RuntimeError("constructed target accumulator did not verify")
    return acc


def payload_for_accumulator(
    wanted_acc: list[int], seed: int, delta_words: list[int]
) -> bytes:
    """Realize any eight-word accumulator with a 1024-byte payload.

    Every input word is chosen to share either its low or high 32 bits with its
    secret word, making p32prod zero. Two words per lane then freely set the
    modular sum of raw words entering the paired accumulator lane.
    """
    if len(wanted_acc) != 8:
        raise ValueError("wanted_acc must have eight words")
    sec = custom_secret2(seed, delta_words)
    payload = bytearray(FORGE_LEN)

    for lane in range(8):
        keys = [rle64(sec, 8 * stripe + 8 * lane) for stripe in range(15)]
        keys.append(rle64(sec, 121 + 8 * lane))
        values = keys[:]
        wanted_sum = (wanted_acc[lane ^ 1] - INIT_ACC[lane ^ 1]) & MASK

        # Word 0 keeps secret.low (free high); word 1 keeps secret.high
        # (free low). The other fourteen words equal their secret exactly.
        fixed = sum(keys[2:]) & MASK
        k0, k1 = keys[0], keys[1]
        v = (
            wanted_sum
            - fixed
            - (k0 & MASK32)
            - ((k1 >> 32) << 32)
        ) & MASK32
        values[1] = ((k1 >> 32) << 32) | v
        partial = (fixed + (k0 & MASK32) + values[1]) & MASK
        high_delta = (wanted_sum - partial) & MASK
        if high_delta & MASK32:
            raise AssertionError("raw-sum construction lost low-word alignment")
        values[0] = high_delta | (k0 & MASK32)
        if sum(values) & MASK != wanted_sum:
            raise AssertionError("raw-sum construction failed")

        for stripe, value in enumerate(values):
            off = stripe * 64 + lane * 8 if stripe < 15 else 960 + lane * 8
            payload[off : off + 8] = wle64(value)

    result = bytes(payload)
    if acc_for_1024_payload(result, seed, delta_words) != [x & MASK for x in wanted_acc]:
        raise RuntimeError("payload did not realize requested accumulator")
    return result


def forge_payload(
    sha_key: bytes,
    seed: int,
    delta_words: list[int],
    claw_solver: Callable[[int, int, int], tuple[int, int]] = remote_fold_claw,
) -> bytes:
    acc = forge_accumulator(sha_key, seed, delta_words, claw_solver)
    payload = payload_for_accumulator(acc, seed, delta_words)
    if custom_xxh3_128(payload, seed, delta_words) != target_digest(sha_key, seed):
        raise RuntimeError("final forged payload did not verify")
    return payload


# ---------------------------------------------------------------------------
# Menu protocol and end-to-end driver
# ---------------------------------------------------------------------------


class MenuClient:
    """Pipelined wrapper around the challenge's line-oriented menu."""

    def __init__(self, tube, wire_batch: int = 512):
        self.tube = tube
        self.wire_batch = wire_batch
        self.queries = 0
        self.tube.recvuntil(b"> ")

    def _sync_menu(self) -> None:
        self.tube.recvuntil(b"> ")

    def fault_digest(self, name: str) -> bytes:
        self.tube.send(b"1\n" + name.encode() + b"\n")
        self.tube.recvuntil(b"[+] digest: ")
        value = bytes.fromhex(self.tube.recvline().strip().decode())
        self._sync_menu()
        return value

    def unlock(self, token: str) -> bytes:
        self.tube.send(b"3\n" + token.encode() + b"\n")
        self.tube.recvuntil(b"[+] digest: ")
        value = bytes.fromhex(self.tube.recvline().strip().decode())
        self._sync_menu()
        return value

    def _wire_equal_batch(self, pairs: list[tuple[bytes, bytes]]) -> list[bool]:
        lines = [b"2", str(len(pairs)).encode()]
        for a, b in pairs:
            lines.extend((a.hex().encode(), b.hex().encode()))
        self.tube.send(b"\n".join(lines) + b"\n")
        self.tube.recvuntil(b"[+] bits: ")
        bits = self.tube.recvline().strip()
        if len(bits) != len(pairs) or any(c not in b"01" for c in bits):
            raise RuntimeError(f"malformed equality response: {bits!r}")
        self._sync_menu()
        return [c == ord("1") for c in bits]

    def equal_batch(self, pairs: list[tuple[bytes, bytes]]) -> list[bool]:
        result: list[bool] = []
        for start in range(0, len(pairs), self.wire_batch):
            chunk = pairs[start : start + self.wire_batch]
            result.extend(self._wire_equal_batch(chunk))
        self.queries += len(pairs)
        return result

    def submit(self, payload: bytes) -> str:
        self.tube.send(b"4\n" + payload.hex().encode() + b"\n")
        data = self.tube.recvuntil(b"\n", timeout=30)
        text = data.decode(errors="replace").strip()
        if "[+] " not in text:
            # Grab any remaining diagnostic (normally "[-] nope").
            text += self.tube.recvrepeat(0.5).decode(errors="replace")
            raise RuntimeError(f"flag submission failed: {text!r}")
        return text.split("[+] ", 1)[1]


def solve_tube(tube, verbose: bool = True) -> str:
    from xxh3_custom import delta_words_from_key, unlock_token

    client = MenuClient(tube)
    if verbose:
        print("[*] requesting r24 and thr35 SHA faults")
    r24 = client.fault_digest("r24")
    thr35 = client.fault_digest("thr35")
    sha_key = recover_sha_key(r24, thr35)
    if verbose:
        print(f"[+] SHA key = {sha_key.hex()}")

    delta_words = delta_words_from_key(sha_key)
    unlocked = client.unlock(unlock_token(sha_key))
    if verbose:
        print(f"[+] unlocked zero digest = {unlocked.hex()}")

    low = recover_seed_low(client, delta_words, verbose)
    high = recover_seed_high(client, delta_words, low, unlocked, verbose)
    seed = (high << 32) | low
    if custom_xxh3_128(bytes(EQUALITY_LEN), seed, delta_words) != unlocked:
        raise RuntimeError("recovered seed does not match unlocked digest")
    if verbose:
        print(f"[+] full seed = {seed:016x}")
        print("[*] solving two fold claws and realizing target accumulator")

    payload = forge_payload(sha_key, seed, delta_words)
    if verbose:
        print(f"[+] forged {len(payload)}-byte payload")
    flag = client.submit(payload)
    if verbose:
        print(f"[+] flag: {flag}")
    return flag


def main() -> None:
    import argparse
    from pwn import context, process, remote

    parser = argparse.ArgumentParser(description="End-to-end Hashbrown solver")
    parser.add_argument("--remote", action="store_true", help="attack the official TLS endpoint")
    parser.add_argument("--host", default="CHALLENGE_HOST")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--seed", type=lambda x: int(x, 0), default=0x4224C4B07D84D037)
    args = parser.parse_args()
    context.log_level = "error"

    if args.remote:
        tube = remote(args.host, args.port, ssl=True, sni=args.host, timeout=900)
    else:
        suffix = bytes(range(31))
        env = dict(os.environ)
        env.update(
            {
                "HASHBROWN_KEY_SUFFIX_HEX": suffix.hex(),
                "HASHBROWN_SEED_HEX": args.seed.to_bytes(8, "little").hex(),
                "FLAG": "pwnsec{hashbrown_local_self_test}",
            }
        )
        tube = process([sys.executable, "main.py", "--stdio"], env=env)
    try:
        solve_tube(tube)
    finally:
        tube.close()


def _self_test_sha() -> None:
    from sha256_faults import faulty_sha256_digest

    prefix = bytes.fromhex("5b0de77c5ad3bef911a29fb17c6634f48a1f91cae7ffde9f")
    for _ in range(10):
        key = prefix + random.randbytes(31)
        got = recover_sha_key(
            faulty_sha256_digest(key, "r24"),
            faulty_sha256_digest(key, "thr35"),
        )
        assert got == key, (got.hex(), key.hex())
    print("SHA recovery self-test passed")


if __name__ == "__main__":
    main()
