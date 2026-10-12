#!/usr/bin/env python3
"""Invert portal33.exe's overlapping x86/x86-64 input checks."""

import struct


MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def rol(value: int, count: int, bits: int) -> int:
    mask = (1 << bits) - 1
    count %= bits
    return ((value << count) | (value >> (bits - count))) & mask


def ror(value: int, count: int, bits: int) -> int:
    mask = (1 << bits) - 1
    count %= bits
    return ((value >> count) | (value << (bits - count))) & mask


def recover() -> bytes:
    # x86 view of 0x401600 checks five chained little-endian dwords.
    targets32 = [
        0xCDBD7302,
        0x30833D2E,
        0xB310EA05,
        0xDEF1B433,
        0x1C3B640E,
    ]
    previous = 0x1337C0DE
    answer = bytearray()
    for target in targets32:
        word = ror(target, 11, 32) ^ previous
        answer += struct.pack("<I", word)
        previous = target

    # x86-64 view jumps to 0x40165f and checks qwords at +0x14/+0x1c,
    # followed by the final dword at +0x24.
    target64_0 = 0x87326027C52B7005
    word64_0 = ror(target64_0, 19, 64) ^ 0x5A33C0D313379090
    answer += struct.pack("<Q", word64_0)

    target64_1 = 0x7E6E88ADD6EBC7E2
    word64_1 = ror(target64_1, 29, 64) ^ target64_0
    answer += struct.pack("<Q", word64_1)

    target32_2 = 0x5E929579
    word32_2 = ror(target32_2, 13, 32) ^ (target64_1 & MASK32)
    answer += struct.pack("<I", word32_2)
    return bytes(answer)


def verify(answer: bytes) -> None:
    assert len(answer) == 40

    values32 = struct.unpack("<5I", answer[:20])
    targets32 = [
        0xCDBD7302,
        0x30833D2E,
        0xB310EA05,
        0xDEF1B433,
        0x1C3B640E,
    ]
    previous = 0x1337C0DE
    for value, target in zip(values32, targets32):
        previous = rol(value ^ previous, 11, 32)
        assert previous == target

    qword0, qword1, dword2 = struct.unpack("<QQI", answer[20:])
    state0 = rol(qword0 ^ 0x5A33C0D313379090, 19, 64)
    assert state0 == 0x87326027C52B7005
    state1 = rol(qword1 ^ state0, 29, 64)
    assert state1 == 0x7E6E88ADD6EBC7E2
    state2 = rol(dword2 ^ (state1 & MASK32), 13, 32)
    assert state2 == 0x5E929579


if __name__ == "__main__":
    candidate = recover()
    verify(candidate)
    print(candidate.decode("ascii"))
