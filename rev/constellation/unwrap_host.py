#!/usr/bin/env python3
"""Unwrap Constellation's nested host archives.

Run this on remote, where decrypt_host.c has already materialized the outer
ZIP.  Large concatenation/XOR/FNV operations are delegated to blobtool.c.
"""
from __future__ import annotations

import argparse
import collections
import os
import struct
import subprocess
import sys
import zipfile

U32 = 0xFFFFFFFF


def u32(b: bytes | bytearray, off: int = 0) -> int:
    return struct.unpack_from("<I", b, off)[0]


def fnv1a32(b: bytes | bytearray) -> int:
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x1000193) & U32
    return h


def decrypt_jkm1(raw: bytes):
    """Parse the small dependency ticket consumed by sub_14002e310."""
    if len(raw) < 12:
        return None
    seed_word, n, outer_check = struct.unpack_from("<III", raw)
    if n + 12 != len(raw):
        return None
    seed = seed_word ^ n
    body = raw[12:]
    if (fnv1a32(body) ^ seed ^ 0xA93F5C71) & U32 != outer_check:
        return None
    out = bytearray(body)
    state = seed ^ 0xA2929CAF
    for i in range(n):
        state = (state * 0x19660D + 0x3C6EF35F + i * 0x45D9F3B) & U32
        out[i] ^= (state >> ((i & 3) * 8)) & 0xFF
        out[i] ^= (i * 0x5B + 0x6D) & 0xFF
    if len(out) < 18 or out[:4] != b"JKM1":
        return None
    key, wanted_hash, name_check = struct.unpack_from("<III", out, 4)
    slen = struct.unpack_from("<H", out, 16)[0]
    if not slen or 18 + slen > len(out):
        return None
    name = bytes(out[18 : 18 + slen]).decode("ascii")
    if fnv1a32(name.encode()) != (name_check ^ wanted_hash ^ key ^ 0x7A11C0DE) & U32:
        return None
    return name, key, wanted_hash


def jsc_xor(raw: bytes | bytearray, key: int) -> bytearray:
    out = bytearray(raw)
    for i in range(len(out)):
        out[i] ^= (key >> ((i & 3) * 8)) & 0xFF
        out[i] ^= (i * 0x49 + 0x3D) & 0xFF
        out[i] ^= (i * 0x11 - 0x5B) & 0xFF
    return out


def parse_jsc2(raw: bytes, descriptor_key: int):
    """Decrypt and parse the chunk assembly descriptor in sub_14002d7c0."""
    d = jsc_xor(raw, descriptor_key)
    if len(d) < 20 or d[:4] != b"JSC2":
        raise ValueError("dependency did not decrypt to JSC2")
    output_key, total, output_check, count = struct.unpack_from("<IIII", d, 4)
    if not 1 <= count <= 4096:
        raise ValueError(f"bad JSC2 chunk count {count}")
    refs = []
    pos = 20
    for index in range(count):
        if pos + 2 > len(d):
            raise ValueError("truncated JSC2 name length")
        n = struct.unpack_from("<H", d, pos)[0]
        pos += 2
        if not n or pos + n + 8 > len(d):
            raise ValueError("truncated JSC2 reference")
        name = bytes(d[pos : pos + n]).decode("ascii")
        pos += n
        expected_size, expected_check = struct.unpack_from("<II", d, pos)
        pos += 8
        refs.append((name, expected_size, expected_check, index))
    if pos != len(d):
        raise ValueError(f"JSC2 trailing bytes: parsed {pos}, size {len(d)}")
    return output_key, total, output_check, refs


def blobtool_value(blobtool: str, command: str, path: str, key: int | None = None) -> int:
    argv = [blobtool, command, path]
    if key is not None:
        argv.append(hex(key))
    out = subprocess.check_output(argv, text=True).strip()
    return int(out, 16) if out else 0


def read_ticket_candidates(z: zipfile.ZipFile):
    candidates = []
    names = set(z.namelist())
    for zi in z.infolist():
        # Tickets are tiny; read the fixed outer header before committing to a
        # full extraction.  This avoids touching hundreds of MB of chunks.
        if zi.file_size < 12:
            continue
        with z.open(zi) as f:
            head = f.read(12)
            if len(head) != 12 or u32(head, 4) + 12 != zi.file_size:
                continue
            raw = head + f.read()
        parsed = decrypt_jkm1(raw)
        if parsed and parsed[0] in names:
            candidates.append((zi.filename, *parsed))
    return candidates


def unwrap_layer(src: str, dst: str, blobtool: str, check_chunks: bool) -> None:
    with zipfile.ZipFile(src) as z:
        candidates = read_ticket_candidates(z)
        groups = collections.Counter((dep, key, wanted) for _, dep, key, wanted in candidates)
        if not groups:
            raise ValueError("no valid JKM1 dependency ticket group")
        (dependency, descriptor_key, wanted_hash), copies = groups.most_common(1)[0]
        dep_raw = z.read(dependency)
        got_wanted = fnv1a32(dep_raw) ^ descriptor_key ^ 0xD00DFEED
        if got_wanted != wanted_hash:
            raise ValueError(
                f"dependency hash mismatch: got {got_wanted:08x}, expected {wanted_hash:08x}"
            )
        output_key, total, output_check, refs = parse_jsc2(dep_raw, descriptor_key)
        print(
            f"  tickets={len(candidates)} selected_copies={copies} dependency={dependency}\n"
            f"  descriptor_key={descriptor_key:08x} output_key={output_key:08x} "
            f"chunks={len(refs)} total={total} check={output_check:08x}",
            flush=True,
        )
        tmp = dst + ".assembled"
        written = 0
        with open(tmp, "wb") as out:
            for name, expected_size, expected_check, index in refs:
                raw = z.read(name)  # zipfile also validates each ZIP CRC.
                if len(raw) != expected_size:
                    raise ValueError(f"chunk {index} size mismatch for {name}")
                if check_chunks:
                    got = fnv1a32(raw) ^ index ^ output_key ^ 0x8EE03E33
                    if got != expected_check:
                        raise ValueError(
                            f"chunk {index} check mismatch: {got:08x} != {expected_check:08x}"
                        )
                out.write(raw)
                written += len(raw)
        if written != total:
            raise ValueError(f"assembled size {written} != descriptor size {total}")
    got = blobtool_value(blobtool, "fnv", tmp)
    if (got ^ output_key ^ 0xD00DFEED) & U32 != output_check:
        raise ValueError(
            f"assembled check mismatch: fnv={got:08x}, key={output_key:08x}, "
            f"expected={output_check:08x}"
        )
    blobtool_value(blobtool, "xor", tmp, output_key)
    os.replace(tmp, dst)
    with open(dst, "rb") as f:
        magic = f.read(4)
    print(f"  wrote {dst} ({written} bytes), magic={magic!r}", flush=True)
    if magic != b"PK\x03\x04":
        raise ValueError("unwrapped layer is not a ZIP")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("outdir")
    ap.add_argument("--blobtool", default="/tmp/blobtool")
    ap.add_argument("--layers", type=int, default=8)
    ap.add_argument("--check-chunks", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    src = os.path.abspath(args.source)
    for layer in range(1, args.layers + 1):
        dst = os.path.join(os.path.abspath(args.outdir), f"layer{layer}.zip")
        print(f"layer {layer}: {src} -> {dst}", flush=True)
        unwrap_layer(src, dst, args.blobtool, args.check_chunks)
        src = dst


if __name__ == "__main__":
    main()
