#!/usr/bin/env python3
"""Decode the initialized ICX physical-word hash table from anon_init.bin.

The file is the 0x2401000-byte anonymous mapping captured at the pre-run
breakpoint.  Its main hashbrown table has 0x400000 buckets, 8-byte entries
stored backwards before its control-byte array, and global memory phase 0x59.
"""
from pathlib import Path
import argparse, struct

MAP_BASE = 0x7fffe311b000
CTRL_VA = 0x7fffe511b1c0
CTRL = CTRL_VA - MAP_BASE
CAP = 0x400000
PHASE = 0x59
PERMS = ((0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0))

def perm_index(addr, phase=PHASE):
    x = (phase ^ addr ^ (addr >> 8) ^ (addr >> 16) ^ 0xa7) & 0xff
    x = ((x << 3) & 0xff) ^ x
    x ^= x >> 5
    x = (((x << 1) & 0xff) ^ x) & 0xff
    # Compiler's multiply-by-0xab sequence is exact division remainder by 6.
    return x % 6

def decode_raw(addr, raw, phase=PHASE, verify=True):
    rb = raw.to_bytes(3, 'little')
    out = bytearray(3)
    p = PERMS[perm_index(addr, phase)]
    for src, dst in enumerate(p):
        out[dst] = rb[src]
    packed = int.from_bytes(out, 'little')
    word = packed & 0x7fffff
    parity = packed >> 23
    expected = (word.bit_count() ^ addr ^ (addr >> 7) ^ (addr >> 15) ^ phase) & 1
    if verify and parity != expected:
        raise ValueError(f'parity error at {addr:#x}: raw {raw:#x}, got {parity}, expected {expected}')
    return word

def load_phases(path):
    b=Path(path).read_bytes()
    base=0x7ffff7ff0000; ctrl=0x7ffff7ff1970-base; cap=0x100
    phases={}
    for i,ctl in enumerate(memoryview(b)[ctrl:ctrl+cap]):
        if ctl < 0x80:
            off=ctrl-(i+1)*4
            page=struct.unpack_from('<H',b,off)[0]
            phases[page]=b[off+2]
    if len(phases)!=0x94:
        raise ValueError(f'page phase count {len(phases):#x}, expected 0x94')
    return phases

def load_words(path, phase_path=None, expected=None):
    b = Path(path).read_bytes()
    if len(b) < CTRL + CAP:
        raise ValueError(f'dump too short: {len(b):#x}')
    phases=load_phases(phase_path) if phase_path else {}
    words = {}
    occupied = 0
    for i, ctl in enumerate(memoryview(b)[CTRL:CTRL+CAP]):
        if ctl < 0x80:
            occupied += 1
            off = CTRL - (i + 1) * 8
            addr, raw = struct.unpack_from('<II', b, off)
            if addr >= 0x800000:
                raise ValueError(f'bad address {addr:#x} in bucket {i:#x}')
            raw &= 0xffffff
            words[addr] = decode_raw(addr, raw, PHASE ^ phases.get(addr >> 8, 0))
    if expected is not None and occupied != expected:
        raise ValueError(f'entry count mismatch occupied={occupied:#x}, expected={expected:#x}')
    if len(words) != occupied:
        raise ValueError(f'duplicate address: occupied={occupied:#x}, unique={len(words):#x}')
    return words

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('dump', nargs='?', default='anon_init.bin')
    ap.add_argument('--phases', help='auxiliary mapping holding per-page phase map')
    ap.add_argument('--expected', type=lambda x:int(x,0))
    ap.add_argument('--start', type=lambda x:int(x,0), default=0x600)
    ap.add_argument('--count', type=lambda x:int(x,0), default=0x100)
    ap.add_argument('--output', help='write flat 32-bit little-endian logical words for all 0x800000 addresses')
    args=ap.parse_args()
    words=load_words(args.dump,args.phases,args.expected)
    print(f'decoded {len(words):#x} initialized words')
    for a in range(args.start,args.start+args.count):
        print(f'{a:06x}: {words.get(a,0):06x}')
    if args.output:
        out=bytearray(0x800000*4)
        for a,w in words.items(): struct.pack_into('<I',out,a*4,w)
        Path(args.output).write_bytes(out)
        print(f'wrote {args.output} ({len(out):#x} bytes)')
if __name__=='__main__': main()
