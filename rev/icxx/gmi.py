#!/usr/bin/env python3
"""ICXX GMI parser + disassembler with virtual-address mapping.

GMI = array of little-endian 23-bit words. Header (word indices):
 0 MAGIC 0x494D47   1 version   2..4 build-id   5 segcount   6 entry
 7 cap-mask? 8 ?   9 0x6FFB00 (stack top?)  10 checksum  11 0
 then segcount * 5-word descriptors: (fileoff, filelen, vaddr, memlen, flags)
"""
import sys, json
from icx_isa import mapping

MASK = 0x7FFFFF
MAGIC = 0x494D47
ISA_SEED = 0xb7d49c21e8a6305f     # system/GMI opcode-table seed (sibling-recovered)
M = mapping(ISA_SEED)

def read_words(path):
    raw = open(path, 'rb').read()
    return [int.from_bytes(raw[i:i+3], 'little') & MASK for i in range(0, len(raw)-2, 3)]

def hdr(words):
    return dict(magic=words[0], ver=words[1], build=tuple(words[2:5]),
               segcount=words[5], entry=words[6], w7=words[7], w8=words[8],
               w9=words[9], cksum=words[10], w11=words[11])

def segs(words):
    h = hdr(words); out=[]
    for i in range(h['segcount']):
        f,fl,v,m,fg = words[12+5*i:17+5*i]
        out.append(dict(fileoff=f, filelen=fl, vaddr=v, memlen=m, flags=fg))
    return out

class VMap:
    """Map virtual word address -> value using segment table (file-backed part)."""
    def __init__(self, words):
        self.words=words; self.S=segs(words); self.mem={}
        for s in self.S:
            for j in range(s['filelen']):
                self.mem[(s['vaddr']+j)&MASK] = words[s['fileoff']+j]
    def get(self, va):
        return self.mem.get(va & MASK)

def sx(x,n): return x-(1<<n) if x&(1<<(n-1)) else x

def dis_one(pc,w,nextw=None):
    op=(w>>16)&0x7f
    if op not in M: return f'.word 0x{w:06x}  ; badop {op:02x}'
    _,d=M[op]; n,f=d['name'],d['format']; a=(w>>12)&15;b=(w>>8)&15;c=(w>>4)&15
    if f=='N': args=''
    elif f=='R': args=f'r{a}'
    elif f=='RRR': args=f'r{a}, r{b}, r{c}'
    elif f=='RI12': args=f'r{a}, {sx(w&0xfff,12):#x}'
    elif f=='RRI8': args=f'r{a}, r{b}, {sx(w&0xff,8):#x}'
    elif f=='B16': args=f'{(pc+1+sx(w&0xffff,16))&MASK:#08x}'
    elif f=='X': args=f'r{a}, 0x{nextw:06x}' if nextw is not None else f'r{a}, ?'
    else: args='?'
    return f'{n.lower():9s} {args}'.rstrip()

def dis_va(vm, start, count):
    """Disassemble by virtual address (following X 2-word insns)."""
    pc=start; done=0
    while done<count:
        w=vm.get(pc)
        if w is None: print(f'{pc:06x}: <unmapped>'); break
        op=(w>>16)&0x7f; _,d=M.get(op,(None,{'format':''}))
        nextw=vm.get(pc+1) if d['format']=='X' else None
        print(f'{pc:06x}: {w:06x}  {dis_one(pc,w,nextw)}')
        pc += 2 if d['format']=='X' else 1
        done+=1

if __name__=='__main__':
    path=sys.argv[1]
    words=read_words(path)
    h=hdr(words)
    print('HEADER:', json.dumps({k:(hex(v) if isinstance(v,int) else [hex(x) for x in v]) for k,v in h.items()}))
    print('SEGMENTS:')
    for i,s in enumerate(segs(words)):
        print(f'  seg{i}: file 0x{s["fileoff"]:x}+0x{s["filelen"]:x} -> va 0x{s["vaddr"]:x}+0x{s["memlen"]:x} flags={s["flags"]}')
    if len(sys.argv)>=3:
        vm=VMap(words)
        start=int(sys.argv[2],0)
        count=int(sys.argv[3],0) if len(sys.argv)>3 else 80
        print(f'--- disasm va 0x{start:x} ({count} insns) ---')
        dis_va(vm,start,count)
