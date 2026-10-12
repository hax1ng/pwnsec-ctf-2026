#!/usr/bin/env python3
"""Disassemble the ICX guest word dump recovered through the emulator's read path."""
import struct
from pathlib import Path

BASE = 0x50000
OPS = {
0x05:("NOP","N"),0x23:("ADD","RRR"),0x0b:("SUB","RRR"),0x63:("MUL","RRR"),
0x3d:("DIVU","RRR"),0x33:("DIVS","RRR"),0x02:("MODU","RRR"),0x57:("MODS","RRR"),
0x26:("AND","RRR"),0x52:("OR","RRR"),0x3a:("XOR","RRR"),0x1f:("NOT","R"),
0x6d:("SHL","RRR"),0x29:("SHR","RRR"),0x68:("SAR","RRR"),0x34:("ROL","RRR"),0x0e:("ROR","RRR"),
0x74:("CMPEQ","RRR"),0x4a:("CMPNE","RRR"),0x04:("CMPLTU","RRR"),0x54:("CMPLEU","RRR"),
0x09:("CMPLTS","RRR"),0x53:("CMPLES","RRR"),0x5c:("MOV","RRR"),0x79:("MOVI","RI12"),
0x6b:("LDI","X"),0x4e:("LOAD","RRI8"),0x69:("STORE","RRI8"),0x27:("LEA","RRI8"),
0x1c:("BR","B16"),0x7a:("BZ","B16"),0x4f:("BNZ","B16"),0x2e:("CALL","B16"),
0x4c:("CALLR","R"),0x0f:("RET","N"),0x44:("PUSH","R"),0x2c:("POP","R"),
0x6f:("CAS","RRR"),0x6c:("SWAP","RRR"),0x2a:("FENCE","N"),0x41:("ERET","N"),
0x1d:("PRET","R"),0x7b:("TLBOP","RI12"),0x56:("CACHEOP","RI12"),0x5a:("GETSR","RI12"),
0x43:("SETSR","RI12"),0x3e:("HALT","N"),0x5f:("WAIT","N"),0x19:("BREAK","N"),
0x5b:("OCTPACK","RRR"),0x62:("OCTUNPACK","RRR"),
}

def sx(v,bits):
    return v-(1<<bits) if v&(1<<(bits-1)) else v

def main():
    words=list(struct.unpack('<%dI'%(Path('guest_50000.words.bin').stat().st_size//4),Path('guest_50000.words.bin').read_bytes()))
    out=[]; i=0
    while i<len(words):
        a=BASE+i; w=words[i]&0x7fffff; op=w>>16
        if op not in OPS:
            out.append(f'{a:06x}: {w:06x}  .word 0x{w:06x}')
            i+=1; continue
        n,f=OPS[op]; args=''; extra=''
        if f=='RRR': args=f'R{(w>>12)&15}, R{(w>>8)&15}, R{(w>>4)&15}'
        elif f=='R': args=f'R{(w>>12)&15}'
        elif f=='RI12': args=f'R{(w>>12)&15}, {sx(w&0xfff,12)}'
        elif f=='RRI8': args=f'R{(w>>12)&15}, R{(w>>8)&15}, {sx(w&0xff,8)}'
        elif f=='B16':
            off=sx(w&0xffff,16); args=f'{off:+d}  ; -> 0x{(a+1+off)&0x7fffff:06x}'
        elif f=='X':
            imm=words[i+1]&0x7fffff if i+1<len(words) else 0
            args=f'R{(w>>12)&15}, 0x{imm:06x}'; extra=f' {imm:06x}'; i+=1
        out.append(f'{a:06x}: {w:06x}{extra}  {n:<9} {args}')
        i+=1
    Path('guest_50000.asm').write_text('\n'.join(out)+'\n')
    # Identify runs of words whose low octet is printable/newline/CR/tab and whose upper bits are clear.
    i=0
    while i<len(words):
        j=i
        while j<len(words) and words[j] < 0x100 and (words[j] in (9,10,13,0) or 32<=words[j]<127): j+=1
        if j-i>=4:
            bs=bytes(x&255 for x in words[i:j])
            print(f'{BASE+i:06x}-{BASE+j:06x}: {bs!r}')
        i=max(j,i+1)

if __name__=='__main__': main()
