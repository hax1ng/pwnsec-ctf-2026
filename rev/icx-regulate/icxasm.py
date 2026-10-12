#!/usr/bin/env python3
import json, struct
from pathlib import Path
MASK=0x7fffff
SALT=[0x7e416e,0x5a5213,0xe586]
OPS=json.load(open('opcodes.json'))['name2op']
def mix(a,b): return (((a^b)*0x45d9f3)+0x494d)&MASK
def checksum(words):
    st=0x494d47
    for x in SALT: st=mix(st,x)
    for i,x in enumerate(words):
        if i!=10: st=mix(st,x)
    return st or 1
def write_words(path,words): Path(path).write_bytes(b"".join((x&MASK).to_bytes(3,"little") for x in words))

class Asm:
    def __init__(s): s.w=[]; s.labels={}; s.fix=[]
    def label(s,n): s.labels[n]=len(s.w)
    def emit(s,x): s.w.append(x&MASK)
    def rrr(s,op,d,a,b): s.emit((OPS[op]<<16)|(d<<12)|(a<<8)|(b<<4))
    def r(s,op,d): s.emit((OPS[op]<<16)|(d<<12))
    def n(s,op): s.emit((OPS[op]<<16))
    def movi(s,d,imm): s.emit((OPS['MOVI']<<16)|(d<<12)|(imm&0xfff))
    def ldi(s,d,imm): s.emit((OPS['LDI']<<16)|(d<<12)); s.emit(imm&MASK)
    def ri12(s,op,d,imm): s.emit((OPS[op]<<16)|(d<<12)|(imm&0xfff))
    def load(s,d,b,o=0): s.emit((OPS['LOAD']<<16)|(d<<12)|(b<<8)|(o&0xff))
    def store(s,sr,b,o=0): s.emit((OPS['STORE']<<16)|(sr<<12)|(b<<8)|(o&0xff))
    def lea(s,d,b,o=0): s.emit((OPS['LEA']<<16)|(d<<12)|(b<<8)|(o&0xff))
    def br(s,op,l): s.fix.append((len(s.w),op,l)); s.emit(OPS[op]<<16)
    def done(s):
        for i,op,l in s.fix:
            off=s.labels[l]-(i+1); assert -0x8000<=off<0x8000
            s.w[i]=(OPS[op]<<16)|(off&0xffff)
        return s.w

def build(code, entry=0x120000, vaddr=0x120000, flags=13, extra=None):
    count=1+(len(extra) if extra else 0)
    hdr=12+5*count; offc=hdr
    base=[0x494d47,1,*SALT,count,entry,0,0,0x6ffb00,0,0]
    base+=[offc,len(code),vaddr,0x1000,flags]
    seg=list(code); cur=offc+len(code)
    if extra:
        for (d,va,ml,fg) in extra:
            base+=[cur,len(d),va,ml,fg]; seg+=list(d); cur+=len(d)
    words=base+seg; words[10]=checksum(words); return words

if __name__=='__main__':
    import sys
    # single-instruction test: build capsule with given op at entry
    name=sys.argv[1] if len(sys.argv)>1 else 'HALT'
    a=Asm()
    if name=='HALT': a.n('HALT')
    elif name=='BREAK': a.n('BREAK')
    elif name=='RET': a.n('RET')
    elif name=='WAIT': a.n('WAIT')
    elif name=='ERET': a.n('ERET')
    elif name=='NOP': a.n('NOP')
    w=build(a.done())
    write_words('/tmp/t.gmi',w)
    print(f"{name}: word={a.w[0]:#x} words={len(w)} checksum={w[10]:#x}")
