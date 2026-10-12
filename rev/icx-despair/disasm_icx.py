#!/usr/bin/env python3
import argparse, struct
from pathlib import Path

OPS={}
for line in Path(__file__).with_name('opcode_map.txt').read_text().splitlines():
    op,name,fmt,priv=line.split()
    OPS[int(op,16)]=(name,fmt,priv)

def sx(x,b): return x-(1<<b) if x&(1<<(b-1)) else x

def inst(words,pc):
    w=words[pc]; op=(w>>16)&0x7f
    if op not in OPS: return f'.word 0x{w:06x}',1,[]
    name,fmt,priv=OPS[op]; lo=w&0xffff
    targ=[]
    if fmt=='N': s=name; n=1
    elif fmt=='R': s=f'{name} r{(w>>12)&15:x}'; n=1
    elif fmt=='RRR': s=f'{name} r{(w>>12)&15:x}, r{(w>>8)&15:x}, r{(w>>4)&15:x}'; n=1
    elif fmt=='RI12': s=f'{name} r{(w>>12)&15:x}, {sx(w&0xfff,12):#x}'; n=1
    elif fmt=='RRI8': s=f'{name} r{(w>>12)&15:x}, r{(w>>8)&15:x}, {sx(w&0xff,8):#x}'; n=1
    elif fmt=='B16':
        off=sx(lo,16); target=(pc+1+off)&0x7fffff; s=f'{name} {off:+#x} ; 0x{target:06x}'; n=1; targ=[target]
    elif fmt=='X':
        imm=words[pc+1] if pc+1<len(words) else 0
        s=f'{name} r{(w>>12)&15:x}, 0x{imm:06x}'; n=2
    else: s=f'{name} ?0x{lo:04x}';n=1
    # Show malformed unused low bits: useful to distinguish code/data.
    return s,n,targ

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('image',nargs='?',default='logical_words.bin')
 ap.add_argument('--start',type=lambda x:int(x,0),default=0x600); ap.add_argument('--count',type=lambda x:int(x,0),default=0x200)
 a=ap.parse_args(); data=Path(a.image).read_bytes(); words=struct.unpack('<%dI'%(len(data)//4),data)
 pc=a.start; end=min(len(words),pc+a.count)
 while pc<end:
  s,n,t=inst(words,pc); raw=' '.join(f'{words[pc+i]:06x}' for i in range(min(n,len(words)-pc)))
  print(f'{pc:06x}: {raw:<15} {s}')
  pc+=n
if __name__=='__main__':main()
