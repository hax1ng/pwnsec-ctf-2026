#!/usr/bin/env python3
import json,pickle,sys
NAMES="NOP ADD SUB MUL DIVU DIVS MODU MODS AND OR XOR NOT SHL SHR SAR ROL ROR CMPEQ CMPNE CMPLTU CMPLEU CMPLTS CMPLES MOV MOVI LDI LOAD STORE LEA BR BZ BNZ CALL CALLR RET PUSH POP CAS SWAP FENCE ERET PRET TLBOP CACHEOP GETSR SETSR HALT WAIT BREAK OCTPACK OCTUNPACK".split()
FMT="N RRR RRR RRR RRR RRR RRR RRR RRR RRR RRR R RRR RRR RRR RRR RRR RRR RRR RRR RRR RRR RRR RRR RI12 X RRI8 RRI8 RRI8 B16 B16 B16 B16 R N R R RRR RRR N N R RI12 RI12 RI12 RI12 N N N N RRR RRR".split()
OPS=json.load(open('opcodes.json'))['name2op']
op2i={OPS[NAMES[i]]:i for i in range(len(NAMES))}
words,full=pickle.load(open('/tmp/gwords.pkl','rb'))
def sx(x,n): return x-(1<<n) if x&(1<<(n-1)) else x
def dis1(pc):
    w=words.get(pc,0); op=(w>>16)&0x7f
    if op not in op2i: return (f".word {w:#08x}",1)
    i=op2i[op]; n=NAMES[i]; f=FMT[i]; a=(w>>12)&15;b=(w>>8)&15;c=(w>>4)&15
    if f=='N': s=n
    elif f=='R': s=f"{n} r{a}"
    elif f=='RRR': s=f"{n} r{a}, r{b}, r{c}"
    elif f=='RI12': s=f"{n} r{a}, {sx(w&0xfff,12):#x}"
    elif f=='RRI8': s=f"{n} r{a}, r{b}, {sx(w&0xff,8):#x}"
    elif f=='B16': s=f"{n} {(pc+1+sx(w&0xffff,16))&0x7fffff:#08x}"
    elif f=='X': nw=words.get(pc+1,0); s=f"{n} r{a}, {nw:#x}"; return (s,2)
    else: s=n
    return (s,1)
def disasm(start,end):
    pc=start
    while pc<end:
        s,ln=dis1(pc)
        raw=words.get(pc,0)
        print(f"  {pc:#08x}: {raw:06x}  {s}")
        pc+=ln
if __name__=='__main__':
    start=int(sys.argv[1],0); end=int(sys.argv[2],0) if len(sys.argv)>2 else start+80
    disasm(start,end)
