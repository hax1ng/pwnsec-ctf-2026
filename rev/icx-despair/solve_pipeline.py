#!/usr/bin/env python3
import re,struct
MASK=(1<<23)-1

def rol(x,n):
 n%=23;x&=MASK
 return ((x<<n)|(x>>(23-n)))&MASK if n else x

def h2(a,b):
 a&=MASK;b&=MASK
 x=((a+b)&MASK) ^ ((a*(b|1))&MASK)
 return rol(x,((a^b)%22)+1)

def h3(a,b,c):
 a&=MASK;b&=MASK;c&=MASK
 x=h2(a^b,c^0x524350)^c
 x=h2(x,b)^((c+0x1c5801)&MASK)
 x=h2(x,b^0x45d9f3)^((c+0x38b002)&MASK)
 x=h2(x,b^0x0bb3e6)^((c+0x550803)&MASK)
 x=h2(x,b^0x518dd9)^((c+0x716004)&MASK)
 x=h2(x,b^0x1767cc)^((c+0x0db805)&MASK)
 x=h2(x,b^0x5d41bf)^((c+0x2a1006)&MASK)
 x=h2(x,b^0x231bb2)
 return x&MASK

def perm16(key,tag,x):
 L=x>>2;R=x&3
 for rnd in range(4):
  L,R=R,L^(h3(key^R,tag^rnd,R)&3)
 return ((L<<2)|R)&15
MAP2=[5,7,11,9]
def qam(y,r):
 lo=MAP2[y&3];hi=MAP2[(y>>2)&3]
 for _ in range(r): lo,hi=(16-hi)&15,lo
 return lo|(hi<<4)

def getbits(words,n):return [(words[i//23]>>(i%23))&1 for i in range(n)]
def packbits(bits):
 w=[0]*((len(bits)+22)//23)
 for i,b in enumerate(bits):w[i//23]|=b<<(i%23)
 return w
lines=open('/tmp/map.err').read().splitlines()
map4=[None]*1025;map5=[None]*1025;map6=[None]*1025
qkey=[None]*257;qrot=[None]*257;actual=[None]*257;desired=[None]*257
for s in lines:
 z=s.split()
 if not z:continue
 if z[0]=='MAP4': i,src,m=map(int,z[1:]);map4[i]=(src,m)
 elif z[0]=='MAP5': i,src,m=map(int,z[1:]);map5[i]=(src,m)
 elif z[0]=='MAP6': i,m=map(int,z[1:]);map6[i]=m
 elif z[0]=='QKEY': i,raw,key=int(z[1]),int(z[2]),int(z[3],16);qkey[i]=key
 elif z[0]=='QROT': i,r=map(int,z[1:]);qrot[i]=r
 elif z[0]=='TGT':
  i=int(re.search(r'idx=(\d+)',s).group(1));actual[i]=int(re.search(r'actual=([0-9a-f]+)',s).group(1),16)
 elif z[0]=='TGTH':
  i=int(z[1].split('=')[1]);H=int(z[2].split('=')[1],16);desc=int(re.search(r'stk=([0-9a-f]+)',s).group(1),16);desired[i]=H^desc
assert all(x is not None for arr in [map4,map5,map6,qkey,qrot,actual,desired] for x in arr)

def invert(outputs):
 final=[]
 raws=[]
 for i,out in enumerate(outputs):
  cands=[x for x in range(16) if qam(perm16(qkey[i],0x51414d,x),qrot[i])==out]
  if len(cands)!=1:raise ValueError((i,out,cands,qkey[i],qrot[i]))
  x=cands[0];raws.append(x);final += [(x>>k)&1 for k in range(4)]
 assert final[1025:]==[0,0,0]
 final=final[:1025]
 inter=[final[i]^map6[i] for i in range(1025)]
 rate=[None]*1025
 for i,(src,m) in enumerate(map5):
  v=inter[i]^m
  if rate[src] is not None and rate[src]!=v:raise ValueError(('map5 conflict',i,src))
  rate[src]=v
 assert None not in rate
 stage3=[None]*897
 for i,(src,m) in enumerate(map4):
  v=rate[i]^m
  if stage3[src] is not None and stage3[src]!=v:raise ValueError(('map4 conflict',i,src,stage3[src],v))
  stage3[src]=v
 assert None not in stage3
 return raws,final,inter,rate,stage3
# self test against actual A run scratch witness
*_,stA=invert(actual)
mem=memoryview(open('/tmp/Amem.bin','rb').read()).cast('I');base=0xb00c0
witA=getbits(mem[base+63:base+63+39],897)
print('selftest stage3 mismatches',sum(a!=b for a,b in zip(stA,witA)))
raws,final,inter,rate,stage3=invert(desired)
print('desired actual:', ''.join(f'{x:02x}' for x in desired))
print('raw nibbles:', ''.join(f'{x:x}' for x in raws))
print('witness bits:', ''.join(map(str,stage3[:500])))
print('witness words:', ' '.join(f'{x:06x}' for x in packbits(stage3[:500])))
open('witness_bits.txt','w').write(''.join(map(str,stage3[:500]))+'\n')
