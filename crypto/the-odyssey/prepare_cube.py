#!/usr/bin/env python3
# Stage 3a: build the cube-derivative tables + adapted hyperplane forms for one position/error-pair guess (input to cube_enum).
import json, sys, itertools, pickle, os
from util import *

data_path, pos_s, guest_s, pair_s, out_path = sys.argv[1:6]
D = json.load(open(data_path)); pos = int(pos_s); gi = int(guest_s)

def insert(B, x):
    while x:
        p=x.bit_length()-1
        if p in B: x ^= B[p]
        else: B[p]=x; return True
    return False

def rank(vs):
    B={}
    return sum(insert(B,x) for x in vs)

def inside(B,x):
    while x:
        p=x.bit_length()-1
        if p not in B: return False
        x ^= B[p]
    return True

def nullspace(rows,n):
    piv={}
    for row in rows:
        y=row
        while y:
            p=y.bit_length()-1
            if p in piv: y ^= piv[p]
            else: piv[p]=y; break
    out=[]
    for free in range(n):
        if free in piv: continue
        x=1<<free
        for p in sorted(piv):
            if (piv[p]&x).bit_count()&1: x |= 1<<p
        out.append(x)
    return out

small=[x for x in range(256) if x.bit_count()<4]
def shape(y):
    return sum(1<<i for i,c in enumerate(small) if c&~y==0)

Hcols=[shape(y) for y in D['coords']]
scar=D['scars'][gi]
synd=[]
for bit in range(24):
    s=0
    for i,z in enumerate(scar):
        if z!='-' and (int.from_bytes(bytes.fromhex(z),'little')>>bit)&1:
            s ^= Hcols[i]
    synd.append(s)
B={}
for s in synd: insert(B,s)
bad=[i for i,h in enumerate(Hcols) if inside(B,h)]
erasures=[i for i,z in enumerate(scar) if z=='-']
extras=[i for i in bad if i not in erasures]
pair=tuple(int(x) for x in pair_s.split(','))
if len(pair)!=2 or not set(pair)<=set(extras): raise ValueError('bad gross pair')
gross=erasures+list(pair)
noise=[i for i in extras if i not in pair]
H=nullspace([1|(D['coords'][i]<<1) for i in gross],9)

def eval_form(h,label):
    y=D['coords'][label]
    return (h&1)^(((h>>1)&y).bit_count()&1)

forms=[]
for mask in range(1,1<<len(H)):
    h=0
    for i in range(len(H)):
        if mask>>i&1: h ^= H[i]
    ep=tuple(eval_form(h,p) for p in noise)
    forms.append((h,ep))
chosen=[]
for wt in range(3):
    for h,ep in forms:
        if sum(ep)!=wt: continue
        if rank([x for x,_ in chosen]+[h])>len(chosen): chosen.append((h,ep))
        if len(chosen)==len(H): break
    if len(chosen)==len(H): break
if len(chosen)<3 or chosen[0][1]!=(0,0) or sum(chosen[1][1])>1:
    print('SKIP: unsuitable adapted form basis', file=sys.stderr)
    sys.exit(3)
# Four directions already overdetermine the high-degree state equations and
# are the maximum consumed by the compact C++ enumerator.
chosen=chosen[:4]

def cube_sum(h):
    z=0
    for label,y in enumerate(D['coords']):
        if eval_form(h,label):
            value=D['scans'][gi][label]
            if value!='-': z ^= int.from_bytes(bytes.fromhex(value),'little')
    return z

cache=os.path.join(os.path.dirname(out_path),f'formula_pos{pos}.pickle')
if os.path.exists(cache):
    top,base,ders=pickle.load(open(cache,'rb'))
else:
    def Pvals(st):
        P=[0]*8; top=0
        for x in range(256):
            q=st[:]; q[pos]^=x
            o=int.from_bytes(peek(tail(q)),'little'); top ^= o
            for b in range(8):
                if x>>b&1: P[b]^=o
        return top,P
    top,base=Pvals([0]*25); raw=[]
    for k in range(200):
        st=[0]*25; st[k//8]=1<<(k%8)
        t,p=Pvals(st)
        if t!=top: raise AssertionError('degree-eight term depends on state')
        raw.append([p[b]^base[b] for b in range(8)])
    # Only a basis of the derivative image is required by cube_enum.
    piv={}; ders=[]
    for ds in raw:
        w=sum(ds[b]<<(64*b) for b in range(8))
        while w:
            p=w.bit_length()-1
            if p in piv: w ^= piv[p]
            else: piv[p]=w; ders.append(ds); break
    pickle.dump((top,base,ders),open(cache,'wb'))

with open(out_path,'w') as f:
    f.write(f'{pos} {top:016x} {len(ders)} {len(chosen)}\n')
    f.write(' '.join(f'{x:016x}' for x in base)+'\n')
    for ds in ders: f.write(' '.join(f'{x:016x}' for x in ds)+'\n')
    for h,ep in chosen:
        f.write(f'{h:x} {cube_sum(h):016x} '+''.join(map(str,ep))+'\n')

meta={
    'pos':pos,'guest':gi,'bad':bad,'erasures':erasures,'extras':extras,
    'gross':gross,'noise':noise,
    'chosen':[{'h':h,'ep':list(ep)} for h,ep in chosen],
}
json.dump(meta,open(out_path+'.json','w'))
print(json.dumps(meta))
