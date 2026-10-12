#!/usr/bin/env python3
# Stage 4a: solve the high-degree cube equations for the pre-tail state (up to an affine family) and locate the flipped scan bits.
import json, sys, itertools
from util import *

data_path, meta_path, normals_s, out_path = sys.argv[1:5]
D=json.load(open(data_path)); meta=json.load(open(meta_path))
pos=meta['pos']; gi=meta['guest']; normals=[int(x,0) for x in normals_s.split(',')]
chosen=meta['chosen']; normals=normals[:len(chosen)]
if not all(normals): raise ValueError('not enough recovered normals')

def eval_form(h,label):
    y=D['coords'][label]
    return (h&1)^(((h>>1)&y).bit_count()&1)

def cube_sum(h):
    z=0
    for label in range(256):
        if eval_form(h,label):
            value=D['scans'][gi][label]
            if value!='-': z ^= int.from_bytes(bytes.fromhex(value),'little')
    return z

def Pvals(st):
    P=[0]*8; top=0
    for x in range(256):
        q=st[:];q[pos]^=x
        o=int.from_bytes(peek(tail(q)),'little');top^=o
        for b in range(8):
            if x>>b&1:P[b]^=o
    return top,P

top,base=Pvals([0]*25); ders=[]
for k in range(200):
    st=[0]*25;st[k//8]=1<<(k%8)
    t,p=Pvals(st)
    if t!=top: raise AssertionError
    ders.append([p[b]^base[b] for b in range(8)])

def ev(P,n):
    z=0
    for b in range(8):
        if n>>b&1:z^=P[b]
    return z

d=len(chosen)
baseflat=0; observed=[]
for j,(item,n) in enumerate(zip(chosen,normals)):
    h=item['h'];observed.append(cube_sum(h))
    baseflat |= (ev(base,n)^(top if h&1 else 0))<<(64*j)
cols=[]
for k in range(200):
    z=0
    for j,n in enumerate(normals):z |= ev(ders[k],n)<<(64*j)
    cols.append(z)

# Column elimination, retaining coefficient vectors in the 200 state variables.
piv={}; pc={}; kernels=[]
for k,v in enumerate(cols):
    c=1<<k
    while v:
        p=v.bit_length()-1
        if p in piv:v^=piv[p];c^=pc[p]
        else:piv[p]=v;pc[p]=c;break
    if not v:kernels.append(c)

def solve(v):
    c=0
    while v:
        p=v.bit_length()-1
        if p not in piv:return None
        v^=piv[p];c^=pc[p]
    return c

# The two labels not in `gross` each carry exactly one flipped scan bit.
# Locate those bits by trying 64^2 possibilities in the high-degree equations.
solutions=[]
for error_bits in itertools.product(range(64),repeat=len(meta['noise'])):
    corrected=observed[:]
    for q,bit in enumerate(error_bits):
        for j,item in enumerate(chosen):
            if item['ep'][q]: corrected[j]^=1<<bit
    target=sum(corrected[j]<<(64*j) for j in range(d))
    part=solve(target^baseflat)
    if part is not None: solutions.append((list(error_bits),part))

print('rank',len(piv),'affine dimension',len(kernels),'correction solutions',len(solutions))
if not solutions: sys.exit(4)
# A valid cube-enumeration match normally leaves exactly one correction.
outs=[]
for bits,part in solutions:
    outs.append({
        **meta,'normals':normals,'error_bits':bits,
        'part':hex(part),'kernels':[hex(x) for x in kernels],
    })
json.dump(outs,open(out_path,'w'))
print('wrote',out_path)
