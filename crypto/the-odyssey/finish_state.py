#!/usr/bin/env python3
# Stage 4b: add lower-dimension cube sums to pin down the final state and recover the linear map L.
import json, sys, itertools, random
from util import *

data_path, candidates_path, output_path = sys.argv[1:4]
D=json.load(open(data_path)); candidates=json.load(open(candidates_path))

def insert(B,x):
    while x:
        p=x.bit_length()-1
        if p in B:x^=B[p]
        else:B[p]=x;return True
    return False

def derive_linear(pairs):
    piv={}
    for y,x in pairs:
        yy=y;xx=x
        while yy:
            p=yy.bit_length()-1
            if p in piv: yy^=piv[p][0];xx^=piv[p][1]
            else:piv[p]=(yy,xx);break
        if len(piv)==8:break
    if len(piv)<8:return None
    def apply(y):
        x=0
        while y:
            p=y.bit_length()-1
            if p not in piv:return None
            y^=piv[p][0];x^=piv[p][1]
        return x
    return apply

def solve_one(C):
    pos=C['pos'];gi=C['guest'];part=int(C['part'],0)
    kernels=[int(x,0) for x in C['kernels']]
    chosen=[x['h'] for x in C['chosen']]; normals=C['normals']
    # Every nonzero form in the recovered space and its corresponding actual
    # fault-byte normal.
    forms=[]
    for mask in range(1,1<<len(chosen)):
        h=n=0
        for i in range(len(chosen)):
            if mask>>i&1:h^=chosen[i];n^=normals[i]
        forms.append((h,n))
    cubes=[];seen=set()
    for i in range(len(forms)):
        for j in range(i):
            h1,n1=forms[i];h2,n2=forms[j]
            labels=tuple(k for k,y in enumerate(D['coords'])
                if ((h1&1)^(((h1>>1)&y).bit_count()&1))
                and ((h2&1)^(((h2>>1)&y).bit_count()&1)))
            if labels in seen:continue
            seen.add(labels)
            if len(labels)!=64:continue
            xs=tuple(x for x in range(256)
                if ((n1&x).bit_count()&1)==(1^(h1&1))
                and ((n2&x).bit_count()&1)==(1^(h2&1)))
            if len(xs)!=64:continue
            target=0;valid=True
            for label in labels:
                z=D['scans'][gi][label]
                if z=='-':valid=False;break
                target ^= int.from_bytes(bytes.fromhex(z),'little')
            if not valid:continue
            # Undo the two known one-bit scan corruptions if this cube contains them.
            for label,bit in zip(C['noise'],C['error_bits']):
                if label in labels:target ^= 1<<bit
            cubes.append((xs,target))
    if not cubes:return None

    def state_from_bits(bits):
        return [sum(((bits>>(8*i+b))&1)<<b for b in range(8)) for i in range(25)]
    def evaluate(bits):
        st=state_from_bits(bits); table=[]
        for x in range(256):
            q=st[:];q[pos]^=x
            table.append(int.from_bytes(peek(tail(q)),'little'))
        out=0
        for ci,(xs,_) in enumerate(cubes):
            z=0
            for x in xs:z^=table[x]
            out |= z<<(64*ci)
        return out

    f0=evaluate(part); singles=[evaluate(part^k) for k in kernels]
    linear=[x^f0 for x in singles]
    # These sixth-order cube sums are affine in the pre-tail state for this
    # construction. Check several second derivatives before relying on it.
    for i,j in list(itertools.combinations(range(len(kernels)),2))[:12]:
        if evaluate(part^kernels[i]^kernels[j]) != f0^linear[i]^linear[j]:
            raise RuntimeError('unexpected quadratic state term')
    target=sum(t<<(64*i) for i,(_,t) in enumerate(cubes))

    piv={};pc={};ukernel=[]
    for i,v in enumerate(linear):
        c=1<<i
        while v:
            p=v.bit_length()-1
            if p in piv:v^=piv[p];c^=pc[p]
            else:piv[p]=v;pc[p]=c;break
        if not v:ukernel.append(c)
    v=target^f0;upart=0
    while v:
        p=v.bit_length()-1
        if p not in piv:return None
        v^=piv[p];upart^=pc[p]
    print('lower cubes',len(cubes),'rank',len(piv),'remaining',len(ukernel))
    if len(ukernel)>22:raise RuntimeError('too many remaining state candidates')

    for mask in range(1<<len(ukernel)):
        u=upart
        for i,k in enumerate(ukernel):
            if mask>>i&1:u^=k
        bits=part
        for i,k in enumerate(kernels):
            if u>>i&1:bits^=k
        st=state_from_bits(bits)
        lookup={}
        collision=False
        for x in range(256):
            q=st[:];q[pos]^=x;o=peek(tail(q))
            if o in lookup:collision=True
            lookup[o]=x
        pairs=[]
        for label,y in enumerate(D['coords']):
            if label in C['bad']:continue
            o=bytes.fromhex(D['scans'][gi][label])
            if o in lookup:pairs.append((y,lookup[o]))
        L=derive_linear(pairs)
        if L and len(pairs)>=240 and all(L(y)==x for y,x in pairs):
            return {'pos':pos,'guest':gi,'state':bytes(st).hex(),
                    'L':[L(1<<i) for i in range(8)],'matches':len(pairs)}
    return None

for C in candidates:
    answer=solve_one(C)
    if answer:
        json.dump(answer,open(output_path,'w'));print(json.dumps(answer));sys.exit(0)
print('no state candidate survived')
sys.exit(5)
