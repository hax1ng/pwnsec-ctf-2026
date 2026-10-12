#!/usr/bin/env python3
# Stage 5: sweep the 256 affine offsets, invert the sponge to the opened state, and forge the admin tag.
import json, sys, secrets
from util import *

D=json.load(open(sys.argv[1])); R=json.load(open(sys.argv[2]))
pos=R['pos']; source=R['guest']; other=1-source
rebased=list(bytes.fromhex(R['state']));L=R['L']

# chi^{-1}, implemented as a five-bit lookup independently on each bit slice.
chi_inv=[None]*32
for a in range(32):
    b=0
    for x in range(5):
        b |= (((a>>x)&1)^((((~a)>>((x+1)%5))&1)&((a>>((x+2)%5))&1)))<<x
    if chi_inv[b] is not None:raise AssertionError
    chi_inv[b]=a

def inv_chi(st):
    out=[0]*25
    for y in range(5):
        for bit in range(8):
            b=sum(((st[x+5*y]>>bit)&1)<<x for x in range(5));a=chi_inv[b]
            for x in range(5):out[x+5*y]|=((a>>x)&1)<<bit
    return out

def inv_shift(out):
    st=[0]*25
    for y in range(5):
        for x in range(5):
            st[x+5*y]=rot(out[y+5*((2*x+3*y)%5)],-offsets[x][y])
    return st

# theta can be inverted after solving only its 40-bit column-parity map.
def parity_map(v):
    C=[(v>>(8*x))&255 for x in range(5)]
    O=[C[x]^C[(x-1)%5]^rot(C[(x+1)%5],1) for x in range(5)]
    return sum(x<<(8*i) for i,x in enumerate(O))

piv={};pc={}
for j in range(40):
    v=parity_map(1<<j);c=1<<j
    while v:
        p=v.bit_length()-1
        if p in piv:v^=piv[p];c^=pc[p]
        else:piv[p]=v;pc[p]=c;break
if len(piv)!=40:raise AssertionError

def inv_parity(v):
    c=0
    while v:
        p=v.bit_length()-1;v^=piv[p];c^=pc[p]
    return c

def inv_theta(out):
    cp=[]
    for x in range(5):
        z=0
        for y in range(5):z^=out[x+5*y]
        cp.append(z)
    q=inv_parity(sum(cp[x]<<(8*x) for x in range(5)))
    C=[(q>>(8*x))&255 for x in range(5)]
    drift=[C[(x-1)%5]^rot(C[(x+1)%5],1) for x in range(5)]
    return [out[x+5*y]^drift[x] for y in range(5) for x in range(5)]

def inv_step(out,c):
    q=list(out);q[0]^=c
    return inv_theta(inv_shift(inv_chi(q)))

def inv_turn(st,constants=rounds):
    st=list(st)
    for c in constants[::-1]:st=inv_step(st,c)
    return st

def inv_edge(before,msg):
    st=list(before)
    for c in rounds[:-3][::-1]:st=inv_step(st,c)
    for i,b in enumerate(padded(msg)[16:32]):st[i]^=b
    st=inv_turn(st)
    for i,b in enumerate(msg[:16]):st[i]^=b
    return st

def edge_from_open(open_state,msg):
    data=padded(msg);st=list(open_state)
    for i,b in enumerate(data[:16]):st[i]^=b
    st=turn(st)
    for i,b in enumerate(data[16:32]):st[i]^=b
    for c in rounds[:-3]:st=step(st,c)
    return st

def seal_from_open(open_state,msg):
    st=list(open_state);data=padded(msg)
    for off in range(0,len(data),16):
        for i,b in enumerate(data[off:off+16]):st[i]^=b
        st=turn(st)
    return bytes(st)

def linear(y):
    x=0
    for i in range(8):
        if y>>i&1:x^=L[i]
    return x

messages=[bytes.fromhex(x) for x in D['guests']]
possibilities=[]
for offset in range(256):
    before=rebased[:];before[pos]^=offset
    open_state=inv_edge(before,messages[source])
    check=edge_from_open(open_state,messages[other]);check[pos]^=offset
    matches=0
    for label,y in enumerate(D['coords']):
        z=D['scans'][other][label]
        if z=='-':continue
        q=check[:];q[pos]^=linear(y)
        if peek(tail(q))==bytes.fromhex(z):matches+=1
    possibilities.append((matches,offset,open_state))
possibilities.sort(reverse=True,key=lambda x:x[0])
matches,offset,open_state=possibilities[0]
print('offset candidates',[(m,hex(c)) for m,c,_ in possibilities[:3]])
if matches<248:raise RuntimeError('the two guest states did not link')
admin=b'AdminSaysWEW'+bytes.fromhex(D['seed'])
answer=tag(seal_from_open(open_state,admin))
result={'answer':answer.hex(),'offset':offset,'opened':bytes(open_state).hex()}
print(json.dumps(result))
