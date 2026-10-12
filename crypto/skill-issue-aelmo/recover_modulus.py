#!/usr/bin/env python3
"""Turn the two `flatter` outputs into p and the complete x0 block."""
import hashlib, json, math, re, sys
from hashlib import shake_256
from Crypto.Util.number import isPrime

N=16

def rows(path):
    out=[]
    for line in open(path):
        z=[int(x) for x in re.findall(r"-?\d+",line)]
        if z: out.append(z)
    return out

def stream(seed,tag,l):
    o=b"";c=0
    while len(o)<l:
        o+=shake_256(seed+tag+c.to_bytes(2,"little")).digest(64);c+=1
    return o[:l]

def diag(seed,tag):
    o=[];c=0
    while len(o)<N:
        for x in stream(seed,tag+c.to_bytes(2,"little"),64):
            v=2+x%241
            if v not in o and all(abs(v-y)!=1 for y in o):
                o.append(v)
                if len(o)==N:break
        c+=1
    return o

def mmul(a,b,p):
    bt=list(zip(*b))
    return [[sum(x*y for x,y in zip(r,c))%p for c in bt] for r in a]

def mpow(a,e,p):
    r=[[int(i==j) for j in range(N)] for i in range(N)]
    while e:
        if e&1:r=mmul(r,a,p)
        a=mmul(a,a,p);e//=2
    return r

def invmat(a,p):
    n=len(a);z=[[x%p for x in a[i]]+[int(i==j) for j in range(n)] for i in range(n)]
    for j in range(n):
        q=next(i for i in range(j,n) if z[i][j]);z[j],z[q]=z[q],z[j]
        iv=pow(z[j][j],-1,p);z[j]=[x*iv%p for x in z[j]]
        for i in range(n):
            if i!=j and z[i][j]:
                q=z[i][j];z[i]=[(x-q*y)%p for x,y in zip(z[i],z[j])]
    return [r[n:] for r in z]

def matvec(a,v,p):return [sum(x*y for x,y in zip(r,v))%p for r in a]

def fmat(a,p):
    x4097=mpow(a,4097,p);x257=mpow(a,257,p);x17=mpow(a,17,p)
    return [[(x4097[i][j]+3*x257[i][j]+11*x17[i][j]+42*a[i][j]+99*int(i==j))%p
             for j in range(N)] for i in range(N)]

def main():
    pubfn=sys.argv[1] if len(sys.argv)>1 else "local_public.json"
    prefix=sys.argv[2] if len(sys.argv)>2 else "localemb"
    outfn=sys.argv[3] if len(sys.argv)>3 else "recovered_x0.json"
    pub=json.load(open(pubfn));inds=json.load(open(prefix+"_indices.json"));L=len(inds)
    cap=pub["cap"]; C=[[cap[i*48+j] for j in range(N)] for i in range(N)]
    d=diag(bytes.fromhex(pub["seed"]),b"a")
    scales=[1+d[i]-d[j] for i in range(N) for j in range(N)]

    rr=rows(prefix+"_second_flat.txt")
    ker=[r[:L] for r in rr if len(r)>L and all(x==0 for x in r[L:])]
    print("[*] short second-kernel rows:",[(sum(x*x for x in r).bit_length(),max(map(abs,r))) for r in ker])
    candidates=[]
    for v in ker:
        if max(map(abs,v))<=1:continue
        qs=[]
        ok=True
        for q,idx in enumerate(inds):
            if idx//N==idx%N:continue
            s=scales[idx]
            if v[q]%s:ok=False;break
            qs.append(v[q]//s)
        if not ok:continue
        g=0
        for x in qs:
            if x:g=math.gcd(g,abs(x))
        g=max(g,1)
        for orient in (1,-1):
            if all(0<=orient*x//g<=255 and x%g==0 for x in qs):
                # B = A + scalar*I on the selected coordinates.
                candidates.append(([orient*x//g for x in v],orient,g))
    if len(candidates)!=1:raise ValueError(f"ambiguous augmented candidate count {len(candidates)}")
    bv,orient,alpha=candidates[0]
    print(f"[+] augmented direction: orientation={orient}, scalar multiple={alpha}")
    partial=dict(zip(inds,bv))

    # Coordinates were selected to contain row 0 and columns 0..3.
    es=[]
    for j in range(4):
        e=sum(C[0][k]*partial[k*N+j]-partial[k]*C[k][j] for k in range(N))
        if e:es.append(abs(e))
    p=0
    for e in es:p=math.gcd(p,e)
    # Normally the four small cofactors are coprime.  Be conservative if a
    # tiny common factor survived.
    if not (p>max(cap) and isPrime(p)):
        for q in range(2,1_000_001):
            if p%q==0 and p//q>max(cap) and isPrime(p//q):
                p//=q;break
    assert p>max(cap) and p.bit_length()==2048 and isPrime(p)
    print(f"[+] recovered p ({p.bit_length()} bits) = {p}")

    # Extend B=A+tI from its complete first row using the cyclic centralizer.
    I=[[int(i==j) for j in range(N)] for i in range(N)]
    powers=[I]
    for _ in range(1,N):powers.append(mmul(powers[-1],C,p))
    vp=[[powers[k][0][j] for k in range(N)] for j in range(N)]
    target=[partial[j]%p for j in range(N)]
    coeff=matvec(invmat(vp,p),target,p)
    B=[[sum(coeff[k]*powers[k][i][j] for k in range(N))%p for j in range(N)] for i in range(N)]
    B=[[x if x<=p//2 else x-p for x in r] for r in B]
    assert all(B[idx//N][idx%N]==partial[idx] for idx in inds)

    lo=max(-B[i][i] for i in range(N)); hi=min(255-B[i][i] for i in range(N))
    print(f"[*] testing diagonal shifts {lo}..{hi}")
    good=[]
    for z in range(lo,hi+1):
        A=[r[:] for r in B]
        for i in range(N):A[i][i]+=z
        if fmat(A,p)==C:good.append((z,A))
    if len(good)!=1:raise ValueError(f"polynomial shift branches: {len(good)}")
    z,A=good[0];print(f"[+] unique diagonal shift {z}")
    m=[]
    for i in range(N):
        for j in range(N):
            s=scales[i*N+j]
            assert A[i][j]%s==0 and 0<=A[i][j]//s<=255
            m.append(A[i][j]//s)
    out={"p":p,"x0":sum(A,[]),"m0":m,"shift":z,"source_candidate_orientation":orient}
    json.dump(out,open(outfn,"w"));print("[+] wrote",outfn)

if __name__=="__main__":main()
