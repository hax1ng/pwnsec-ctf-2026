# Stage 1: recover the hidden Reed-Muller byte coordinates from the wake HSSP leaks.
import sys, json, itertools

p = (1 << 512) - 569

def parse(path):
    out={'wakes':[], 'guests':[], 'scars':[], 'scans':[]}
    for line in open(path):
        line=line.strip()
        if line.startswith('seed: '): out['seed']=line[6:]
        elif line.startswith('wake: '): out['wakes'].append([int(x,16) for x in line[6:].split(',')])
        elif line.startswith('guest: '): out['guests'].append(line[7:])
        elif line.startswith('scar: '): out['scars'].append(line[6:].split(','))
        elif line.startswith('scan: '): out['scans'].append(line[6:].split(','))
    return out

def recover_lattice(h, n=26):
    m=len(h)
    hv=vector(ZZ,h)
    B=matrix(ZZ,hv).T.augment(identity_matrix(ZZ,m)).stack(vector(ZZ,[p]+[0]*m))
    print('LLL1',B.dimensions(),flush=True)
    B=B.LLL(algorithm='fpLLL:fast')
    nr=m-n
    zero=[r[1:] for r in B if r[0]==0]
    assert len(zero) >= nr
    ortho=matrix(ZZ,zero[:nr])
    R=ortho.T.augment(identity_matrix(ZZ,m))
    R[:,:nr] *= 2^12
    print('LLL2',R.dimensions(),flush=True)
    R=R.LLL(algorithm='fpLLL:fast')
    good=[vector(ZZ,row[nr:]) for row in R if not any(row[:nr])]
    assert len(good)==n
    return matrix(ZZ,good)

def allones(v):
    if all(x in (0,1) for x in v) and any(v): return vector(ZZ,v)
    if all(x in (0,-1) for x in v) and any(v): return -vector(ZZ,v)

def recover_binary(L,n=26):
    todo=[]; seen=set()
    for row in L:
        v=allones(row)
        if v is not None and tuple(v) not in seen:
            seen.add(tuple(v)); todo.append(v)
    i=0
    while i<len(todo):
        v=todo[i];i+=1
        for row in L:
            for vv in (row-v,row+v):
                nv=allones(vv)
                if nv is not None and tuple(nv) not in seen:
                    seen.add(tuple(nv));todo.append(nv)
    print('binary vectors',len(todo),flush=True)
    if len(todo)!=n:
        return None
    return matrix(ZZ,todo)

def mitm_masks(weights, targets):
    n=len(weights); k=n//2
    left={}
    for mask in range(1<<k):
        s=sum(weights[i] for i in range(k) if mask>>i&1)%p
        left[s]=mask
    right=[]
    for mask in range(1<<(n-k)):
        s=sum(weights[k+i] for i in range(n-k) if mask>>i&1)%p
        right.append((s,mask))
    ans=[]
    for target in targets:
        found=None
        for s2,m2 in right:
            m1=left.get((target-s2)%p)
            if m1 is not None:
                found=m1|(m2<<k);break
        assert found is not None
        ans.append(found)
    return ans

def recover_wake(h):
    # A reduced completion basis is occasionally awkward for the simple
    # Nguyen--Stern greedy binary-vector recovery.  Independent 64-sample
    # windows give equivalent HSSP instances, so retry another one if needed.
    for start in (0,64,128,192):
        idx=list(range(start,start+64))
        L=recover_lattice([h[i] for i in idx])
        A=recover_binary(L) # 26 x 64, each row a hidden component
        if A is None:
            print('retry HSSP window',start+64,flush=True)
            continue
        F=GF(p)
        try:
            weights=matrix(F,A.T).solve_right(vector(F,[h[i] for i in idx]))
        except ValueError:
            continue
        weights=[ZZ(x) for x in weights]
        masks=mitm_masks(weights,h)
        if not all(all(((masks[i]>>j)&1)==A[j,col] for j in range(26)) for col,i in enumerate(idx)):
            continue
        comps=[]
        for j in range(26): comps.append(tuple((mask>>j)&1 for mask in masks))
        if all(sum(weights[j] for j in range(26) if masks[i]>>j&1)%p==h[i] for i in range(256)):
            return comps
    raise RuntimeError('HSSP recovery failed in every sample window')

data=parse(sys.argv[1])
allcomps=[]
for wi,h in enumerate(data['wakes']):
    print('=== WAKE',wi,'===',flush=True)
    allcomps.append(recover_wake(h))

sets=[set(c) for c in allcomps]
marks=set()
for i in range(3):
    for j in range(i):
        common=sets[i]&sets[j]
        print('intersection',j,i,len(common),flush=True)
        assert len(common)==12
        marks |= common
assert len(marks)==36

print('Schur square',flush=True)
C=matrix(GF(2),[list(v) for v in marks])
sq=[]
for i in range(C.nrows()):
    for j in range(i,C.nrows()):
        sq.append([C[i,k]*C[j,k] for k in range(256)])
S=matrix(GF(2),sq)
print('square rank',S.rank(),flush=True)
K=S.right_kernel().basis_matrix()
print('dual dims',K.dimensions(),flush=True)
assert K.nrows()==9
one=vector(GF(2),[1]*256)
assert one in K.row_space()
basis=[one]
for row in K:
    if matrix(GF(2),basis+[row]).rank()>len(basis): basis.append(row)
assert len(basis)==9
coords=basis[1:]
ys=[int(sum(ZZ(coords[b][label])<<b for b in range(8))) for label in range(256)]
assert len(set(ys))==256

out=data
out['coords']=ys
out['mark_vectors']=[''.join(str(x) for x in v) for v in marks]
json.dump(out,open(sys.argv[2],'w'))
print('wrote',sys.argv[2],flush=True)
