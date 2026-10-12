#!/usr/bin/env sage
# Core solver: finite-difference recurrence + Cuso multivariate Coppersmith to recover u,v from eight 890-bit prefixes.
import json,sys,logging,math
from sage.all import var
import cuso

J=json.load(open(sys.argv[1]));p=J['p'];n=J['n'];k=J['k']
B=2**(n-k);X=B//2;t=J['x']
if t != list(range(8)):
    raise ValueError('the finite-difference attack requires taps 0,...,7')
C=[h*B+X for h in J['h']]
d=[var(f'd{i}') for i in range(8)]; x=var('x')
SA=[]; coeffs=[]; bounds={x:(0,p)}
for j in range(8):
    co=[0]*8
    for i in range(j,8):
        co[i]=(-1)**(7-i)*math.comb(7-j,i-j)
    coeffs.append(co)
    SA.append(sum(co[i]*C[i] for i in range(8))%p)
    bounds[d[j]]=(-sum(map(abs,co))*X-1,sum(map(abs,co))*X+1)
s=[SA[j]+d[j] for j in range(8)]
# If Xpar=-u, the normalized finite differences obey
#       (7-i) S_{i+1} = (Xpar-i) S_i.
rels=[(7-i)*s[i+1]-(x-i)*s[i]==0 for i in range(7)]
logging.basicConfig(level=logging.INFO)
roots=cuso.find_small_roots(
    rels,bounds,modulus=p,use_graph_optimization=False,
    allow_partial_solutions=True,
)
for root in roots:
    if not all(q in root for q in d):
        continue
    ss=[(SA[i]+int(root[d[i]]))%p for i in range(8)]
    if x in root:
        xx=int(root[x])%p
    else:
        xx=(7*ss[1]*pow(ss[0],-1,p))%p
    u=(-xx)%p
    # The last normalized finite difference is exactly z_7.
    v=ss[7]*((u+7)%p)%p
    if all(((v*pow((u+i)%p,-1,p))%p)>>int(n-k)==J['h'][i] for i in range(8)):
        print(json.dumps({'u':u,'v':v,'d':[int(root[q]) for q in d]}))
        sys.exit(0)
raise RuntimeError('no verified root')
