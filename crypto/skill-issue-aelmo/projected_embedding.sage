#!/usr/bin/env sage-run
"""Fast alternative: find the projected integer orthogonal lattice by embedding."""
from sage.all import *
import json,sys,time,hashlib,subprocess,re,os
n=16
fn=sys.argv[1] if len(sys.argv)>1 else "local_public.json"
prefix=sys.argv[2] if len(sys.argv)>2 else "emb"
pub=json.load(open(fn)); a=pub["cap"]
C=matrix(ZZ,n,n,[a[i*48+j] for i in range(n) for j in range(n)])
must=set(i*n+i for i in range(n));must.update(range(n))
for j in range(4):must.update(k*n+j for k in range(n))
rest=[i for i in range(n*n) if i not in must]
rest.sort(key=lambda i:hashlib.sha256((pub["seed"]+":"+str(i)).encode()).digest())
inds=sorted(must|set(rest[:152-len(must)])); N=len(inds)
json.dump([int(i) for i in inds],open(prefix+"_indices.json","w"))
P=identity_matrix(ZZ,n); vs=[]
for k in range(n):vs.append([P.list()[i] for i in inds]);P=P*C
V=matrix(ZZ,vs); assert V.rank()==n
Q=ZZ(1)<<5000
B=[]
for i in range(N):
    B.append([ZZ(i==j) for j in range(N)]+[Q*V[k,i] for k in range(n)])
lat=prefix+"_embedding.txt"
with open(lat,"w") as f:
    f.write("["+"\n".join("["+" ".join(map(str,r))+"]" for r in B)+"]\n")
print("[*] wrote embedding",N,"x",N+n,flush=True)
if len(sys.argv)>3 and sys.argv[3] == "generate":
    print("[*] generation-only mode", flush=True)
    # Sage's loader catches SystemExit and returns status 1, so terminate the
    # generation-only subprocess directly after flushing the file and output.
    os._exit(0)
t=time.time()
o=subprocess.check_output(["/usr/bin/fplll","-a","lll","-m","wrapper",lat],text=True)
print("[*] fplll",time.time()-t,"s",flush=True)
R=[]
for line in o.splitlines():
    z=[ZZ(x) for x in re.findall(r"-?\d+",line)]
    if z:R.append(z)
ker=[vector(ZZ,r[:N]) for r in R if len(r)==N+n and all(x==0 for x in r[N:])]
print("[*] exact embedded kernel rows",len(ker),flush=True)
K=matrix(ZZ,ker); assert K.nrows()==N-n
with open(prefix+"_orthogonal.txt","w") as f:
    for r in K.rows():f.write(" ".join(map(str,r))+"\n")
nb=[ZZ(r*r).nbits() for r in K.rows()]
print("[*] norm2 bits",nb[:8],nb[-12:],flush=True)
drop=max(range(K.nrows()),key=lambda i:K[i]*K[i])
short=matrix(ZZ,[K[i] for i in range(K.nrows()) if i!=drop])
print("[*] drop",drop,"short rank",short.rank(),flush=True)
t=time.time();S=short.right_kernel_matrix();print("[*] second kernel",S.dimensions(),time.time()-t,flush=True)
T=S.LLL(delta=.99,algorithm="fpLLL:proved")
with open(prefix+"_augmented.txt","w") as f:
    for r in T.rows():f.write(" ".join(map(str,r))+"\n")
for i,r in enumerate(T.rows()): print("candidate",i,"norm2bits",ZZ(r*r).nbits(),"maxbits",max(abs(x).nbits() for x in r),"max",max(abs(x) for x in r),flush=True)
if fn.startswith("local"):
 sec=json.load(open("local_secret.json"));p=ZZ(sec["p"]);Av=vector(ZZ,[sec["x_signed"][0][i] for i in inds])
 for i,r in enumerate(K.rows()):
  z=r*Av;assert z%p==0
  if i<4 or i>=K.nrows()-8:print("ortho",i,0 if z==0 else abs(z).nbits(),z//p)
 print("exact count",sum(r*Av==0 for r in K.rows()))
 for i,r in enumerate(T.rows()):
  rel=None
  for jj,idx in enumerate(inds):
   if idx//n!=idx%n and Av[jj] and r[jj]%Av[jj]==0:
    al=r[jj]//Av[jj]; dif=[r[q]-al*Av[q] for q in range(N)]
    if all(dif[q]==0 for q,ix in enumerate(inds) if ix//n!=ix%n):
     dg=[dif[q] for q,ix in enumerate(inds) if ix//n==ix%n]
     if len(set(dg))==1:rel=(al,dg[0]);break
  print("relation",i,rel)
