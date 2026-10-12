# Stage 2: use scar RM(3,8) syndromes to locate the damaged scans and list the 6 gross-error pair guesses.
import json,sys,itertools
D=json.load(open(sys.argv[1]))
def ins(B,x):
 while x:
  p=x.bit_length()-1
  if p in B:x^=B[p]
  else:B[p]=x;return True
 return False
def inside(B,x):
 while x:
  p=x.bit_length()-1
  if p not in B:return False
  x^=B[p]
 return True
def rank(rows):b={};return sum(ins(b,x) for x in rows)
def nullspace(rows,n=9):
 piv={}
 for row in rows:
  y=row
  while y:
   p=y.bit_length()-1
   if p in piv:y^=piv[p]
   else:piv[p]=y;break
 out=[]
 for f in range(n):
  if f in piv:continue
  x=1<<f
  for p in sorted(piv):
   if (piv[p]&x).bit_count()&1:x|=1<<p
  out.append(x)
 return out
small=[x for x in range(256) if x.bit_count()<4]
def shape(y):return sum(1<<i for i,c in enumerate(small) if c&~y==0)
HC=[shape(y) for y in D['coords']]
for gi,scar in enumerate(D['scars']):
 syn=[]
 for bit in range(24):
  s=0
  for i,z in enumerate(scar):
   if z!='-' and int.from_bytes(bytes.fromhex(z),'little')>>bit&1:s^=HC[i]
  syn.append(s)
 B={}
 for s in syn:ins(B,s)
 bad=[i for i,h in enumerate(HC) if inside(B,h)];eras=[i for i,z in enumerate(scar) if z=='-'];extra=[i for i in bad if i not in eras]
 print('guest',gi,'bad',bad,'eras',eras,'extra',extra)
 for gross2 in itertools.combinations(extra,2):
  gross=eras+list(gross2);noise=[x for x in extra if x not in gross2];H=nullspace([1|(D['coords'][x]<<1) for x in gross]);evals=[]
  for h in H:evals.append(tuple((h&1)^(((h>>1)&D['coords'][p]).bit_count()&1) for p in noise))
  erank=rank([sum(b<<i for i,b in enumerate(e)) for e in evals]) # transpose rank not exactly but same
  exactdim=len(H)-erank
  print(' ',gross2,'H',len(H),'noise-rank',erank,'exactdim',exactdim)
