# Run the SBVM4 program, HMAC-authenticate + order the 17 exfil fragments
# (11 from the HTTP cookie, 6 from DNS subdomains), rebuild the packet, decrypt.
import base64,hmac,hashlib,struct
from vm_task3 import run
key=bytes.fromhex('675b9b274437515500acb59dba9762ae327fda3f66c66a816ef6ffe8e7b6cd04')
cookie='R7v1OZ2VcO6dZbWw.pGoBpnRtm8bpuHQz.tPpm8l94kJtivhm1.0g8E4bJbWk4xrcl_.a4RMOKy86kJ4aWuW.MQezgiSG-okDnOMX.GjNgKuj7xnXiuV37.hJk9wHrqnUJKS-63.29g5vdRV9or12oXP.Fg_iEztfyTXNTquv.V7OzV3BPJ2eY'
chunks=[('cookie',base64.urlsafe_b64decode(x+'='*((-len(x))%4))) for x in cookie.split('.')]
for x in '''a5bcdc1458a6a0088f6fdc19 d85cff9989eb82394c4ec437 ca2b0ae3cf01a55a053f25dd bba466d1b17a7e4468daa58c c8477db511e573e7ee95028b 1bb2d91f73476d8656cc6e28'''.split():chunks.append(('dns',bytes.fromhex(x)))
count=17;ordered=[None]*count
for source,ch in chunks:
 hits=[]
 for idx in range(count):
  msg=b'fragment'+struct.pack('<HH',idx,count)+ch[4:]
  if hmac.new(key,msg,hashlib.sha256).digest()[:4]==ch[:4]:hits.append(idx)
 print(source,ch.hex(),'hits',hits)
 for i in hits:
  if ordered[i]:raise ValueError('dup')
  ordered[i]=ch[4:]
assert all(x is not None for x in ordered)
data=b''.join(ordered);open('exfil_reconstructed.bin','wb').write(data)
print('DATA',len(data),data.hex())
# derive context via known four fields, metadata is vault blob size 102
m=bytes.fromhex('3b989840953b10a7078710e84e9e305e153232a9f80e25e95dbbfe244ff77284');tag=bytes.fromhex('d6dc51a763f7b494cce1b5583beb459b')
trans=hashlib.sha256(b'SBv4 transcript digest'+m+tag+struct.pack('<I',5)).digest();env=bytes.fromhex('c154b62abb2fbd6929d9b8607c2a381b');meta=struct.pack('<I',102);sess=hashlib.sha256(b'a8f3b2c1-7d4e-4f5a-9b6c-1e2d3c4b5a6f').digest()[:12]
vm,_=run(trans+env+meta+sess)
context=hashlib.sha256(b'SBVM4 context'+vm).digest();route=hashlib.sha256(b'SBVM4 route'+vm).digest()
print('trans',trans.hex(),'vm',vm.hex(),'context',context.hex(),'route',route.hex(),'keyok',route==key)
# decrypt packet
from Crypto.Cipher import ChaCha20
assert data[:5]==bytes.fromhex('cf01a55a05')
nonce=data[5:17];ct=data[17:-16];mac=data[-16:]
packet_key=hashlib.sha256(context+nonce).digest()
c=ChaCha20.new(key=packet_key,nonce=nonce);c.seek(64);pt=c.decrypt(ct)
print('nonce',nonce.hex(),'ctlen',len(ct),'tag',mac.hex(),'PT',pt.hex(),repr(pt))
open('exfil_plain.bin','wb').write(pt)
