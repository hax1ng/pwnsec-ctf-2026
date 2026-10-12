# Rebuild the C2 master key from stage3_810.bin, then walk + ratchet through the
# six C2 HTTP bodies in challenge.pcap, writing each decrypted task as c2_<frame>.dec
import pefile,hashlib,hmac,subprocess,json,zlib,struct
from Crypto.Cipher import ChaCha20
p=pefile.PE('stage3_810.bin'); IB=p.OPTIONAL_HEADER.ImageBase
get=lambda va,n:p.get_data(va-IB,n)
xk=get(0x180007000,4)
dec=lambda va,n:bytes(c^xk[i%4] for i,c in enumerate(get(va,n)))
auth=dec(0x1800071b8,13); salt1=dec(0x1800071c8,16); salt2=dec(0x1800071d8,16); marker=bytes.fromhex('c7e1f5b9d20468f6')
k1=hashlib.sha256(auth+marker+salt1).digest()[:16]
# special rolling/rotate API hash
names=[b'NtAllocateVirtualMemory',b'NtWriteVirtualMemory',b'NtProtectVirtualMemory',b'NtQueueApcThread']
def rh(s):
 x=0x5d7e9a2f
 for c in s:
  if 65<=c<=90:c+=32
  m=(x*0x21)&0xffffffff
  x=((m>>13)|(((m^c)<<19)&0xffffffff))&0xffffffff
 return x
hs=b''.join(struct.pack('<I',rh(s)) for s in names)
k2=bytes(a^b for a,b in zip(hs,salt2))
master=hmac.new(k1+k2,b'SBv4 transcript root',hashlib.sha256).digest()
print('auth',auth,'marker',marker.hex(),'salt1',salt1.hex(),'salt2',salt2.hex())
print('hashes', [hex(rh(x)) for x in names],hs.hex()); print('k1',k1.hex(),'k2',k2.hex(),'master',master.hex())
# extract frame bodies
frames=[380,443,459,529,540,567]
out=subprocess.check_output(['tshark','-r','challenge.pcap','-Y',' || '.join('frame.number==%d'%x for x in frames),'-T','fields','-E','separator=|','-e','frame.number','-e','http.file_data'],text=True)
packets={int(line.split('|')[0]):bytes.fromhex(line.split('|')[1].strip()) for line in out.splitlines() if '|' in line}
prev=b'\0'*16
counter=0
for frame in frames:
 d=packets[frame]; typ=d[4]; ctr=struct.unpack('<I',d[5:9])[0]; prev8=d[9:17]; nonce=d[17:29]; ct=d[29:-16]; tag=d[-16:]
 direction=b'S' if typ==2 else b'C'
 record=hmac.new(master,b'record-key'+direction+d[:29],hashlib.sha256).digest()
 cipher=ChaCha20.new(key=record,nonce=nonce); cipher.seek(64); pt=cipher.decrypt(ct)
 print('\nFRAME',frame,'type',typ,'ctr',ctr,'prev',prev8.hex(),'nonce',nonce.hex(),'ctlen',len(ct),'tag',tag.hex(),'record',record.hex())
 print('PT',repr(pt[:200]))
 try:
  uz=zlib.decompress(pt); print('ZLIB',len(uz),repr(uz[:500])); open('c2_%d.dec'%frame,'wb').write(uz)
 except Exception as e: print('not zlib',e); open('c2_%d.dec'%frame,'wb').write(pt)
 # advance: sha256(packet header + plaintext? function called before decrypt in incoming with ciphertext; outgoing after encrypt, ciphertext. So ciphertext)
 inner=hashlib.sha256(d[:29]+ct).digest()
 advmsg=b'advance'+tag+inner
 master=hmac.new(master,advmsg,hashlib.sha256).digest()
 prev=tag; counter+=1
 print('nextmaster',master.hex())
