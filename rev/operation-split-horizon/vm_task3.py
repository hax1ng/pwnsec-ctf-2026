# Tiny SBVM4 interpreter: pulls the 0x7a-byte SBVM4_PROGRAM_BLOB out of the
# decompressed frame-540 COFF task (c2_540.dec) and emulates it over a 64-byte input.
import hashlib,struct
b=open('c2_540.dec','rb').read();r=b[0x2484:0x2484+0x280]; prog=r[0x1aa:0x1aa+0x7a]
def run(mem,verbose=False):
 mem=bytearray(mem)+bytearray(256-len(mem)); reg=[0]*8;pc=0;z=False;steps=0
 while pc<len(prog) and steps<4096:
  op=prog[pc]; old=pc;steps+=1
  if op==0xff:return bytes(mem[128:192]),reg
  if op==0x11:
   a=prog[pc+1];reg[a]=struct.unpack_from('<I',prog,pc+2)[0];pc+=6
  elif op in [0x12,0x21,0x22,0x23,0x24,0x25]:
   a,c=prog[pc+1:pc+3]; assert a<8 and c<8
   if op==0x12:reg[a]=reg[c]
   elif op==0x21:reg[a]=(reg[a]+reg[c])&0xffffffff
   elif op==0x22:reg[a]^=reg[c]
   elif op==0x23:reg[a]=(reg[a]*reg[c])&0xffffffff
   else:
    n=reg[c]&31
    if n: reg[a]=(((reg[a]<<n)|(reg[a]>>(32-n))) if op==0x24 else ((reg[a]>>n)|(reg[a]<<(32-n))))&0xffffffff
   pc+=3
  elif op==0x26:
   a=prog[pc+1];reg[a]&=struct.unpack_from('<I',prog,pc+2)[0];z=reg[a]==0;pc+=6
  elif op in [0x31,0x32]:
   a,c=prog[pc+1:pc+3];pos=reg[c];assert pos<=255
   if op==0x31:reg[a]=mem[pos]
   else:mem[pos]=reg[a]&255
   pc+=3
  elif op in [0x41,0x42]:
   rel=struct.unpack_from('<h',prog,pc+1)[0];pc+=3
   if op==0x42 or z:pc+=rel
   else:z=False
  elif op==0x43:
   a=prog[pc+1];rel=struct.unpack_from('<h',prog,pc+2)[0];reg[a]=(reg[a]-1)&0xffffffff;pc+=4
   if reg[a]!=0:pc+=rel
  else:raise Exception(f'op {op:x} pc{pc:x}')
  if verbose:print(old,hex(op),reg,pc)
 raise Exception(('no halt',pc,steps))
if __name__=='__main__':
 trans=bytes.fromhex('7221262e9cf8a08ba1a863ce050e8b61b0dbcd8156475cf15b8bf1ca29e8499a');env=bytes.fromhex('c154b62abb2fbd6929d9b8607c2a381b');meta=struct.pack('<I',0x22);sess=hashlib.sha256(b'a8f3b2c1-7d4e-4f5a-9b6c-1e2d3c4b5a6f').digest()[:12]
 out,reg=run(trans+env+meta+sess);print('prog',prog.hex());print('vmout',out.hex());print('regs',reg);print('context',hashlib.sha256(b'SBVM4 context'+out).hexdigest());print('route',hashlib.sha256(b'SBVM4 route'+out).hexdigest())
