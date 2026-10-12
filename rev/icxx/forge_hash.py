#!/usr/bin/env python3
import struct,random
M=(1<<64)-1
C1=0xbf58476d1ce4e5b9; C2=0x94d049bb133111eb
I1=pow(C1,-1,1<<64); I2=pow(C2,-1,1<<64)
def xs_inv(y,s):
    x=y
    for _ in range(8): x=y^(x>>s)
    return x&M
def mix(x):
    x&=M; x^=x>>30;x=x*C1&M;x^=x>>27;x=x*C2&M;x^=x>>31;return x&M
def imix(x):
    x=xs_inv(x,31);x=x*I2&M;x=xs_inv(x,27);x=x*I1&M;x=xs_inv(x,30);return x&M
def rol(x,n):
    n&=63;return ((x<<n)|(x>>(64-n)))&M if n else x&M
def tweakmix(x,j):
    x ^= x>>30; x ^= j; x=x*C1&M; x^=x>>27;x=x*C2&M;x^=x>>31;return x&M
def core(tag,msg, trace=False):
    h=mix(len(msg)^tag); lanes=[0]*8
    for i in range((len(msg)+7)//8):
        c=int.from_bytes(msg[i*8:i*8+8].ljust(8,b'\0'),'little')
        h=mix(h^i^c); j=i&7; lanes[j]=mix(lanes[j]^h)
    ts=[]; t=mix(h^tag); ts.append(t)
    for j in range(1,8):
        t=tweakmix(rol(tag,7*j)^t,j);ts.append(t)
    out=[mix(lanes[j]^ts[j]) for j in range(8)]
    if trace:return out,lanes,h,ts
    return b''.join(x.to_bytes(8,'little') for x in out)
def preimage_tail(tag, fixed16, target):
    assert len(fixed16)==16 and len(target)==64
    target=list(struct.unpack('<8Q',target))
    # message total 80 bytes -> last 8 chunks controllable
    # required pre-final lanes from target and tag-specific final t; t depends final h!
    # But final t0 depends final chain h, so cannot independently pretarget until choose final h.
    # Last wanted h (chunk9) is also chain h; solve mutual constraint by brute/fixed point? derive lane7 affected at i=7 only, lane0 at8, lane1 at9.
    raise NotImplementedError
if __name__=='__main__':
 for _ in range(100):
  x=random.randrange(1<<64);assert imix(mix(x))==x
 nonce=0x938336342979c9e4; epoch=5424251
 m1=struct.pack('<QI',nonce,epoch)
 print(core(0x41444d494e555044,m1).hex())
MASK46=(1<<46)-1
SEED=0xb7d49c21e8a6305f
GOLD=0x9e3779b97f4a7c15
def fmeta(x,nonce,epoch):
    x &= MASK46
    k=mix(SEED ^ nonce ^ ((epoch&0xffffffff)<<31))
    inc=0
    si=0
    for it in range(0x2e0):
        k=mix(k^inc)
        a=k%46
        b=rol(k,23)%45
        b += b>=a
        # CNOT bit b -> a
        x ^= ((x>>b)&1)<<a
        # obfuscated condition only true it=0
        q=((it&0xffff)*0x469f)>>19
        if ((29*q+si)&0xffff)==0:
            a2=(k>>17)%46
            b2=(k>>41)%45
            b2 += a2<=b2
            ba=(x>>a2)&1; bb=(x>>b2)&1
            if ba!=bb:x ^= (1<<a2)|(1<<b2)
        si=(si-1)&0xffffffff
        inc=(inc+GOLD)&M
    return x ^ (mix(nonce ^ (epoch&0xffffffff) ^ 0x006c6f6f6d2d3436)&MASK46)
def solve_meta(nonce,epoch):
    K=0x2d314f19a72b
    n2=rol(nonce,19);e2=epoch^0x4539a1
    def g(x):return fmeta(x,nonce,epoch)^fmeta(x^K,n2,e2)
    b=g(0); cols=[g(1<<i)^b for i in range(46)]
    # equations bit rows: sum colbit*x = bbit
    rows=[]
    for j in range(46):
        coef=sum(((cols[i]>>j)&1)<<i for i in range(46)); rhs=(b>>j)&1
        rows.append(coef|(rhs<<46))
    piv=[]; row=0
    for col in range(46):
        p=next((k for k in range(row,46) if (rows[k]>>col)&1),None)
        if p is None:continue
        rows[row],rows[p]=rows[p],rows[row]
        for k in range(46):
            if k!=row and ((rows[k]>>col)&1): rows[k]^=rows[row]
        piv.append(col);row+=1
    for k in range(row,46):
        if (rows[k]&MASK46)==0 and ((rows[k]>>46)&1):raise ValueError('no sol')
    x=0
    for r,col in enumerate(piv): x|=((rows[r]>>46)&1)<<col
    assert g(x)==0
    return x,fmeta(x,nonce,epoch)

def solve_zero_meta(nonce,epoch):
    """Invert the affine 46-bit coefficient generator to make alpha zero."""
    b=fmeta(0,nonce,epoch)
    cols=[fmeta(1<<i,nonce,epoch)^b for i in range(46)]
    rows=[]
    for j in range(46):
        coef=sum(((cols[i]>>j)&1)<<i for i in range(46))
        rows.append(coef|(((b>>j)&1)<<46))
    row=0; piv=[]
    for col in range(46):
        p=next(k for k in range(row,46) if (rows[k]>>col)&1)
        rows[row],rows[p]=rows[p],rows[row]
        for k in range(46):
            if k!=row and ((rows[k]>>col)&1): rows[k]^=rows[row]
        piv.append(col); row+=1
    x=sum(((rows[r]>>46)&1)<<col for r,col in enumerate(piv))
    assert fmeta(x,nonce,epoch)==0
    return x
FR=0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
ADMIN_DOMAIN=b'ICXX\0ADMIN\0UPDATE\0'
DELEGATE_DOMAIN=b'ICXX\0DELEGATE\0SNAPSHOT\0'

def collision_payload(nonce,epoch,prefix=b'\0',target=None,H=0x123456789abcdef0):
    # Need the controlled nine chunks to start on a message-block boundary.
    assert (len(DELEGATE_DOMAIN)+16+len(prefix))%8==0
    plen=len(prefix)+72
    fixed=DELEGATE_DOMAIN+struct.pack('<QII',nonce,epoch,plen)+prefix
    assert len(fixed)%8==0
    if target is None:
        target=core(0x41444d494e555044,ADMIN_DOMAIN+struct.pack('<QI',nonce,epoch))
    assert len(target)==64
    tout=list(struct.unpack('<8Q',target))
    tag=0x44454c4547415445
    # process current fixed chunks, without finalization
    h=mix((len(fixed)+72)^tag); lanes=[0]*8
    nfix=len(fixed)//8
    for i in range(nfix):
        c=int.from_bytes(fixed[8*i:8*i+8],'little');h=mix(h^i^c);lanes[i&7]=mix(lanes[i&7]^h)
    # final t from chosen H and desired final lane states
    t=mix(H^tag);ts=[t]
    for j in range(1,8):t=tweakmix(rol(tag,7*j)^t,j);ts.append(t)
    desired=[imix(tout[j])^ts[j] for j in range(8)]
    final_i=nfix+8; final_j=final_i&7
    before=desired[:]
    before[final_j]=imix(desired[final_j])^H
    chunks=[]
    # 8 chunks set each lane exactly once because consecutive
    for i in range(nfix,nfix+8):
        j=i&7; hn=imix(before[j])^lanes[j]; c=imix(hn)^h^i
        chunks.append(struct.pack('<Q',c)); h=hn; lanes[j]=before[j]
    i=final_i;c=imix(H)^h^i;chunks.append(struct.pack('<Q',c));h=H;lanes[i&7]=mix(lanes[i&7]^H)
    payload=prefix+b''.join(chunks)
    m2=DELEGATE_DOMAIN+struct.pack('<QII',nonce,epoch,len(payload))+payload
    assert core(tag,m2)==target,(core(tag,m2).hex(),target.hex())
    return payload
