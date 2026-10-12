#!/usr/bin/env python3
"""ICX 23-bit logical <-> 24-bit phase/address-dependent physical word codec."""
PERMS=((0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0))

def _perm_index(address:int, phase:int)->int:
    x=((address>>8) ^ (address>>16) ^ phase ^ address ^ 0xa7) & 0xff
    x=((x<<3)&0xff) ^ x
    x=(x>>5) ^ x
    x=((x<<1)&0xff) ^ x
    # reciprocal sequence in native code computes x % 6
    q=(((x*0xab)>>9)&~1)*3
    return (x-q)&0xff

def _parity23(value:int)->int:
    return (value & 0x7fffff).bit_count() & 1

def parity(value:int,address:int,phase:int)->int:
    return (_parity23(value) ^ (address>>7) ^ (address>>15) ^ address ^ phase) & 1

def encode(value:int,address:int,phase:int)->bytes:
    value &= 0x7fffff
    physical=value | (parity(value,address,phase)<<23)
    raw=physical.to_bytes(3,'little')
    p=PERMS[_perm_index(address,phase)]
    # Native encoder emits logical bytes in the permutation-table order.
    return bytes(raw[i] for i in p)

def decode(raw:bytes,address:int,phase:int,check=True)->int:
    assert len(raw)==3
    p=PERMS[_perm_index(address,phase)]
    logical=bytearray(3)
    for physical_index, logical_index in enumerate(p):
        logical[logical_index]=raw[physical_index]
    physical=int.from_bytes(logical,'little')
    value=physical&0x7fffff
    got=physical>>23
    want=parity(value,address,phase)
    if check and got != want: raise ValueError((address,want,got,raw.hex(),hex(value)))
    return value
