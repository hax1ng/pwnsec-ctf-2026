#!/usr/bin/env python3
import json
MASK=(1<<64)-1

def splitmix_next(state):
    state=(state+0x9e3779b97f4a7c15)&MASK
    z=state
    z=((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK
    z=((z^(z>>27))*0x94d049bb133111eb)&MASK
    z=z^(z>>31)
    return state,z

def opcode_table(build):
    a=list(range(128))
    state=build ^ 0x00004953412d7631  # LE ASCII b"1v-ASI"
    n=128
    while n>1:
        lim=(~(MASK%n))&MASK
        while True:
            state,z=splitmix_next(state)
            if z < lim: break
        j=z%n
        a[n-1],a[j]=a[j],a[n-1]
        n-=1
    return a

def mapping(build,schema='isa.json'):
    defs=json.load(open(schema))['instructions']
    tab=opcode_table(build)
    return {tab[i]:(i,d) for i,d in enumerate(defs)}

if __name__=='__main__':
    build=0x8b0111aed0ea2462
    m=mapping(build)
    for op,(i,d) in sorted(m.items()):print(f'{op:02x}: {i:02d} {d["name"]:10s} {d["format"]}')
