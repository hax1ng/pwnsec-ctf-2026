import hmac
import secrets
from os import getenv

from util import *


flag = getenv("FLAG", "pwnsec{????????????????????????????????????????????????}").encode()


small = [value for value in range(256) if value.bit_count() < 4]
wide = [value for value in range(256) if value.bit_count() < 5]
seed = secrets.token_bytes(16)
key = secrets.token_bytes(16)
fog = secrets.token_bytes(9)
guests = [secrets.token_bytes(24), secrets.token_bytes(24)]
admin = b"AdminSaysWEW" + seed
position = places[secrets.randbelow(len(places))]
wire = shuffle(range(256))
rows = [secrets.randbits(len(small)) for _ in range(36)]
marks = [
    mark(wire[label], small, rows)
    for label in range(256)
]
modulus = (1 << 512) - 569
wakes = []
groups = [
    list(range(24)),
    list(range(12, 36)),
    list(range(24, 36)) + list(range(12)),
]
for group in groups:
    noise = [secrets.randbits(256), secrets.randbits(256)]
    weights = [secrets.randbelow(modulus - 1) + 1 for index in range(26)]
    wake = []
    for label in range(256):
        mask = sum(
            ((marks[label] >> source) & 1) << index
            for index, source in enumerate(group)
        )
        mask |= ((noise[0] >> label) & 1) << 24
        mask |= ((noise[1] >> label) & 1) << 25
        value = sum(weights[index] for index in range(26) if (mask >> index) & 1)
        wake.append(value % modulus)
    wakes.append(wake)

print(f"seed: {seed.hex()}")
for wake in wakes:
    print("wake: " + ",".join(f"{value:0128x}" for value in wake))

for guest in guests:
    before = edge(key, fog, guest)
    scan = []
    rows = [secrets.randbits(len(wide)) for _ in range(24)]
    scar = [paint(wire[label], wide, rows) for label in range(256)]
    for label in range(256):
        state = before[:]
        state[position] ^= wire[label]
        scan.append(peek(tail(state)))
    order = shuffle(range(256))
    for label in order[:4]:
        scan[label] = b""
        scar[label] = b""
    errors = []
    for place, label in enumerate(order[4:8]):
        while 1:
            error = secrets.randbelow((1 << 24) - 1) + 1
            if rank(errors + [error]) == len(errors) + 1:
                errors.append(error)
                scar[label] = (
                    int.from_bytes(scar[label], "little") ^ error
                ).to_bytes(3, "little")
                break
        if place < 2:
            scan[label] = stray(before)
        else:
            noisy = bytearray(scan[label])
            bit = secrets.randbelow(64)
            noisy[bit // 8] ^= 1 << (bit % 8)
            scan[label] = bytes(noisy)
    print(f"guest: {guest.hex()}")
    print("scar: " + ",".join(value.hex() if value else "-" for value in scar))
    print("scan: " + ",".join(value.hex() if value else "-" for value in scan))

print("admin tag:")
try:
    answer = bytes.fromhex(input().strip())
except:
    answer = b""

expected = tag(seal(key, fog, admin))
if len(answer) == 12 and hmac.compare_digest(answer, expected):
    print(flag)
else:
    print("rejected")
