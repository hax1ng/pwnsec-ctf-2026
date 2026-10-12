# Layer 2 extractor: unscramble the PyInstaller stub payload out of update.exe
# (find marker -> read LE size -> XOR with repeating key -> reverse) => layer2.exe
from pathlib import Path
import struct
src=Path('update.exe').read_bytes(); mark=b'<<<PAYLOAD_START>>>'; rest=src.split(mark,1)[1]
n=struct.unpack('<I',rest[:4])[0]
print('len',hex(n),n,'available',len(rest)-4)
s=rest[4:4+n]
k=[0xa5,0x3c,0xff,0,0x55,0xaa]
p=bytes(b^k[i%6] for i,b in enumerate(s))[::-1]
Path('layer2.exe').write_bytes(p)
print(p[:64],len(p))
