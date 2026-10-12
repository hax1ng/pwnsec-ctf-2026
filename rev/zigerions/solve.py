#!/usr/bin/env python3
"""Final Zigerions step: AES-128-ECB decrypt the flag out of the fake `svchost` ELF.

The dropped `svchost` is a data container disguised as an ELF. Its .rodata holds
the 16-byte key `M68K_AES_FLAGKEY` (symbol __3) and its .data holds a 48-byte
ciphertext (symbol __4). No IV is stored anywhere, so the mode is ECB.
"""

from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

blob = Path("svchost.bin").read_bytes()

# Key is the ASCII tag sitting at the file's fake "entry point" (__3).
key = b"M68K_AES_FLAGKEY"
assert key in blob

# Ciphertext is the 48-byte .data object (__4). It directly follows the inverse
# S-box, so we just locate it by its known first block.
ciphertext = bytes.fromhex(
    "674e0e339bc75891878e9418bb3fb91a"
    "f8fa389587016dfbe91db26b39b41c51"
    "bc8a191fbdc5ad5fb30b22aa6c0d35b3"
)
assert ciphertext in blob

plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)
print(plaintext.decode())
