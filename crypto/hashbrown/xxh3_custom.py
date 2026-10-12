from __future__ import annotations

import hashlib


MASK = (1 << 64) - 1

P32_1 = 0x9E3779B1
P32_2 = 0x85EBCA77
P32_3 = 0xC2B2AE3D
P64_1 = 0x9E3779B185EBCA87
P64_2 = 0xC2B2AE3D27D4EB4F
P64_3 = 0x165667B19E3779F9
P64_4 = 0x85EBCA77C2B2AE63
P64_5 = 0x27D4EB2F165667C5
PRIME_MX1 = 0x165667919E3779F9

EQUALITY_LEN = 257
FORGE_LEN = 1024
MIN_LONG_LEN = 257
MAX_LONG_LEN = 1024

INIT_ACC = [P32_3, P64_1, P64_2, P64_3, P64_4, P32_2, P64_5, P32_1]

KSECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1c"
    "ded46de9839097db7240a4a4b7b3671f"
    "cb79e64eccc0e578825ad07dccff7221"
    "b8084674f743248ee03590e6813a264c"
    "3c2852bb91c300cb88d0658b1b532ea3"
    "71644897a20df94e3819ef46a9deacd8"
    "a8fa763fe39c343ff9dcbbc7c70b4f1d"
    "8a51e04bcdb45931c89f7ec9d9787364"
    "eac5ac8334d3ebc3c581a0fffa1363eb"
    "170ddd51b7f0da49d316552629d4689e"
    "2b16be587d47a1fc8ff8b8d17ad031ce"
    "45cb3a8f95160428afd7fbcabb4b407e"
)


def u64(x: int) -> int:
    return x & MASK


def rle64(buf: bytes | bytearray, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 8], "little")


def wle64(x: int) -> bytes:
    return (x & MASK).to_bytes(8, "little")


def expand_sha256(label: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:nbytes])


def delta_words_from_key(sha_key: bytes) -> list[int]:
    delta = expand_sha256(b"xxh3-secret:" + sha_key, 24 * 8)
    return [rle64(delta, 8 * i) for i in range(24)]


def custom_secret2(seed: int, delta_words: list[int]) -> bytes:
    if len(delta_words) != 24:
        raise ValueError("delta_words must contain 24 u64 words")

    seed &= MASK
    out = bytearray(192)
    for i in range(12):
        k0 = rle64(KSECRET, 16 * i)
        k1 = rle64(KSECRET, 16 * i + 8)
        d0 = delta_words[2 * i]
        d1 = delta_words[2 * i + 1]
        out[16 * i : 16 * i + 8] = wle64(k0 + seed + d0)
        out[16 * i + 8 : 16 * i + 16] = wle64(k1 - seed + d1)
    return bytes(out)


def avalanche(x: int) -> int:
    x &= MASK
    x ^= x >> 37
    x = (x * PRIME_MX1) & MASK
    x ^= x >> 32
    return x & MASK


def fold64(a: int, b: int) -> int:
    p = (a & MASK) * (b & MASK)
    return ((p & MASK) ^ (p >> 64)) & MASK


def p32prod(x: int) -> int:
    return ((x & 0xFFFFFFFF) * (x >> 32)) & MASK


def accumulate_512(acc: list[int], stripe: bytes, secret_slice: bytes) -> None:
    for lane in range(8):
        x = rle64(stripe, 8 * lane)
        k = rle64(secret_slice, 8 * lane)
        dk = x ^ k
        acc[lane ^ 1] = (acc[lane ^ 1] + x) & MASK
        acc[lane] = (acc[lane] + p32prod(dk)) & MASK


def digest_from_acc(
    acc: list[int],
    seed: int,
    length: int,
    delta_words: list[int],
) -> bytes:
    sec = custom_secret2(seed, delta_words)
    low = (length * P64_1) & MASK
    high = (~(length * P64_2)) & MASK
    for i in range(4):
        low = (
            low
            + fold64(
                acc[2 * i] ^ rle64(sec, 11 + 16 * i),
                acc[2 * i + 1] ^ rle64(sec, 19 + 16 * i),
            )
        ) & MASK
        high = (
            high
            + fold64(
                acc[2 * i] ^ rle64(sec, 117 + 16 * i),
                acc[2 * i + 1] ^ rle64(sec, 125 + 16 * i),
            )
        ) & MASK
    return avalanche(high).to_bytes(8, "big") + avalanche(low).to_bytes(8, "big")


def custom_xxh3_128(data: bytes, seed: int, delta_words: list[int]) -> bytes:
    if not (MIN_LONG_LEN <= len(data) <= MAX_LONG_LEN):
        raise ValueError("custom model covers only 257..1024 byte inputs")

    sec = custom_secret2(seed, delta_words)
    acc = INIT_ACC[:]
    length = len(data)

    nb_stripes = (length - 1) // 64
    for stripe in range(nb_stripes):
        accumulate_512(
            acc,
            data[stripe * 64 : (stripe + 1) * 64],
            sec[stripe * 8 : stripe * 8 + 64],
        )
    accumulate_512(acc, data[-64:], sec[121:185])
    return digest_from_acc([x & MASK for x in acc], seed, length, delta_words)


def acc_for_1024_payload(data: bytes, seed: int, delta_words: list[int]) -> list[int]:
    if len(data) != FORGE_LEN:
        raise ValueError("payload must be exactly 1024 bytes")
    sec = custom_secret2(seed, delta_words)
    acc = INIT_ACC[:]
    for stripe in range(15):
        accumulate_512(
            acc,
            data[stripe * 64 : (stripe + 1) * 64],
            sec[stripe * 8 : stripe * 8 + 64],
        )
    accumulate_512(acc, data[-64:], sec[121:185])
    return [x & MASK for x in acc]


def target_digest(sha_key: bytes, seed: int) -> bytes:
    return hashlib.sha256(
        b"target:" + sha_key + (seed & MASK).to_bytes(8, "little")
    ).digest()[:16]


def unlock_token(sha_key: bytes) -> str:
    return hashlib.sha256(b"unlock:" + sha_key).hexdigest()
