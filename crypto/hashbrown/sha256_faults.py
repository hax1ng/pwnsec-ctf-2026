from __future__ import annotations

from pathlib import Path


SHA256_SOURCE = Path(__file__).with_name("sha256.py").read_bytes()

FAULTS: dict[str, int] = {
    "base": 10704,
    "r24": 25498,
    "r44": 25497,
    "r60": 25506,
    "shift1": 14000,
    "shift2": 14001,
    "shift4": 14002,
    "shift8": 14003,
    "slice44": 14633,
    "slice60": 14642,
    "step44": 14137,
    "step24": 14138,
    "thr11": 17682,
    "thr14": 17680,
    "thr17": 17681,
    "thr35": 17673,
}


class UnknownFault(ValueError):
    pass


def fault_names() -> list[str]:
    return list(FAULTS)


def faulty_sha256_digest(message: bytes, fault_name: str) -> bytes:
    if fault_name not in FAULTS:
        raise UnknownFault(f"unknown fault: {fault_name}")

    source = bytearray(SHA256_SOURCE)
    pos = FAULTS[fault_name]
    source[pos // 8] ^= 1 << (pos % 8)

    namespace: dict[str, object] = {"__builtins__": __builtins__}
    exec(bytes(source), namespace)
    generate_hash = namespace["generate_hash"]
    return bytes(generate_hash(message))  # type: ignore[misc]
