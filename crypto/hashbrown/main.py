from __future__ import annotations

import argparse
import hmac
import os
import secrets
import signal
import socket
import socketserver
import string
import sys

from sha256_faults import UnknownFault, faulty_sha256_digest, fault_names
from xxh3_custom import (
    EQUALITY_LEN,
    FORGE_LEN,
    custom_xxh3_128,
    delta_words_from_key,
    target_digest,
    unlock_token,
)


KEY_PREFIX = bytes.fromhex("5b0de77c5ad3bef911a29fb17c6634f48a1f91cae7ffde9f")
SHA_KEY_LEN = 55
MAX_BATCH = 4096
ALARM_SECONDS = 900
HEX_CHARS = set(string.hexdigits)


class StopSession(Exception):
    pass


def env_hex(name: str, expected_len: int) -> bytes | None:
    value = os.environ.get(name)
    if value is None:
        return None
    if len(value) != expected_len * 2 or any(c not in HEX_CHARS for c in value):
        raise ValueError(f"{name} must be {expected_len} bytes encoded as hex")
    return bytes.fromhex(value)


class Challenge:
    def __init__(self, reader=None, writer=None) -> None:
        self.reader = reader if reader is not None else sys.stdin.buffer
        self.writer = writer if writer is not None else sys.stdout.buffer
        self.flag = os.environ.get("FLAG", "pwnsec{hashbrown_default_flag}")
        suffix = env_hex("HASHBROWN_KEY_SUFFIX_HEX", SHA_KEY_LEN - len(KEY_PREFIX))
        seed_bytes = env_hex("HASHBROWN_SEED_HEX", 8)
        self.sha_key = KEY_PREFIX + (
            suffix if suffix is not None else secrets.token_bytes(SHA_KEY_LEN - len(KEY_PREFIX))
        )
        self.seed = (
            int.from_bytes(seed_bytes, "little")
            if seed_bytes is not None
            else secrets.randbits(64)
        )
        self.delta_words = delta_words_from_key(self.sha_key)
        self.unlock_used = False

    def write(self, text: str, end: str = "\n") -> None:
        self.writer.write((text + end).encode())
        self.writer.flush()

    def read_line(self, prompt: str) -> str:
        self.write(prompt, end="")
        line = self.reader.readline()
        if not line:
            raise EOFError
        return line.decode(errors="strict").strip()

    def read_fixed_hex(self, prompt: str, expected_len: int) -> bytes | None:
        value = self.read_line(prompt)
        if len(value) != expected_len * 2 or any(c not in HEX_CHARS for c in value):
            self.write("[-] invalid hex")
            return None
        return bytes.fromhex(value)

    def fault_sha(self) -> None:
        self.write("[*] available faults: " + ", ".join(fault_names()))
        name = self.read_line("[*] fault name: ")
        try:
            digest = faulty_sha256_digest(self.sha_key, name)
        except UnknownFault:
            self.write("[-] unknown fault")
            return
        self.write("[+] digest: " + digest.hex())

    def iihash_equal_batch(self) -> None:
        raw_n = self.read_line("[*] n: ")
        try:
            n = int(raw_n, 10)
        except ValueError:
            self.write("[-] invalid n")
            return
        if not (1 <= n <= MAX_BATCH):
            self.write("[-] invalid n")
            return

        bits = []
        for idx in range(n):
            a = self.read_fixed_hex(f"[*] a[{idx}] hex: ", EQUALITY_LEN)
            if a is None:
                return
            b = self.read_fixed_hex(f"[*] b[{idx}] hex: ", EQUALITY_LEN)
            if b is None:
                return
            ha = custom_xxh3_128(a, self.seed, self.delta_words)
            hb = custom_xxh3_128(b, self.seed, self.delta_words)
            bits.append("1" if ha == hb else "0")
        self.write("[+] bits: " + "".join(bits))

    def unlock_digest(self) -> None:
        if self.unlock_used:
            self.write("[-] already used")
            return
        token = self.read_line("[*] token: ")
        if not hmac.compare_digest(token, unlock_token(self.sha_key)):
            self.write("[-] invalid token")
            return
        self.unlock_used = True
        digest = custom_xxh3_128(bytes(EQUALITY_LEN), self.seed, self.delta_words)
        self.write("[+] digest: " + digest.hex())

    def get_flag(self) -> None:
        payload = self.read_fixed_hex("[*] payload hex: ", FORGE_LEN)
        if payload is None:
            return
        digest = custom_xxh3_128(payload, self.seed, self.delta_words)
        if hmac.compare_digest(digest, target_digest(self.sha_key, self.seed)):
            self.write("[+] " + self.flag)
            raise StopSession
        self.write("[-] nope")

    def run(self) -> None:
        while True:
            self.write("1. FaultSHA")
            self.write("2. IIHashEqualBatch")
            self.write("3. UnlockDigest")
            self.write("4. GetFlag")
            self.write("5. Exit")
            choice = self.read_line("> ")
            if choice == "1":
                self.fault_sha()
            elif choice == "2":
                self.iihash_equal_batch()
            elif choice == "3":
                self.unlock_digest()
            elif choice == "4":
                self.get_flag()
            elif choice == "5":
                self.write("[*] bye")
                return
            else:
                self.write("[-] invalid choice")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(ALARM_SECONDS)
        try:
            Challenge(self.rfile, self.wfile).run()
        except (EOFError, StopSession, UnicodeDecodeError, BrokenPipeError, socket.timeout):
            return


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_stdio() -> None:
    signal.alarm(ALARM_SECONDS)
    try:
        Challenge().run()
    except StopSession:
        return


def run_server(host: str, port: int) -> None:
    with ThreadedTCPServer((host, port), Handler) as server:
        server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Hashbrown challenge service")
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "1337")))
    args = parser.parse_args()

    if args.stdio:
        run_stdio()
    else:
        run_server(args.host, args.port)


if __name__ == "__main__":
    main()
