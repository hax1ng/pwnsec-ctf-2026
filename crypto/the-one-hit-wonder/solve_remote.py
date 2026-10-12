#!/usr/bin/env python3
"""Collect one live instance, solve it on remote, and check it in-session."""

import json
import re
import socket
import ssl
import subprocess
import time
from pathlib import Path


HOST = "CHALLENGE_HOST"  # per-session <hex>.chal.ctf.ae assigned for the live instance
PORT = 443
HERE = Path(__file__).resolve().parent
TRANSCRIPT = HERE / "remote_transcript.bin"
INSTANCE = HERE / "remote_instance.json"
SOLVER_OUT = HERE / "remote_solver.out"
SOLVER_ERR = HERE / "remote_solver.err"


class Tube:
    def __init__(self, sock, log):
        self.sock = sock
        self.log = log
        self.buf = b""

    def recvuntil(self, marker):
        while marker not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"EOF before marker {marker!r}")
            self.buf += chunk
        end = self.buf.index(marker) + len(marker)
        data, self.buf = self.buf[:end], self.buf[end:]
        self.log.write(b"RX " + data)
        self.log.flush()
        return data

    def sendline(self, value):
        data = str(value).encode() + b"\n"
        self.log.write(b"TX " + data)
        self.log.flush()
        self.sock.sendall(data)

    def finish(self):
        data = self.buf
        self.buf = b""
        self.sock.settimeout(5)
        while True:
            try:
                chunk = self.sock.recv(65536)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            data += chunk
        self.log.write(b"RX " + data)
        self.log.flush()
        return data


def decimal(label, data):
    m = re.search(rb"(?m)^" + re.escape(label) + rb" = ([0-9]+)$", data)
    if not m:
        raise ValueError(f"could not parse {label!r} from {data!r}")
    return int(m.group(1))


def main():
    # The hostname is exact and in scope. CTF ingress certificates are not relied
    # upon for identity; SNI is still set so the router selects this instance.
    ctx = ssl._create_unverified_context()
    raw = socket.create_connection((HOST, PORT), timeout=30)
    sock = ctx.wrap_socket(raw, server_hostname=HOST)

    with TRANSCRIPT.open("wb") as log:
        io = Tube(sock, log)
        io.recvuntil(b"> ")
        io.sendline(1)
        info = io.recvuntil(b"> ")
        p = decimal(b"p", info)
        n = decimal(b"bits", info)
        k = decimal(b"keep", info)
        if (n, k) != (1536, 890):
            raise ValueError(f"unexpected parameters: n={n}, k={k}")

        taps, highs = [], []
        for t in range(8):
            io.sendline(2)
            io.recvuntil(b"x = ")
            io.sendline(t)
            answer = io.recvuntil(b"> ")
            got_t = decimal(b"t", answer)
            y = decimal(b"y", answer)
            if got_t != t:
                raise ValueError(f"tap mismatch: sent {t}, got {got_t}")
            taps.append(t)
            highs.append(y)

        instance = {"p": p, "n": n, "k": k, "x": taps, "h": highs}
        INSTANCE.write_text(json.dumps(instance) + "\n")

        # Keep this TLS session alive while the non-trivial Sage/Cuso work runs
        # on remote. A menu-log request is harmless and doubles as a liveness
        # check without consuming any additional taps.
        subprocess.run(
            ["scp", "-q", str(INSTANCE), "remote:~/remote_instance.json"],
            check=True,
        )
        proc = subprocess.Popen(
            ["ssh", "remote", "cd ~ && sage-run solve_difference.py remote_instance.json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        while True:
            try:
                proc.wait(timeout=20)
                break
            except subprocess.TimeoutExpired:
                io.sendline(3)
                io.recvuntil(b"> ")

        stdout, stderr = proc.communicate()
        SOLVER_OUT.write_bytes(stdout)
        SOLVER_ERR.write_bytes(stderr)
        if proc.returncode:
            raise RuntimeError(
                f"remote solver exited {proc.returncode}; see {SOLVER_ERR.name}"
            )

        records = []
        for line in stdout.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        if not records:
            raise RuntimeError("solver emitted no JSON result")
        u, v = int(records[-1]["u"]), int(records[-1]["v"])

        # Independent exact verification before using the challenge's one check.
        shift = n - k
        recovered = [
            (v * pow((u + t) % p, -1, p) % p) >> shift for t in taps
        ]
        if recovered != highs:
            raise RuntimeError("recovered secret does not reproduce transcript")

        io.sendline(4)
        io.recvuntil(b"a = ")
        io.sendline(u)
        io.recvuntil(b"b = ")
        io.sendline(v)
        result = io.finish()
        text = result.decode(errors="replace")
        print(text, end="")
        m = re.search(r"(?:pwnsec|flag)\{[^\r\n}]+\}", text)
        if not m:
            raise RuntimeError("check returned no flag")
        (HERE / "flag.txt").write_text(m.group(0) + "\n")
        print(f"saved verified candidate to flag.txt: {m.group(0)}")


if __name__ == "__main__":
    main()
