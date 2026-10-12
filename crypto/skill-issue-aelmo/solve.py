#!/usr/bin/env python3
"""End-to-end driver for skill issue '@'aelmo.

Run this on the compute host that has ``sage-run`` and ``flatter``.  The two
lattice reductions take most of the time; completed outputs are reused unless
``--force`` is supplied.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent


def command(argv: list[str]) -> None:
    print("[>]", " ".join(argv), flush=True)
    subprocess.run(argv, check=True)


def reduce_with_flatter(source: Path, destination: Path) -> None:
    if not shutil.which("flatter"):
        raise RuntimeError("flatter is required for the lattice reductions")
    print(f"[>] flatter < {source} > {destination}", flush=True)
    started = time.monotonic()
    with source.open("rb") as inp, destination.open("wb") as out:
        subprocess.run(["flatter"], stdin=inp, stdout=out, check=True)
    print(f"[*] flatter finished in {time.monotonic()-started:.2f}s", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("public", nargs="?", default="remote_public.json")
    ap.add_argument("prefix", nargs="?", default="remoteemb")
    ap.add_argument("--force", action="store_true", help="redo cached reductions")
    args = ap.parse_args()

    public = Path(args.public).resolve()
    prefix = Path(args.prefix).resolve()
    first_input = Path(str(prefix) + "_embedding.txt")
    first_output = Path(str(prefix) + "_flatter.txt")
    second_input = Path(str(prefix) + "_second_embedding.txt")
    second_output = Path(str(prefix) + "_second_flat.txt")
    recovered_x0 = Path(str(prefix) + "_recovered_x0.json")
    recovered_full = Path(str(prefix) + "_recovered_full.json")

    sage = shutil.which("sage-run")
    if not sage:
        raise RuntimeError("run this driver on remote, where sage-run is available")

    if args.force or not first_output.exists():
        command([
            sage,
            str(HERE / "projected_embedding.sage"),
            str(public),
            str(prefix),
            "generate",
        ])
        reduce_with_flatter(first_input, first_output)
    else:
        print("[*] reusing", first_output, flush=True)

    if args.force or not second_output.exists():
        command([sys.executable, str(HERE / "make_second_embedding.py"), str(prefix)])
        reduce_with_flatter(second_input, second_output)
    else:
        print("[*] reusing", second_output, flush=True)

    command([
        sys.executable,
        str(HERE / "recover_modulus.py"),
        str(public),
        str(prefix),
        str(recovered_x0),
    ])
    command([
        sage,
        str(HERE / "finish_recover.sage"),
        str(public),
        str(recovered_x0),
        str(recovered_full),
    ])

    result = json.loads(recovered_full.read_text())
    flag = result["flag"]
    expected_len = json.loads(public.read_text())["flag_len"]
    assert len(flag.encode()) == expected_len
    assert flag.startswith("pwnsec{") and flag.endswith("}")
    print("[FLAG]", flag)


if __name__ == "__main__":
    main()
