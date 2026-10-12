# PwnSec CTF 2026 — Writeups

Writeups, exploits, and solve scripts from **Team W4llz** for **PwnSec CTF 2026**.

| | |
|---|---|
| **Event** | PwnSec CTF 2026 |
| **Dates** | 12–13 September 2026 (Sat 10:00 EDT → Sun 10:00 EDT) |
| **Team** | W4llz |
| **Challenges documented** | 24 across 6 categories |

## Overview

PwnSec CTF 2026 was a 24-hour jeopardy-style competition spanning pwn, web,
crypto, reverse engineering, misc, and OSINT. This repository collects our
solved challenges — each in its own directory with a standalone, beginner-
friendly writeup (`README.md`) and the final working exploit / solve scripts and
the relevant challenge source.

The writeups walk through the full thought process: initial recon, the core
vulnerability or trick, and a step-by-step exploit, so they're useful whether
you played the event or are reading cold.

## Solved Challenges

### Pwn (4)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| JavaScript After Core | Elite | 260 | [writeup](pwn/javascript-after-core/README.md) |
| PHP Sandbox Escape | Hard | 158 | [writeup](pwn/php-sandbox-escape/README.md) |
| PwnSec Support | Hard | 151 | [writeup](pwn/pwnsec-support/README.md) |
| Freal World Manipulation | Medium | 122 | [writeup](pwn/freal-world-manipulation/README.md) |

### Web (3)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| Ibrahim's Tea | Elite | 500 | [writeup](web/ibrahims-tea/README.md) |
| readtwice | Hard | 280 | [writeup](web/readtwice/README.md) |
| Mouse in the House | Medium | 194 | [writeup](web/mouse-in-the-house/README.md) |

### Crypto (6)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| Hashbrown | Elite | 295 | [writeup](crypto/hashbrown/README.md) |
| The One Hit Wonder | Medium | 291 | [writeup](crypto/the-one-hit-wonder/README.md) |
| The Odyssey | Elite | 239 | [writeup](crypto/the-odyssey/README.md) |
| skill issue @aelmo | Hard | 185 | [writeup](crypto/skill-issue-aelmo/README.md) |
| Tap Tap | Medium | 122 | [writeup](crypto/tap-tap/README.md) |
| Gap Gap | Medium | 112 | [writeup](crypto/gap-gap/README.md) |

### Reversing (8)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| ICXX | Hard | 500 | [writeup](rev/icxx/README.md) |
| ICX: Regulate | Hard | 435 | [writeup](rev/icx-regulate/README.md) |
| ICX: Confusion | Medium | 316 | [writeup](rev/icx-confusion/README.md) |
| ICX: Despair | Hard | 316 | [writeup](rev/icx-despair/README.md) |
| Operation Split Horizon | Hard | 280 | [writeup](rev/operation-split-horizon/README.md) |
| Constellation | Hard | 194 | [writeup](rev/constellation/README.md) |
| Zigerions | Hard | 131 | [writeup](rev/zigerions/README.md) |
| Two Worlds, One Heart | Easy | 94 | [writeup](rev/two-worlds-one-heart/README.md) |

### Misc (2)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| jailincpython | Medium | 210 | [writeup](misc/jailincpython/README.md) |
| Speaking Stephen | Hard | 203 | [writeup](misc/speaking-stephen/README.md) |

### OSINT (1)

| Challenge | Difficulty | Points | Writeup |
|---|---|---|---|
| Hunting 01 | — | — | [writeup](osint/hunting-01/README.md) |

## Notable Solves

- **Hunting 01 (OSINT)** — a nine-stage investigation chaining a 4 GB Windows
  memory image, disk artifacts, and real-world maritime/OSINT pivots into a final
  SHA-256 "claim" flag. Captured at solve count 1 (first blood).
- **Ibrahim's Tea (Web, Elite, 500)** — not really a web challenge: a full
  V8/Chrome renderer exploit chaining two CVEs (a `sort()` type confusion for
  cage read/write, then a stale-Wasm-instance sandbox escape) into native code
  execution inside the admin bot.
- **ICXX (Rev, Hard, 500)** — a seven-link chain against a custom VM: ELF repair,
  GF(2²³) erasure recovery, HTTP smuggling, BLS12-381 metadata forgery, and an
  oracle read to leak the gate token.
- **The ICX series (Rev)** — Confusion, Despair, Regulate, and ICXX, a family of
  challenges built on the same bespoke 23/24-bit-word virtual machine.
- **JavaScript After Core (Pwn, Elite)** — a JavaScriptCore build pinned to the
  commit right before a WebKit fix; exploited the "having a bad time" butterfly
  bug to mutate an immutable JS string.

## Repository Layout

```
pwnsec-ctf-2026/
├── crypto/     # 6 challenges
├── misc/       # 2 challenges
├── osint/      # 1 challenge
├── pwn/        # 4 challenges
├── rev/        # 8 challenges
└── web/        # 3 challenges
```

Each challenge directory contains a `README.md` writeup plus the final solve
scripts / exploits and the relevant challenge source.

## Notes

- **Redaction:** per-session challenge endpoints have been replaced with
  `CHALLENGE_HOST`, and internal infrastructure details have been removed.
  Flags shown are the accepted competition flags.
- **Ownership:** challenge binaries and source files are included for
  reproducibility and remain the property of their original authors / the PwnSec
  CTF organizers. Everything else (writeups, exploits, solve scripts) is our own
  work.
