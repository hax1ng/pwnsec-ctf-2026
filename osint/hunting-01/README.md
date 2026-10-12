# Hunting 01

**Category:** OSINT | **Flag:** `pwnsec{17c1fde9bd6bfb56cb8764305445b2b7aa4d81405f98c0a698cd7e1bda93b549}`

## Challenge Description

> No `challenge.md` shipped with this one, so here's the shape of it from the artifacts and the questions themselves.

"Hunting" is a **nine-stage investigation** built on one incident. You're handed a Windows evidence bundle — a ~4 GB memory dump plus a KAPE-style disk collection — and each stage (`hunting-01` through `hunting-09`) asks a different question about the same attack: how the victim got infected, which programs ran, what the malware could do, where it phoned home, how it built its crypto key, and — the fun twist — what the incident responder did *while the malware was still watching*. The ninth stage is the payoff: concatenate the first eight answers and SHA-256 them to "claim your points."

What we started with:

```text
hunting-01-player.zip
artefact.zip                           (password: infected)
  artefact/KUVEE-20260819-061315.dmp   (~4 GB Windows memory dump)
  artefact/2026-08-19T053959_disk.zip  (KAPE disk artifacts: $MFT, Prefetch, registry, WER, event logs)
```

The whole story, in one line:

```text
USB drive -> fake-PDF .lnk -> ftp.exe -> cmd.exe -> renamed SumatraPDF (msg.exe)
          -> malicious uxtheme.dll -> encrypted download.dat -> hijacked WmiPrvSE.exe
```

## Initial Analysis

The starting point for nearly everything here was **Volatility 3** against the memory dump, backed up by classic disk forensics (Prefetch, the NTFS `$MFT`, Recent Items, and Windows Error Reporting). A handful of commands did most of the heavy lifting:

```bash
vol -f KUVEE-20260819-061315.dmp windows.pslist
vol -f KUVEE-20260819-061315.dmp windows.pstree
vol -f KUVEE-20260819-061315.dmp windows.cmdline
vol -f KUVEE-20260819-061315.dmp windows.filescan
vol -f KUVEE-20260819-061315.dmp windows.dumpfiles --virtaddr <file-object>
```

All malware analysis was kept **static** — the sample was recovered out of RAM and read, never run. Before diving into the questions, it helps to have the timeline straight (all UTC):

| Time (UTC) | What happened |
|---|---|
| 2026-08-19 04:47:37 | Removable drive appears as `E:` |
| 04:48:20 | Windows creates the victim's `FINANCIAL_REPORT.lnk` Recent Item |
| 04:48:21 | Edge handles `E:\FINANCIAL_REPORT.pdf` |
| 04:48:45 | `ftp.exe` runs from the malicious shortcut chain |
| 04:48:47 | `cmd.exe` runs, opens the decoy / kicks off the next stage |
| 04:48:53 | `msg.exe` (a renamed SumatraPDF) runs |
| 04:48:55 | The first hijacked `WmiPrvSE.exe` attempt crashes |
| 04:49:52 | The malicious chain runs a second time |
| 04:49:54 | The surviving `WmiPrvSE.exe`, PID 2324, is created |
| 06:13:15 | The responder's memory acquisition begins |

## The Investigation

Nine stages, walked in order.

### Stage 1 — The Infection Chain

The question wants **five MITRE ATT&CK technique IDs, in execution order**. The clues that pinned them down:

1. The lure and payload lived on removable drive `E:`.
2. The lure was a disguised shortcut ending in `.pdf.lnk` (Windows hides the `.lnk`, so it *looks* like a PDF).
3. That shortcut launched Microsoft's real `ftp.exe` with `-s:-`.
4. `-s:-` tells FTP to read commands from a local file literally named `-`. That one-character file was recovered resident in memory and contained:

```text
!start /min FICTIONAL_DOCUMENT_CONFIDENTIAL.pdf
!start /min msg.exe
quit
```

FTP's `!` prefix shells out, so this opens a decoy PDF and launches `msg.exe` — a renamed legitimate app that then side-loads the attacker's DLL from its own directory.

Mapping the chain:

| Technique | Meaning here |
|---|---|
| `T1091` | Infection arrived via removable media |
| `T1204.002` | User opened the malicious file/shortcut |
| `T1218` | A trusted Windows binary (`ftp.exe`) acted as a proxy |
| `T1059.003` | The chain used the Windows command shell |
| `T1574.002` | `msg.exe` side-loaded the attacker's DLL |

This one was *brutal* to pin down — there are more than five mappable behaviors in the chain (double-extension masquerade `T1036.007`, indirect execution `T1202`, PE injection `T1055.002`, and the ATT&CK-version ambiguity between `T1574.002` and the newer merged `T1574.001`). The blocker was never the forensics; it was guessing the author's exact five IDs out of a dozen defensible ones. Dozens of orderings were rejected before the historical side-loading ID `T1574.002` and the command-shell `T1059.003` both landing in the set turned out to be correct.

**Answer:** `T1091_T1204.002_T1218_T1059.003_T1574.002`

### Stage 2 — Patient Zero

"When was the malware first executed on Kuvee's workstation? (Unix epoch seconds)"

Windows dropped a Recent Items shortcut the instant the victim first touched the material:

```text
C:\Users\kuveeeee\AppData\Roaming\Microsoft\Windows\Recent\FINANCIAL_REPORT.lnk
```

Its creation time was `2026-08-19 04:48:20.847824 UTC`. The question wants whole epoch seconds, so drop the fraction:

```bash
date -u -d '2026-08-19 04:48:20 UTC' +%s   # -> 1787114900
```

**A genuine gotcha lives here.** The standalone stage-2 submission that the platform accepted was actually `1787089733` — the same instant expressed in the machine's **local** timezone (US Pacific, PDT/UTC-7), because the box's SYSTEM hive showed `Pacific Standard Time` and the malware's own keylog file was dated with the local date (`2026-08-18.log`). That local-time framing was the intended trap for the standalone question (0 solves / 77 wrong before it fell).

But the final stage-9 seal (the one that produces the accepted flag) uses the **UTC** epoch `1787114900`. That's the value baked into the winning hash — verified by recomputation. So depending on which you mean, stage 2's answer is either the local-time `1787089733` (standalone) or the UTC `1787114900` (used in the final concatenation). The flag below only works with the latter.

**Answer (used in the final seal):** `1787114900`  ·  **Standalone-accepted variant:** `1787089733`

### Stage 3 — Reconstructing the Chain

Now the challenge drops the ATT&CK jargon and wants the actual filenames and process lineage. Prefetch gave the execution order of the three executables:

```text
ftp.exe  ->  cmd.exe  ->  msg.exe
```

`msg.exe` wasn't the normal Windows messaging tool — its metadata and behavior marked it as a renamed **SumatraPDF 3.6.1**, a legit program tricked into loading dependencies from beside itself on `E:`. Its Prefetch record (`MSG.EXE-880C76A1.pf`) referenced all the USB-local pieces:

```text
E:\MSG.EXE   E:\UXTHEME.DLL   E:\VCRUNTIME140.DLL   E:\DOWNLOAD.DAT
```

So `uxtheme.dll` is the side-loaded loader and `download.dat` is the payload it reads. Volatility then exposed the surviving compromised process:

```text
PID 2324   PPID 10272   WmiPrvSE.exe
```

The parent (10272) had already exited, but historical GUI/TextInput state tied PID 10272 back to `E:\msg.exe`. PID 2324 also held an executable-looking private memory region with **no backing file** and several threads starting inside it — the signature of manually mapped / injected code rather than a normal WMI worker.

**Answer:** `ftp.exe_cmd.exe_msg.exe_uxtheme.dll_download.dat_WmiPrvSE.exe_2324_10272`

### Stage 4 — The Command Set

With the implant dumped out of PID 2324's suspicious VAD (SHA-256 `0b8287466bbeec75857cb54c047a072891b1a428e17b44ffadb03b0b05ec09c1`), `strings` revealed a tidy command pool. The trick was **not** to blindly count uppercase words — the same region holds status tags (`SUCCESS`, `FAILED`), notifications (`USB_INSERTED`, `USB_REMOVED`), and a response-packet tag (`SEND_PATH`). Cross-referencing the dispatcher (an inlined byte-compare loop) confirmed the 14 real operator commands:

```text
SCREENSHOOT  LISTFOLDER  UPLOAD  DOWNLOAD  INFOR  LISTPROCESS  LISTTHREAD
LISTMODULES  KILLPROCESS  SUSPENDPROCESS  RESUMEPROCESS  GETKEYLOGGER  GETFILEUSB  EXIT
```

A second trap: part of the code (file offset `0x3000`–`0x3fff`) was **paged out / zeroed** in the dump, so five commands (`DOWNLOAD`, `INFOR`, `LISTPROCESS`, `LISTTHREAD`, `LISTMODULES`) had no recoverable code xref — but their strings survived in the intact pool, and the dispatcher order matched the pool order, confirming them.

Grouping by first letter: D1, E1, G2, I1, K1, L4, R1, S2, U1 = 14 total. (First blood on this one.)

**Answer:** `14_1D_1E_2G_1I_1K_4L_1R_2S_1U`

### Stage 5 — Calling Home

The implant held one plaintext domain: `financetrade.com`. It wasn't accepted just for looking shady — disassembly proved it's the real C2. At VA `0x301223c`:

```asm
lea rcx, [financetrade.com]
call [gethostbyname]      ; resolve domain -> hostent
mov  rdx, [rax+0x18]      ; h_addr_list
movsx r8, [rax+0x12]      ; h_length
mov  rdx, [rdx]           ; h_addr_list[0] = resolved C2 IP
```

There's no hardcoded C2 IP — the endpoint comes straight from DNS resolution of the domain. The separate `127.0.0.1` string belongs to an unrelated local-socket path, not the C2. (First blood.)

**Answer:** `financetrade.com`

### Stage 6 — Key Material

This was the hardest stage, and the most *OSINT-flavored* of the whole group. A tempting `mysecretkey` string sits in the implant, but following the crypto code shows it's a decoy with no code reference. What the malware actually does:

1. Fetch a fixed GitHub raw URL over WinHTTP:
   ```text
   https://raw.githubusercontent.com/tdeit/key/refs/heads/main/key
   ```
2. SHA-256 the HTTP **response body**.
3. Use that 32-byte digest as the RC4 key.

The challenge wants the **original response body** — not the digest, not the ciphertext. Problem: the body was wiped from the heap after hashing, the page it would've lived on was **paged out** (and no `pagefile.sys` was collected), and the GitHub repo `tdeit/key` had since been deleted (404, no Wayback capture, no GH-Archive event). The surviving response header said `Content-Length: 44`, but the 44 bytes sitting after it in memory turned out to be a reused buffer full of Microsoft certificate-list (CTL) data — confirmed via GitHub's content-deterministic raw ETag not matching. Weeks of memory carving were a dead end.

The escape hatch was the organizer's hint about **online malware-analysis platforms**. Searching public **ANY.RUN** submissions for that exact raw GitHub URL surfaced a retained task from when the file still existed:

```text
ANY.RUN task: 980cd09d-95f0-412c-af15-85b0b1f0ce1d  (submitted 2026-08-13)
```

Its saved desktop **screenshot** showed the deleted file's content in plain sight:

```text
https://www.youtube.com/watch?v=W4UeUJA9wLU
```

That URL is 43 visible bytes; the `Content-Length: 44` is just the source file's trailing newline. The platform accepted the visible value without the newline. (First blood — 0 global solves before this.)

**Answer:** `https://www.youtube.com/watch?v=W4UeUJA9wLU`

### Stage 7 — Watching the Watchers

The implant was also a keylogger, and its activity log was still open when RAM was captured. `windows.filescan` located the file object:

```text
C:\Users\kuveeeee\AppData\Local\Temp\Microsoft\Network\logs\2026-08-18.log
```

Dumping its cached contents showed the incident responder's own keystrokes being logged back at them:

```text
[KAPE - File Explorer]          Time: 22:35:07   ... cmd[ENTER]
[C:\Windows\System32\cmd.exe]   Time: 22:35:11
[Search]                        Time: 22:35:18   cmd ... right click ...
[Administrator: Command Prompt] Time: 22:35:35
```

The shell at `22:35:11` was a normal (non-elevated) prompt. The first window title that explicitly says **`Administrator`** — i.e. the first elevated shell — is at `22:35:35`. (First blood.)

**Answer:** `22:35:35`

### Stage 8 — Over the Responder's Shoulder

Reading further down that same stolen keylog, the responder finishes the KAPE disk collection and then browses into a second toolkit:

```text
[Comae-Toolkit-v20230117 - File Explorer]  Time: 23:13:05
```

Followed by navigation into its `x64` directory. That toolkit ships **DumpIt**, which fits the memory dump acquired at `06:13:15 UTC`. (First blood.)

**Answer:** `Comae-Toolkit-v20230117`

### Stage 9 — Claim Your Points

The finale is simple in theory and unforgiving in practice: **concatenate answers 1–8 with nothing between them, then SHA-256 the result.** One mistyped timestamp or capital letter and the whole hash changes.

```python
import hashlib

answers = [
    "T1091_T1204.002_T1218_T1059.003_T1574.002",
    "1787114900",
    "ftp.exe_cmd.exe_msg.exe_uxtheme.dll_download.dat_WmiPrvSE.exe_2324_10272",
    "14_1D_1E_2G_1I_1K_4L_1R_2S_1U",
    "financetrade.com",
    "https://www.youtube.com/watch?v=W4UeUJA9wLU",
    "22:35:35",
    "Comae-Toolkit-v20230117",
]

digest = hashlib.sha256("".join(answers).encode("utf-8")).hexdigest()
print(digest)
# 17c1fde9bd6bfb56cb8764305445b2b7aa4d81405f98c0a698cd7e1bda93b549
```

Note the stage-2 value used here is the **UTC** epoch `1787114900` — swapping in the local-time `1787089733` yields a completely different (wrong) hash.

**Answer:** `pwnsec{17c1fde9bd6bfb56cb8764305445b2b7aa4d81405f98c0a698cd7e1bda93b549}`

## Flag

```text
pwnsec{17c1fde9bd6bfb56cb8764305445b2b7aa4d81405f98c0a698cd7e1bda93b549}
```

## Key Takeaways

- **Recent Items + Prefetch answer "when" and "in what order."** They're the fastest way to time-order an execution chain.
- **A legit filename doesn't make a process legit.** `ftp.exe`, `uxtheme.dll`, and a renamed SumatraPDF (`msg.exe`) were all trusted binaries abused as proxies and loaders. A process tree *plus* private executable memory with no backing file is far stronger evidence of injection than either clue alone.
- **Watch for intended traps in forensic math.** The timezone trap in stage 2 (local Pacific vs UTC) and the paged-out command bytes in stage 4 both punish anyone who takes the first obvious reading. Note that even the challenge itself was inconsistent: the standalone stage-2 answer was the *local* epoch, but the stage-9 seal demanded the *UTC* epoch.
- **When RAM has nothing left, pivot to OSINT.** The key-material body was genuinely unrecoverable from the dump (wiped heap, paged-out body, no `pagefile.sys`, deleted repo). The solve came from public **ANY.RUN** sandbox history, whose retained screenshot preserved the file's content long after the GitHub repo was deleted. Public malware-analysis platforms are an OSINT goldmine for content that no longer exists locally.
- **GitHub's raw ETag is a content-deterministic equality oracle.** It can confirm or reject a candidate file body byte-for-byte without burning a flag submission — handy for validating recovered bytes.
- **Keep your exact accepted answers.** A chained hash means one wrong character anywhere silently breaks the final flag.
