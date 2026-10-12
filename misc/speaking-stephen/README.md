# Speaking Stephen

**Category:** Misc | **Difficulty:** Hard | **Points:** 203 | **Flag:** `pwnsec{FB4A693729A5CB9B}`

## Challenge Description

> Can you make Stephen say what you want him to say?
>
> **- @habema**

## Initial Analysis

The site is a little voice toy. You upload (or record) some audio and "Stephen" answers in a synthetic voice. Upload someone saying *"Hello there,"* and Stephen replies with a synthetic *"Hello there."* So there's a clear two-stage pipeline:

```text
our audio  ->  Whisper tiny.en (speech-to-text)  ->  transcript  ->  espeak-ng (text-to-speech)  ->  Stephen's WAV
```

The Info tab spells out both halves:

```text
Model: tiny.en
TTS: espeak-ng
```

and the OpenAPI doc exposes the endpoint we care about:

```text
POST /transcribe     # takes an uploaded `file`, can return audio or JSON (base64 WAV)
```

Two clues make the whole challenge click:

1. **eSpeak is in SSML mode.** One of the page's examples transcribes to:
   ```xml
   Hello <break time="1s"/> everyone.
   ```
   and Stephen actually *pauses* instead of pronouncing the tag. If the transcript were treated as plain text, he'd read "less than break...". The pause proves eSpeak is being run with SSML/markup parsing enabled (its `-m` flag). SSML is basically "HTML for speech" — and it includes an `<audio src="...">` element that tells eSpeak to open a file and splice it into the output.

2. **The flag is already a WAV on disk.** The Info tab links an `entrypoint.sh` snippet (kept here as [`entrypoint-snippet.txt`](entrypoint-snippet.txt)):
   ```sh
   printf '<speak><say-as interpret-as="characters">%s</say-as></speak>' "${FLAG:?}" \
     | espeak-ng -m -s 110 -v en-us --stdin -w "$ICONDIR/flag.wav"
   ```
   On startup the server reads `$FLAG`, has eSpeak speak it **one character at a time**, and saves it as `flag.wav` inside eSpeak's sound-icon directory. The flag is sitting right there as audio — we just need to make Stephen play it back.

## The Vulnerability / Core Concept

The dangerous boundary is where **machine-generated text (Whisper's transcript) is trusted as executable speech markup (SSML) by eSpeak**. If we can get Whisper to emit a literal `<audio src="...">` tag, eSpeak will dutifully open that file and embed it in Stephen's reply:

```xml
<audio src="/usr/lib/x86_64-linux-gnu/espeak-ng-data/soundicons/flag.wav">
```

The catch — and the reason this is rated Hard — is making Whisper output *exact punctuation*. If you just record yourself saying "less than, audio, source, equals, flag dot wav, greater than," Whisper transcribes the **English words**, not the symbols `<`, `=`, `/`, `>`. There's no natural sound that reliably forces those characters out.

The fix: because the model (`tiny.en`) is public, we treat it like any other differentiable model and craft an **adversarial audio example** — the audio equivalent of nudging an image until a classifier calls it a cat, except here we optimize the waveform until Whisper *prints the exact tag we want*.

## Exploitation

### 1. Optimize an adversarial WAV against tiny.en

[`adversarial_whisper.py`](adversarial_whisper.py) loads the real `tiny.en` weights, freezes them, and makes the **waveform itself** the trainable parameter. It backpropagates a cross-entropy loss between Whisper's predicted tokens and our target token IDs:

```python
per_token = F.cross_entropy(chosen, target, reduction='none')
return per_token.mean() + 0.75 * per_token.max(), chosen, target
```

That `+ 0.75 * per_token.max()` term is important: a low *mean* loss can still hide one wrong token (a stray slash or quote), and greedy decoding then diverges. Explicitly punishing the **worst token** forces every single character across the argmax margin. The loop also optimizes both of Whisper's decoding modes — timestamped and `without_timestamps` — so the tag survives whichever path the server uses:

```python
lts, chosen, target = seq_loss(x, prefix_ts, desired_ts)   # timestamped
lnt, _, _            = seq_loss(x, prefix_nt, desired_nt)   # without_timestamps
loss = lts + 0.35 * lnt + reg
```

The real success check isn't "loss is small" — it's re-decoding the saved WAV and confirming the text literally matches:

```python
o = whisper.DecodingOptions(language='en', task='transcribe',
                            without_timestamps=True, suppress_tokens='')
model.decode(mel, o)   # must print the exact <audio ...> tag
```

Start with the short tag to prove the concept, then extend the `--target` to the full absolute path:

```sh
# prove injection works
python3 adversarial_whisper.py --target ' <audio src=flag.wav>' --output adv.wav
# then the real payload (full path to eSpeak's sound-icon dir)
python3 adversarial_whisper.py \
  --target ' <audio src="/usr/lib/x86_64-linux-gnu/espeak-ng-data/soundicons/flag.wav">' \
  --output adv.wav
```

(This optimization is GPU work — it was run on a CUDA box, not the local VM.)

### 2. Find the right path

Using just `flag.wav` made eSpeak *process* the tag but return a tiny ~352-byte silent WAV — the injection fired, but the relative filename wasn't found. On a Debian x86-64 box eSpeak keeps its sound icons under `/usr/lib/x86_64-linux-gnu/espeak-ng-data/soundicons/`, so extending the target to that absolute path is what made it resolve. eSpeak's permissive parser doesn't care about the spaces around `=` or the missing `</audio>`.

### 3. Deliver and capture

[`request_test.py`](request_test.py) uploads the adversarial WAV to `/transcribe`, asks for JSON, and decodes the returned base64 WAV:

```sh
python3 request_test.py -f adv.wav -o flag_response
```

The size jump was the obvious success signal: **352 bytes of silence** before the correct path, and a **433,056-byte / ~9.8-second WAV** once eSpeak embedded the real `flag.wav`.

### 4. Read the stolen recording

The returned WAV is the flag spoken character-by-character. Running it back through ASR gives:

```text
P W N S E C left brace F B 4 A 6 9 3 7 2 9 A 5 C B 9 B right brace
```

ASR prints spoken letters in uppercase; the event's platform metadata fixes the prefix as lowercase `pwnsec`, so the assembled flag is below.

## Flag

```
pwnsec{FB4A693729A5CB9B}
```

## Key Takeaways

- **Follow the whole data flow.** The upload feature wasn't the bug; the bug was Whisper's output being trusted as SSML by eSpeak. SSML `<audio src="...">` is a local-file-read primitive.
- **Public model = adversarial model.** When a service tells you exactly which model it runs (`tiny.en`), you can run it locally and optimize inputs to force a chosen output — same idea as adversarial images, applied to audio.
- **Optimize the worst token, not just the average.** For a targeted transcription attack, mean loss lies; one wrong character breaks greedy decoding. Weight `per_token.max()` and verify by actually re-decoding.
- Dead ends worth skipping next time: literally *saying* the tag out loud, requesting `/flag.wav` or `/static/` directly (404), and FFmpeg playlist/concat tricks — attacking the transcript was the real path.
