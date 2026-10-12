/* blobtool: fast mmap helper for the hundreds-of-MB chunk blobs.
 *   fnv FILE       -> print FNV-1a-32 of the whole file
 *   xor FILE KEY   -> XOR the file in place with the keyed byte pattern
 * Called by unwrap_host.py so the heavy byte ops run in C, not Python. */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *s) { perror(s); exit(1); }

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s fnv FILE | xor FILE KEY\n", argv[0]);
        return 2;
    }
    int writing = strcmp(argv[1], "xor") == 0;
    if (!writing && strcmp(argv[1], "fnv") != 0) return 2;
    int fd = open(argv[2], writing ? O_RDWR : O_RDONLY);
    if (fd < 0) die("open");
    struct stat st;
    if (fstat(fd, &st)) die("fstat");
    size_t n = (size_t)st.st_size;
    uint8_t *p = mmap(NULL, n, writing ? (PROT_READ|PROT_WRITE) : PROT_READ,
                      writing ? MAP_SHARED : MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) die("mmap");
    if (!writing) {
        uint32_t h = 0x811c9dc5u;
        for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x1000193u;
        printf("%08" PRIx32 "\n", h);
    } else {
        if (argc != 4) return 2;
        uint32_t key = (uint32_t)strtoul(argv[3], NULL, 0);
        uint8_t pattern[256];
        for (unsigned i = 0; i < 256; i++)
            pattern[i] = (uint8_t)(key >> ((i & 3) * 8)) ^
                         (uint8_t)(i * 0x49 + 0x3d) ^
                         (uint8_t)(i * 0x11 - 0x5b);
        for (size_t i = 0; i < n; i++) p[i] ^= pattern[i & 255];
        if (msync(p, n, MS_SYNC)) die("msync");
        printf("00000000\n");
    }
    munmap(p, n);
    close(fd);
    return 0;
}
