/* decrypt_host: verify main.exe's 40-byte trailer (FNV + avalanche checks) and
 * decrypt the appended outer host archive with its keystream.
 * usage: ./decrypt_host main.exe decrypted_host.bin */
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

static inline uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31;
    return n ? (x << n) | (x >> (32 - n)) : x;
}

static inline uint32_t ror32(uint32_t x, unsigned n) {
    n &= 31;
    return n ? (x >> n) | (x << (32 - n)) : x;
}

static inline uint32_t avalanche(uint32_t x) {
    x = (x ^ (x >> 16)) * UINT32_C(0x7feb352d);
    x = (x ^ (x >> 15)) * UINT32_C(0x846ca68b);
    return x ^ (x >> 16);
}

static uint32_t fnv1a(const uint8_t *p, uint64_t n) {
    uint32_t h = UINT32_C(0x811c9dc5);
    for (uint64_t i = 0; i < n; ++i)
        h = (h ^ p[i]) * UINT32_C(0x01000193);
    return h;
}

static uint32_t get32(const uint8_t *p) {
    uint32_t x;
    memcpy(&x, p, sizeof(x));
    return x;
}

static uint64_t get64(const uint8_t *p) {
    uint64_t x;
    memcpy(&x, p, sizeof(x));
    return x;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s main.exe decrypted_host.bin\n", argv[0]);
        return 2;
    }
    int in_fd = open(argv[1], O_RDONLY);
    if (in_fd < 0) { perror("open input"); return 1; }
    struct stat st;
    if (fstat(in_fd, &st) || st.st_size < 40) { perror("fstat/input"); return 1; }
    uint64_t size = (uint64_t)st.st_size;
    const uint8_t *in = mmap(NULL, size, PROT_READ, MAP_PRIVATE, in_fd, 0);
    if (in == MAP_FAILED) { perror("mmap input"); return 1; }

    const uint8_t *t = in + size - 40;
    uint64_t payload_len = get64(t);
    uint32_t r15 = get32(t + 8);
    uint32_t expected1 = get32(t + 12);
    uint32_t r14 = get32(t + 16);
    uint32_t expected2 = get32(t + 20);
    if (payload_len > size - 40) {
        fprintf(stderr, "invalid payload length\n"); return 1;
    }
    uint64_t payload_off = size - 40 - payload_len;
    const uint8_t *enc = in + payload_off;
    uint32_t prefix_hash = fnv1a(in, payload_off);
    uint32_t payload_hash = fnv1a(enc, payload_len);
    uint32_t check1 = avalanche(ror32((uint32_t)(payload_len >> 32), 21)
                                ^ ror32(r14, 29)
                                ^ (uint32_t)payload_len ^ payload_hash
                                ^ prefix_hash ^ r15 ^ UINT32_C(0x4e6f5a21));
    uint32_t check2 = avalanche(prefix_hash ^ r14 ^ expected1 ^ r15
                                ^ UINT32_C(0xbb67ae85));
    fprintf(stderr,
            "size=%" PRIu64 " payload_off=%#" PRIx64 " payload_len=%" PRIu64 "\n"
            "r15=%08x expected1=%08x r14=%08x expected2=%08x\n"
            "prefix_fnv=%08x payload_fnv=%08x check1=%08x check2=%08x\n",
            size, payload_off, payload_len, r15, expected1, r14, expected2,
            prefix_hash, payload_hash, check1, check2);
    if (check1 != expected1 || check2 != expected2) {
        fprintf(stderr, "trailer verification failed\n"); return 1;
    }

    int out_fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) { perror("open output"); return 1; }
    if (ftruncate(out_fd, (off_t)payload_len)) { perror("ftruncate"); return 1; }
    uint8_t *out = mmap(NULL, payload_len, PROT_READ | PROT_WRITE, MAP_SHARED, out_fd, 0);
    if (out == MAP_FAILED) { perror("mmap output"); return 1; }

    uint32_t state = avalanche(ror32(r14, 23) ^ prefix_hash ^ r15
                               ^ UINT32_C(0xe9d7a531));
    for (uint64_t j = 0; j < payload_len; ++j) {
        uint32_t jj = (uint32_t)j;
        uint32_t v = rol32(jj + r15, (unsigned)(jj + 5))
                   ^ rol32(r14, (unsigned)(jj - 15))
                   ^ rol32(prefix_hash, (unsigned)(jj + 13))
                   ^ jj * UINT32_C(0x045d9f3b) ^ state;
        state = avalanche(v);
        out[j] = enc[j] ^ (uint8_t)(state >> ((jj & 3) * 8))
                        ^ (uint8_t)(jj * UINT32_C(0x61) + (uint8_t)r14 + 0x5d);
    }
    if (msync(out, payload_len, MS_SYNC)) perror("msync");
    fprintf(stderr, "decrypted final_state=%08x first16=", state);
    for (unsigned i = 0; i < 16 && i < payload_len; ++i) fprintf(stderr, "%02x", out[i]);
    fputc('\n', stderr);
    munmap(out, payload_len); close(out_fd); munmap((void *)in, size); close(in_fd);
    return 0;
}
