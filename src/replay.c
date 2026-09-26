/* Runs inputs through one build and prints a digest of each transcript, so builds
 * for different architectures can be compared out of process, after the fact or
 * per input by the oracle in src/oracle.h.
 *
 *   replay TARGET          reads input paths from stdin, one per line, and
 *                          prints "TARGET DIGEST PATH" for each
 *   replay -d TARGET FILE  prints the transcript of FILE as hex, for diffing a
 *                          divergence between two architectures
 *
 * Plain C with no libFuzzer, so it builds with any cross compiler. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "diffsecp.h"
#include "digest.h"

#ifndef DIFFSECP_VARIANT
#error "DIFFSECP_VARIANT must name the variant linked into this binary"
#endif

#define VARIANT DIFFSECP_CAT(diffsecp_variant_, DIFFSECP_VARIANT)

extern const struct diffsecp_variant VARIANT;

/* One byte over the limit, to tell oversized inputs from ones that fit exactly. */
static unsigned char input[DIFFSECP_INPUT_MAX + 1];
static unsigned char transcript[DIFFSECP_TRANSCRIPT_MAX];

static diffsecp_target_fn find_target(const char *name) {
#define DIFFSECP_MATCH(t) if (strcmp(name, #t) == 0) return VARIANT.t;
    DIFFSECP_TARGETS(DIFFSECP_MATCH)
#undef DIFFSECP_MATCH
    return NULL;
}

static int read_input(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    int ok;

    if (f == NULL) {
        return 0;
    }
    *len = fread(input, 1, sizeof(input), f);
    ok = !ferror(f);
    fclose(f);
    return ok;
}

static int replay_paths(const char *name, diffsecp_target_fn fn) {
    char path[4096];
    size_t n, len;
    uint64_t h;

    while (fgets(path, sizeof(path), stdin) != NULL) {
        n = strcspn(path, "\r\n");
        if (path[n] == '\0' && !feof(stdin)) {
            fprintf(stderr, "replay: path too long: %s\n", path);
            return 1;
        }
        path[n] = '\0';
        if (n == 0) {
            continue;
        }
        if (!read_input(path, &len)) {
            fprintf(stderr, "replay: cannot read %s\n", path);
            return 1;
        }
        /* The fuzzer rejects these too, so every build skips the same inputs. */
        if (len > DIFFSECP_INPUT_MAX) {
            printf("%s - %s\n", name, path);
            fflush(stdout);
            continue;
        }
        h = diffsecp_digest(transcript, fn(input, len, transcript, sizeof(transcript)));
        /* Two halves because older Windows runtimes lack a portable 64-bit format. */
        printf("%s %08lx%08lx %s\n", name, (unsigned long)(h >> 32), (unsigned long)(h & 0xffffffffu), path);
        /* Line by line, so a fuzzer can keep one replay running as an oracle. */
        fflush(stdout);
    }
    return ferror(stdin) ? 1 : 0;
}

static int dump(const char *path, diffsecp_target_fn fn) {
    size_t len, tlen, i;

    if (!read_input(path, &len) || len > DIFFSECP_INPUT_MAX) {
        fprintf(stderr, "replay: cannot read %s or it exceeds %d bytes\n", path, DIFFSECP_INPUT_MAX);
        return 1;
    }
    tlen = fn(input, len, transcript, sizeof(transcript));
    for (i = 0; i < tlen; i++) {
        printf("%02x%c", transcript[i], (i % 32 == 31 || i + 1 == tlen) ? '\n' : ' ');
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *name;
    diffsecp_target_fn fn;

#ifdef _WIN32
    /* Keep "\n" line endings so output compares byte for byte with other platforms. */
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    if (argc == 2) {
        name = argv[1];
    } else if (argc == 4 && strcmp(argv[1], "-d") == 0) {
        name = argv[2];
    } else {
        fprintf(stderr, "usage: %s TARGET < paths\n       %s -d TARGET FILE\n", argv[0], argv[0]);
        return 2;
    }
    fn = find_target(name);
    if (fn == NULL) {
        fprintf(stderr, "replay: unknown target %s\n", name);
        return 2;
    }

    VARIANT.init();
    return argc == 2 ? replay_paths(name, fn) : dump(argv[3], fn);
}
