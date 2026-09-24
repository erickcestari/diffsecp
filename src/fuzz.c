/* libFuzzer entry point for one target, chosen at compile time with
 * DIFFSECP_TARGET. Runs each input through every variant and aborts on the first
 * transcript mismatch, so libFuzzer saves the input as a reproducer. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diffsecp.h"
#include "variants.h" /* Generated from variants.mk. */

#ifndef DIFFSECP_TARGET
#error "DIFFSECP_TARGET must be set to a member of struct diffsecp_variant"
#endif

#define DECLARE(name) extern const struct diffsecp_variant diffsecp_variant_##name;
DIFFSECP_VARIANTS(DECLARE)
#undef DECLARE

#define ENTRY(name) &diffsecp_variant_##name,
static const struct diffsecp_variant *const variants[] = {DIFFSECP_VARIANTS(ENTRY)};
#undef ENTRY

#define NVARIANTS (sizeof(variants) / sizeof(variants[0]))

static unsigned char transcripts[NVARIANTS][DIFFSECP_TRANSCRIPT_MAX];
static size_t lengths[NVARIANTS];

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void dump(size_t v, size_t at) {
    size_t lo = at > 16 ? at - 16 : 0;
    size_t hi = at + 48 < lengths[v] ? at + 48 : lengths[v];
    size_t i;

    fprintf(stderr, "  %-16s [%zu, %zu):", variants[v]->name, lo, hi);
    for (i = lo; i < hi; i++) {
        fprintf(stderr, "%s%02x", i == at ? " >" : " ", transcripts[v][i]);
    }
    fputc('\n', stderr);
}

static void report_divergence(size_t v) {
    size_t n = lengths[0] < lengths[v] ? lengths[0] : lengths[v];
    size_t at = 0;

    while (at < n && transcripts[0][at] == transcripts[v][at]) {
        at++;
    }
    fprintf(stderr, "diffsecp: target %s diverges between %s and %s at byte %zu (lengths %zu, %zu)\n",
            DIFFSECP_STR(DIFFSECP_TARGET), variants[0]->name, variants[v]->name, at, lengths[0], lengths[v]);
    dump(0, at);
    dump(v, at);
    abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    size_t i;

    (void)argc;
    (void)argv;
    for (i = 0; i < NVARIANTS; i++) {
        variants[i]->init();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const unsigned char empty[1];
    size_t i;

    if (size > DIFFSECP_INPUT_MAX) {
        return -1;
    }
    /* libsecp rejects null buffers even when empty, which would trip its illegal callback. */
    if (data == NULL) {
        data = empty;
    }

    for (i = 0; i < NVARIANTS; i++) {
        lengths[i] = variants[i]->DIFFSECP_TARGET(data, size, transcripts[i], DIFFSECP_TRANSCRIPT_MAX);
    }
    for (i = 1; i < NVARIANTS; i++) {
        if (lengths[i] != lengths[0] || memcmp(transcripts[i], transcripts[0], lengths[0]) != 0) {
            report_divergence(i);
        }
    }
    return 0;
}
