/* One build of libsecp256k1 as a function that libafl/qemu calls, inside QEMU
 * for another architecture and natively as the reference. Everything passes
 * through these globals, so the host needs no calling convention: it writes the
 * target and the input, runs diffsecp_guest_run and reads the transcript. The
 * integers are 32-bit little-endian on every guest libafl/qemu supports. */

#include <stdint.h>

#include "diffsecp.h"
#include "reads.h"

#ifndef DIFFSECP_VARIANT
#error "DIFFSECP_VARIANT must name the variant linked into this binary"
#endif

#define VARIANT DIFFSECP_CAT(diffsecp_variant_, DIFFSECP_VARIANT)

extern const struct diffsecp_variant VARIANT;

/* The target's position in DIFFSECP_TARGETS, as in diffsecp_guest_targets. */
uint32_t diffsecp_guest_target;
uint32_t diffsecp_guest_in_len;
unsigned char diffsecp_guest_in[DIFFSECP_INPUT_MAX];
const uint32_t diffsecp_guest_in_max = sizeof(diffsecp_guest_in);
uint32_t diffsecp_guest_out_len;
unsigned char diffsecp_guest_out[DIFFSECP_TRANSCRIPT_MAX];

#define DIFFSECP_NAME(t) #t,
const char *const diffsecp_guest_targets[] = {DIFFSECP_TARGETS(DIFFSECP_NAME)};
#undef DIFFSECP_NAME
const uint32_t diffsecp_guest_ntargets = sizeof(diffsecp_guest_targets) / sizeof(diffsecp_guest_targets[0]);

#ifdef DIFFSECP_NOTE_READS
struct diffsecp_read diffsecp_reads[DIFFSECP_READS_MAX];
size_t diffsecp_nreads;

void diffsecp_note_read(const unsigned char *p, size_t n) {
    reads_note(diffsecp_guest_in, p, n);
}
#endif

void diffsecp_guest_init(void);
void diffsecp_guest_run(void);

void diffsecp_guest_init(void) {
    VARIANT.init();
}

/* Not inlined into main, where the host breaks on its first call. */
__attribute__((noinline)) void diffsecp_guest_run(void) {
#define DIFFSECP_FN(t) VARIANT.t,
    const diffsecp_target_fn fns[] = {DIFFSECP_TARGETS(DIFFSECP_FN)};
#undef DIFFSECP_FN

#ifdef DIFFSECP_NOTE_READS
    diffsecp_nreads = 0;
#endif
    diffsecp_guest_out_len = (uint32_t)fns[diffsecp_guest_target](
        diffsecp_guest_in, diffsecp_guest_in_len, diffsecp_guest_out, sizeof(diffsecp_guest_out));
}

/* The reference links into the fuzzer, which has its own main. */
#ifndef DIFFSECP_REFERENCE
int main(void) {
    diffsecp_guest_init();
    diffsecp_guest_run();
    return 0;
}
#endif
