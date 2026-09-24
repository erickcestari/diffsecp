/* One build of libsecp256k1 plus every target, as a single translation unit so the
 * targets can reach static internals. The Makefile compiles this once per variant
 * and then localizes all libsecp symbols, leaving diffsecp_variant_<name> as the
 * only global so variants link side by side. */

#ifndef DIFFSECP_VARIANT
#error "DIFFSECP_VARIANT must be set to the variant name"
#endif

#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1

#include "src/secp256k1.c"
#include "src/precomputed_ecmult.c"
#include "src/precomputed_ecmult_gen.c"
#include "contrib/lax_der_parsing.c"

#include "diffsecp.h"
#include "reader.h"
#include "transcript.h"

static secp256k1_context *variant_ctx;

static void variant_init(void) {
    /* Blinding never changes results, so a fixed seed keeps runs reproducible. */
    static const unsigned char seed[32] = "diffsecp context randomization";

    variant_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!secp256k1_context_randomize(variant_ctx, seed)) {
        abort();
    }
}

#include "targets/ecdsa.c"
#include "targets/schnorrsig.c"
#include "targets/field.c"
#include "targets/scalar.c"
#include "targets/group.c"

#ifdef DIFFSECP_SELFTEST
/* A deliberately wrong build for `make selftest`: flipping the last transcript
 * byte is the smallest divergence the harness must still report. */
#define DIFFSECP_SELFTEST_WRAP(t) \
    static size_t selftest_##t(const unsigned char *in, size_t len, unsigned char *out, size_t cap) { \
        size_t n = target_##t(in, len, out, cap); \
        if (n > 0) { \
            out[n - 1] ^= 1; \
        } \
        return n; \
    }
DIFFSECP_TARGETS(DIFFSECP_SELFTEST_WRAP)
#define DIFFSECP_INIT(t) .t = selftest_##t,
#else
#define DIFFSECP_INIT(t) .t = target_##t,
#endif

const struct diffsecp_variant DIFFSECP_CAT(diffsecp_variant_, DIFFSECP_VARIANT) = {
    .name = DIFFSECP_STR(DIFFSECP_VARIANT),
    .init = variant_init,
    DIFFSECP_TARGETS(DIFFSECP_INIT)
};
