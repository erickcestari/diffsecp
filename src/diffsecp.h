#ifndef DIFFSECP_H
#define DIFFSECP_H

#include <stddef.h>

/* Larger inputs are rejected so every transcript fits in DIFFSECP_TRANSCRIPT_MAX. */
#define DIFFSECP_INPUT_MAX 4096
#define DIFFSECP_TRANSCRIPT_MAX (1u << 18)

/* A target runs the input against one build and writes every observable result
 * (return codes, output bytes) to out. Builds that agree produce identical
 * transcripts. Returns the transcript length. */
typedef size_t (*diffsecp_target_fn)(const unsigned char *in, size_t len,
                                     unsigned char *out, size_t cap);

/* The only global symbol a variant object exports. */
struct diffsecp_variant {
    const char *name;
    void (*init)(void);
    diffsecp_target_fn ecdsa;
    diffsecp_target_fn schnorrsig;
    diffsecp_target_fn field;
    diffsecp_target_fn scalar;
};

#endif /* DIFFSECP_H */
