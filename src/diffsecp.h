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

/* Every target, as X(name). The Makefile's TARGETS must list the same names. */
#define DIFFSECP_TARGETS(X) X(ecdsa) X(schnorrsig) X(field) X(scalar) X(group) X(keys) \
                            X(ellswift)

/* The only global symbol a variant object exports, named diffsecp_variant_<name>. */
struct diffsecp_variant {
    const char *name;
    void (*init)(void);
#define DIFFSECP_MEMBER(t) diffsecp_target_fn t;
    DIFFSECP_TARGETS(DIFFSECP_MEMBER)
#undef DIFFSECP_MEMBER
};

#define DIFFSECP_CAT_(a, b) a##b
#define DIFFSECP_CAT(a, b) DIFFSECP_CAT_(a, b)
#define DIFFSECP_STR_(a) #a
#define DIFFSECP_STR(a) DIFFSECP_STR_(a)

#endif /* DIFFSECP_H */
