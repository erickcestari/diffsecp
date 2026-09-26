#ifndef DIFFSECP_DIGEST_H
#define DIFFSECP_DIGEST_H

#include <stddef.h>
#include <stdint.h>

/* FNV-1a of a transcript, shared by replay.c and fuzz.c so digests from other
 * architectures compare with the fuzzer's. Inputs aren't adversarial to the
 * hash, so 64 bits make a collision that hides a divergence negligible. */
static uint64_t diffsecp_digest(const unsigned char *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325u;
    size_t i;

    for (i = 0; i < n; i++) {
        h = (h ^ p[i]) * 0x100000001b3u;
    }
    return h;
}

#endif /* DIFFSECP_DIGEST_H */
