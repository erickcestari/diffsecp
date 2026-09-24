#ifndef DIFFSECP_TRANSCRIPT_H
#define DIFFSECP_TRANSCRIPT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Append-only log of every result a target observes. */
struct transcript {
    unsigned char *buf;
    size_t cap;
    size_t len;
};

static void transcript_put(struct transcript *t, const unsigned char *p, size_t n) {
    if (n > t->cap - t->len) {
        /* Targets bound their output by DIFFSECP_INPUT_MAX; overflowing is a harness bug. */
        fprintf(stderr, "diffsecp: transcript overflow, raise DIFFSECP_TRANSCRIPT_MAX\n");
        abort();
    }
    memcpy(t->buf + t->len, p, n);
    t->len += n;
}

static void transcript_u8(struct transcript *t, unsigned int v) {
    unsigned char b = (unsigned char)v;
    transcript_put(t, &b, 1);
}

static void transcript_u32(struct transcript *t, uint32_t v) {
    unsigned char b[4];

    b[0] = (unsigned char)(v >> 24);
    b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);
    b[3] = (unsigned char)v;
    transcript_put(t, b, sizeof(b));
}

static void transcript_int(struct transcript *t, int v) {
    transcript_u32(t, (uint32_t)v);
}

#endif /* DIFFSECP_TRANSCRIPT_H */
