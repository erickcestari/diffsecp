#ifndef DIFFSECP_READER_H
#define DIFFSECP_READER_H

#include <stddef.h>
#include <string.h>

/* Consumes fuzz input. Reads past the end yield zeros, so every input is valid. */
struct reader {
    const unsigned char *p;
    size_t left;
};

static void reader_take(struct reader *r, unsigned char *out, size_t n) {
    size_t k = n < r->left ? n : r->left;

    /* Guarded because advancing a null pointer by zero is undefined in C. */
    if (k > 0) {
        memcpy(out, r->p, k);
        r->p += k;
        r->left -= k;
    }
    memset(out + k, 0, n - k);
}

static unsigned int reader_u8(struct reader *r) {
    unsigned char b;
    reader_take(r, &b, 1);
    return b;
}

static unsigned int reader_u16(struct reader *r) {
    unsigned char b[2];
    reader_take(r, b, 2);
    return (unsigned int)b[0] << 8 | b[1];
}

static int reader_empty(const struct reader *r) {
    return r->left == 0;
}

#endif /* DIFFSECP_READER_H */
