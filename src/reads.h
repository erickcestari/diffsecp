#ifndef DIFFSECP_READS_H
#define DIFFSECP_READS_H

#include <stddef.h>
#include <stdint.h>

/* Where the reference build read each operand of at least 32 bytes in the last
 * input, which libafl/ mutates as 256-bit numbers. A read may run past the end
 * of the input, which the mutator then extends. A build with
 * -DDIFFSECP_NOTE_READS routes every read to diffsecp_note_read, which the
 * driver (src/fuzz.c or src/guest.c) defines with reads_note. The layout is
 * what libafl/common reads. */
#define DIFFSECP_READS_MAX 256

struct diffsecp_read {
    uint32_t offset;
    uint32_t len;
};

/* Defined by the driver. */
extern struct diffsecp_read diffsecp_reads[DIFFSECP_READS_MAX];
extern size_t diffsecp_nreads;

void diffsecp_note_read(const unsigned char *p, size_t n);

/* Records a read of n bytes at p, in an input that starts at base. */
static void reads_note(const unsigned char *base, const unsigned char *p, size_t n) {
    if (n >= 32 && diffsecp_nreads < DIFFSECP_READS_MAX) {
        diffsecp_reads[diffsecp_nreads].offset = (uint32_t)(p - base);
        diffsecp_reads[diffsecp_nreads].len = (uint32_t)n;
        diffsecp_nreads++;
    }
}

#endif /* DIFFSECP_READS_H */
