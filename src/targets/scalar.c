/* Scalar arithmetic driven as a register machine, reaching the internal API.
 * Operands are copied before each call so no call relies on aliasing the
 * contract leaves unspecified.
 *
 * Input: repeated [op, selector, operands...]. The selector picks the
 * destination and two source registers. */

#define SCALAR_REGS 4
#define SCALAR_MAX_OPS 1024

enum scalar_op {
    SCALAR_SET_B32,
    SCALAR_SET_B32_SECKEY,
    SCALAR_ADD,
    SCALAR_MUL,
    SCALAR_NEGATE,
    SCALAR_HALF,
    SCALAR_INVERSE,
    SCALAR_INVERSE_VAR,
    SCALAR_COND_NEGATE,
    SCALAR_CMOV,
    SCALAR_SPLIT_128,
    SCALAR_SPLIT_LAMBDA,
    SCALAR_MUL_SHIFT_VAR,
    SCALAR_QUERY,
    SCALAR_OP_COUNT
};

static void scalar_record(struct transcript *t, const secp256k1_scalar *s) {
    unsigned char b32[32];

    secp256k1_scalar_get_b32(b32, s);
    transcript_put(t, b32, sizeof(b32));
}

/* Predicates and bit extraction on a and b; leaves both untouched. */
static void scalar_query(struct transcript *t, struct reader *r,
                         const secp256k1_scalar *a, const secp256k1_scalar *b) {
    unsigned int count, offset, limb;

    transcript_int(t, secp256k1_scalar_is_zero(a));
    transcript_int(t, secp256k1_scalar_is_one(a));
    transcript_int(t, secp256k1_scalar_is_even(a));
    transcript_int(t, secp256k1_scalar_is_high(a));
    transcript_int(t, secp256k1_scalar_eq(a, b));

    /* get_bits_var needs 1 <= count <= 32 and offset + count <= 256. */
    count = 1 + reader_u8(r) % 32;
    offset = reader_u16(r) % (257 - count);
    transcript_u32(t, secp256k1_scalar_get_bits_var(a, offset, count));

    /* get_bits_limb32 additionally needs all bits within one 32-bit limb. */
    count = 1 + reader_u8(r) % 32;
    limb = reader_u8(r) % 8;
    offset = 32 * limb + reader_u8(r) % (33 - count);
    transcript_u32(t, secp256k1_scalar_get_bits_limb32(a, offset, count));
}

static size_t target_scalar(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    secp256k1_scalar reg[SCALAR_REGS];
    unsigned char b32[32];
    int i;

    for (i = 0; i < SCALAR_REGS; i++) {
        secp256k1_scalar_set_int(&reg[i], 0);
    }

    for (i = 0; i < SCALAR_MAX_OPS && !reader_empty(&r); i++) {
        unsigned int op = reader_u8(&r) % SCALAR_OP_COUNT, sel = reader_u8(&r);
        secp256k1_scalar *d = &reg[sel % SCALAR_REGS];
        secp256k1_scalar a = reg[(sel / SCALAR_REGS) % SCALAR_REGS];
        secp256k1_scalar *b = &reg[(sel / (SCALAR_REGS * SCALAR_REGS)) % SCALAR_REGS];
        secp256k1_scalar y = *b, res, res2;
        int ret;

        transcript_u8(&t, op);
        switch ((enum scalar_op)op) {
        case SCALAR_SET_B32:
            reader_take(&r, b32, sizeof(b32));
            secp256k1_scalar_set_b32(d, b32, &ret);
            transcript_int(&t, ret);
            break;
        case SCALAR_SET_B32_SECKEY:
            reader_take(&r, b32, sizeof(b32));
            transcript_int(&t, secp256k1_scalar_set_b32_seckey(d, b32));
            break;
        case SCALAR_ADD:
            transcript_int(&t, secp256k1_scalar_add(&res, &a, &y));
            *d = res;
            break;
        case SCALAR_MUL:
            secp256k1_scalar_mul(&res, &a, &y);
            *d = res;
            break;
        case SCALAR_NEGATE:
            secp256k1_scalar_negate(&res, &a);
            *d = res;
            break;
        case SCALAR_HALF:
            secp256k1_scalar_half(&res, &a);
            *d = res;
            break;
        case SCALAR_INVERSE:
            secp256k1_scalar_inverse(&res, &a);
            *d = res;
            break;
        case SCALAR_INVERSE_VAR:
            secp256k1_scalar_inverse_var(&res, &a);
            *d = res;
            break;
        case SCALAR_COND_NEGATE:
            transcript_int(&t, secp256k1_scalar_cond_negate(d, (int)(reader_u8(&r) & 1)));
            break;
        case SCALAR_CMOV:
            secp256k1_scalar_cmov(d, &a, (int)(reader_u8(&r) & 1));
            break;
        case SCALAR_SPLIT_128:
            secp256k1_scalar_split_128(&res, &res2, &a);
            scalar_record(&t, &res2);
            *d = res;
            *b = res2;
            break;
        case SCALAR_SPLIT_LAMBDA:
            secp256k1_scalar_split_lambda(&res, &res2, &a);
            scalar_record(&t, &res2);
            *d = res;
            *b = res2;
            break;
        case SCALAR_MUL_SHIFT_VAR:
            /* Shift must be at least 256; the implementations handle up to 512. */
            secp256k1_scalar_mul_shift_var(&res, &a, &y, 256 + reader_u8(&r));
            *d = res;
            break;
        case SCALAR_QUERY:
            scalar_query(&t, &r, &a, &y);
            break;
        case SCALAR_OP_COUNT:
            abort();
        }
        scalar_record(&t, d);
    }

    return t.len;
}
