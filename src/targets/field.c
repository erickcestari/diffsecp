/* Field arithmetic driven as a register machine, reaching the internal API.
 *
 * The harness tracks each register's magnitude and weakly normalizes operands
 * before any call that would exceed the documented bounds. The guide variant is
 * built with VERIFY, so a tracking mistake aborts there instead of silently
 * feeding out-of-contract inputs. Every op records the normalized value of its
 * destination, which is comparable across field implementations.
 *
 * Input: repeated [op, selector, operands...]. The selector picks the
 * destination and two source registers. */

#define FIELD_REGS 4
#define FIELD_MAX_OPS 1024

enum field_op {
    FIELD_SET_B32_MOD,
    FIELD_SET_B32_LIMIT,
    FIELD_ADD,
    FIELD_ADD_INT,
    FIELD_MUL,
    FIELD_SQR,
    FIELD_NEGATE,
    FIELD_MUL_INT,
    FIELD_HALF,
    FIELD_NORMALIZE,
    FIELD_NORMALIZE_WEAK,
    FIELD_NORMALIZE_VAR,
    FIELD_INV,
    FIELD_INV_VAR,
    FIELD_SQRT,
    FIELD_CMOV,
    FIELD_STORAGE,
    FIELD_QUERY,
    FIELD_OP_COUNT
};

struct field_reg {
    secp256k1_fe v;
    int mag;
};

static void field_weaken(struct field_reg *x) {
    secp256k1_fe_normalize_weak(&x->v);
    x->mag = 1;
}

static void field_limit(struct field_reg *x, int max) {
    if (x->mag > max) {
        field_weaken(x);
    }
}

static void field_record(struct transcript *t, const secp256k1_fe *v) {
    secp256k1_fe n = *v;
    unsigned char b32[32];

    secp256k1_fe_normalize_var(&n);
    secp256k1_fe_get_b32(b32, &n);
    transcript_put(t, b32, sizeof(b32));
}

/* Predicates on a and b; leaves both registers untouched. */
static void field_query(struct transcript *t, const struct field_reg *a, const struct field_reg *b) {
    secp256k1_fe x = a->v, y = b->v;

    transcript_int(t, secp256k1_fe_normalizes_to_zero(&x));
    transcript_int(t, secp256k1_fe_normalizes_to_zero_var(&x));
    transcript_int(t, secp256k1_fe_is_square_var(&x));
    secp256k1_fe_normalize_weak(&x);
    secp256k1_fe_normalize_weak(&y);
    transcript_int(t, secp256k1_fe_equal(&x, &y));
    secp256k1_fe_normalize(&x);
    secp256k1_fe_normalize(&y);
    transcript_int(t, secp256k1_fe_is_zero(&x));
    transcript_int(t, secp256k1_fe_is_odd(&x));
    transcript_int(t, secp256k1_fe_cmp_var(&x, &y));
}

static size_t target_field(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    struct field_reg reg[FIELD_REGS];
    unsigned char b32[32];
    int i;

    for (i = 0; i < FIELD_REGS; i++) {
        secp256k1_fe_set_int(&reg[i].v, 0);
        reg[i].mag = 0;
    }

    for (i = 0; i < FIELD_MAX_OPS && !reader_empty(&r); i++) {
        unsigned int op = reader_u8(&r) % FIELD_OP_COUNT, sel = reader_u8(&r);
        struct field_reg *d = &reg[sel % FIELD_REGS];
        struct field_reg *a = &reg[(sel / FIELD_REGS) % FIELD_REGS];
        struct field_reg *b = &reg[(sel / (FIELD_REGS * FIELD_REGS)) % FIELD_REGS];
        secp256k1_fe tmp;
        int ret, m;

        transcript_u8(&t, op);
        switch ((enum field_op)op) {
        case FIELD_SET_B32_MOD:
            reader_take(&r, b32, sizeof(b32));
            secp256k1_fe_set_b32_mod(&d->v, b32);
            d->mag = 1;
            break;
        case FIELD_SET_B32_LIMIT:
            reader_take(&r, b32, sizeof(b32));
            ret = secp256k1_fe_set_b32_limit(&d->v, b32);
            transcript_int(&t, ret);
            if (ret) {
                d->mag = 1;
            } else {
                /* On overflow d is invalid and must be overwritten. */
                secp256k1_fe_set_int(&d->v, 0);
                d->mag = 0;
            }
            break;
        case FIELD_ADD:
            if (d->mag + a->mag > 32) field_weaken(d);
            if (d->mag + a->mag > 32) field_weaken(a);
            m = a->mag;
            secp256k1_fe_add(&d->v, &a->v);
            d->mag += m;
            break;
        case FIELD_ADD_INT:
            field_limit(d, 31);
            secp256k1_fe_add_int(&d->v, (int)(reader_u16(&r) % 0x8000));
            d->mag += 1;
            break;
        case FIELD_MUL:
            field_limit(a, 8);
            field_limit(b, 8);
            /* b may alias neither r nor a. */
            tmp = b->v;
            secp256k1_fe_mul(&d->v, &a->v, &tmp);
            d->mag = 1;
            break;
        case FIELD_SQR:
            field_limit(a, 8);
            secp256k1_fe_sqr(&d->v, &a->v);
            d->mag = 1;
            break;
        case FIELD_NEGATE:
            field_limit(a, 31);
            m = a->mag + (int)(reader_u8(&r) % (unsigned int)(32 - a->mag));
            secp256k1_fe_negate_unchecked(&d->v, &a->v, m);
            d->mag = m + 1;
            break;
        case FIELD_MUL_INT:
            m = (int)(reader_u8(&r) % 33);
            if (m * d->mag > 32) field_weaken(d);
            secp256k1_fe_mul_int_unchecked(&d->v, m);
            d->mag *= m;
            break;
        case FIELD_HALF:
            field_limit(d, 31);
            secp256k1_fe_half(&d->v);
            d->mag = (d->mag >> 1) + 1;
            break;
        case FIELD_NORMALIZE:
            secp256k1_fe_normalize(&d->v);
            d->mag = 1;
            break;
        case FIELD_NORMALIZE_WEAK:
            field_weaken(d);
            break;
        case FIELD_NORMALIZE_VAR:
            secp256k1_fe_normalize_var(&d->v);
            d->mag = 1;
            break;
        case FIELD_INV:
            m = a->mag != 0;
            secp256k1_fe_inv(&d->v, &a->v);
            d->mag = m;
            break;
        case FIELD_INV_VAR:
            m = a->mag != 0;
            secp256k1_fe_inv_var(&d->v, &a->v);
            d->mag = m;
            break;
        case FIELD_SQRT:
            field_limit(a, 8);
            /* r and a must not alias. */
            ret = secp256k1_fe_sqrt(&tmp, &a->v);
            transcript_int(&t, ret);
            d->v = tmp;
            d->mag = 1;
            break;
        case FIELD_CMOV:
            m = d->mag > a->mag ? d->mag : a->mag;
            secp256k1_fe_cmov(&d->v, &a->v, (int)(reader_u8(&r) & 1));
            d->mag = m;
            break;
        case FIELD_STORAGE: {
            secp256k1_fe_storage s;

            secp256k1_fe_normalize(&d->v);
            secp256k1_fe_to_storage(&s, &d->v);
            secp256k1_fe_from_storage(&d->v, &s);
            d->mag = 1;
            break;
        }
        case FIELD_QUERY:
            field_query(&t, a, b);
            break;
        case FIELD_OP_COUNT:
            abort();
        }
        field_record(&t, &d->v);
    }

    return t.len;
}
