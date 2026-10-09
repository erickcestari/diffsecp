/* Group arithmetic and point multiplication driven as a register machine,
 * reaching the internal API.
 *
 * Points come from k*G with fuzzed k, so the fuzzer controls how they relate
 * and reaches what fuzzed signatures can't: doubling inside an addition,
 * P + (-P) and infinity as an operand. Each op records its destination in
 * affine coordinates, since the jacobian z depends on how a point was computed
 * (for example on the ecmult window size) and differs between builds.
 *
 * Input: repeated [op, selector, operands...]. The selector picks the
 * destination and two source registers, and its top two bits how many
 * registers a batch op takes. */

#define GROUP_REGS 4
/* Point multiplications dominate, so fewer ops than the field and scalar targets. */
#define GROUP_MAX_OPS 32

enum group_op {
    GROUP_GEN,
    GROUP_SET_XO,
    GROUP_SET_INFINITY,
    GROUP_ADD_VAR,
    GROUP_ADD_GE,
    GROUP_ADD_GE_VAR,
    GROUP_ADD_ZINV_VAR,
    GROUP_DOUBLE,
    GROUP_DOUBLE_VAR,
    GROUP_NEG,
    GROUP_RESCALE,
    GROUP_MUL_LAMBDA,
    GROUP_ECMULT,
    GROUP_ECMULT_CONST,
    GROUP_ECMULT_CONST_XONLY,
    GROUP_ECMULT_MULTI,
    GROUP_BATCH_AFFINE,
    GROUP_QUERY,
    GROUP_OP_COUNT
};

/* Point j of a multi-point multiplication is register j % 4, with scalar
 * sc[j % 4] + (j / 4) * step. The callback fails at point fail_at. */
struct group_multi {
    secp256k1_scalar sc[GROUP_REGS];
    secp256k1_ge pt[GROUP_REGS];
    secp256k1_scalar step;
    size_t fail_at;
};

static int group_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    const struct group_multi *m = data;
    secp256k1_scalar k;

    if (idx == m->fail_at) {
        return 0;
    }
    secp256k1_scalar_set_int(&k, (unsigned int)(idx / GROUP_REGS));
    secp256k1_scalar_mul(&k, &k, &m->step);
    secp256k1_scalar_add(sc, &m->sc[idx % GROUP_REGS], &k);
    *pt = m->pt[idx % GROUP_REGS];
    return 1;
}

static void group_take_scalar(struct reader *r, secp256k1_scalar *s) {
    unsigned char b32[32];

    reader_take(r, b32, sizeof(b32));
    secp256k1_scalar_set_b32(s, b32, NULL);
}

/* Magnitude 1, so it can feed any field op. */
static void group_take_fe(struct reader *r, secp256k1_fe *x) {
    unsigned char b32[32];

    reader_take(r, b32, sizeof(b32));
    secp256k1_fe_set_b32_mod(x, b32);
}

static void group_take_nonzero_fe(struct reader *r, secp256k1_fe *x) {
    group_take_fe(r, x);
    if (secp256k1_fe_normalizes_to_zero_var(x)) {
        secp256k1_fe_set_int(x, 1);
    }
}

/* set_gej_var normalizes its input, so it works on a copy. */
static void group_affine(secp256k1_ge *r, const secp256k1_gej *a) {
    secp256k1_gej tmp = *a;

    secp256k1_ge_set_gej_var(r, &tmp);
}

static void group_record_fe(struct transcript *t, const secp256k1_fe *x) {
    secp256k1_fe n = *x;
    unsigned char b32[32];

    secp256k1_fe_normalize_var(&n);
    secp256k1_fe_get_b32(b32, &n);
    transcript_put(t, b32, sizeof(b32));
}

static void group_record_ge(struct transcript *t, const secp256k1_ge *p) {
    transcript_u8(t, (unsigned int)p->infinity);
    if (!p->infinity) {
        group_record_fe(t, &p->x);
        group_record_fe(t, &p->y);
    }
}

/* The *_var ops promise r->z == a->z * rzr. The ratio itself depends on a's z,
 * so only whether the promise holds is comparable across builds. */
static void group_record_rzr(struct transcript *t, const secp256k1_gej *r, const secp256k1_gej *a,
                             const secp256k1_fe *rzr) {
    secp256k1_fe z;

    secp256k1_fe_mul(&z, &a->z, rzr);
    transcript_int(t, r->infinity || secp256k1_fe_equal(&z, &r->z));
}

/* Predicates on a and b, plus curve membership of fuzzed x coordinates. */
static void group_query(struct transcript *t, struct reader *r, const secp256k1_gej *a,
                        const secp256k1_gej *b, const secp256k1_ge *ga, const secp256k1_ge *gb) {
    secp256k1_fe xn, xd;

    group_take_fe(r, &xn);
    group_take_nonzero_fe(r, &xd);
    transcript_int(t, secp256k1_gej_is_infinity(a));
    transcript_int(t, secp256k1_gej_eq_var(a, b));
    transcript_int(t, secp256k1_gej_eq_ge_var(a, gb));
    transcript_int(t, secp256k1_ge_eq_var(ga, gb));
    transcript_int(t, secp256k1_ge_is_valid_var(ga));
    if (!a->infinity && !gb->infinity) {
        transcript_int(t, secp256k1_gej_eq_x_var(&gb->x, a));
    }
    transcript_int(t, secp256k1_ge_x_on_curve_var(&xn));
    transcript_int(t, secp256k1_ge_x_frac_on_curve_var(&xn, &xd));
}

/* x(q*P) from x-only multiplication, for P = a with x given as the fraction
 * (x*d)/d, or for a raw fraction n/d that may not be on the curve. */
static void group_ecmult_const_xonly(struct transcript *t, struct reader *r, const secp256k1_ge *a) {
    secp256k1_scalar q;
    secp256k1_fe n, d, x;
    unsigned int flags;
    int ret, raw;

    group_take_scalar(r, &q);
    flags = reader_u8(r);
    group_take_fe(r, &n);
    group_take_nonzero_fe(r, &d);
    /* q must be nonzero, and a known point must not be infinity. */
    if (secp256k1_scalar_is_zero(&q)) {
        secp256k1_scalar_set_int(&q, 1);
    }
    raw = (flags & 1) || a->infinity;
    if (!raw && (flags & 2)) {
        secp256k1_fe_mul(&n, &a->x, &d);
    } else if (!raw) {
        n = a->x;
    }
    ret = secp256k1_ecmult_const_xonly(&x, &n, (flags & 2) ? &d : NULL, &q, !raw);
    transcript_int(t, ret);
    if (ret) {
        group_record_fe(t, &x);
    }
}

/* A scratch size from 16 fuzzed bits: a 12-bit mantissa shifted by up to 9, so
 * every scale comes up, from sizes too small for any point to 2 MB. Strauss
 * needs less room per point than Pippenger, so no size makes Strauss alone fail
 * and ecmult_multi_var fall back after it. */
static size_t group_scratch_size(unsigned int v) {
    return (size_t)(v & 0xFFF) << ((v >> 12) % 10);
}

/* Pippenger's bucket windows past 7 take more than 1260 points, and its largest
 * more than 16050, which cost seconds per input across the builds. */
#define GROUP_LARGE_MIN 1261
#define GROUP_LARGE_MAX 16384
#define GROUP_LARGE_ODDS 4096

/* As sp_limit_due: the hash of the whole input (FNV-1a) falls in its lowest
 * 1/GROUP_LARGE_ODDS, which mutations reroll where they would keep a flag. */
static int group_large_due(const unsigned char *in, size_t len) {
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < len; i++) {
        h = (h ^ in[i]) * 16777619u;
    }
    return h <= UINT32_MAX / GROUP_LARGE_ODDS;
}

/* ng*G + the sum of the points, as MuSig key aggregation computes it: the four
 * registers without scratch space, or with flag bit 1 up to 255 points and a
 * scratch space of fuzzed size, which picks Strauss or Pippenger (from 88
 * points) and how many batches, or the scratch-free fallback when too small.
 * Flag bit 0 drops ng, bit 2 makes the callback fail, and bit 3, while *large
 * is set, takes GROUP_LARGE_MIN to GROUP_LARGE_MAX points and a 16 times
 * larger scratch space, then clears *large. */
static int group_ecmult_multi(struct reader *r, secp256k1_gej *res, const secp256k1_gej *reg, int *large) {
    struct group_multi m;
    secp256k1_scalar ng;
    secp256k1_scratch_space *scratch = NULL;
    size_t n = GROUP_REGS;
    unsigned int flags, scale = 0;
    int j, ret;

    group_take_scalar(r, &ng);
    flags = reader_u8(r);
    for (j = 0; j < GROUP_REGS; j++) {
        group_take_scalar(r, &m.sc[j]);
        group_affine(&m.pt[j], &reg[j]);
    }
    secp256k1_scalar_set_int(&m.step, 0);
    m.fail_at = SIZE_MAX;
    if (flags & 2) {
        if ((flags & 8) && *large) {
            *large = 0;
            n = GROUP_LARGE_MIN + reader_u16(r) % (GROUP_LARGE_MAX - GROUP_LARGE_MIN + 1);
            scale = 4;
        } else {
            n = reader_u8(r);
        }
        group_take_scalar(r, &m.step);
        scratch = secp256k1_scratch_space_create(variant_ctx, group_scratch_size(reader_u16(r)) << scale);
    }
    if (flags & 4) {
        m.fail_at = reader_u8(r);
    }
    ret = secp256k1_ecmult_multi_var(&variant_ctx->error_callback, scratch, res, (flags & 1) ? NULL : &ng,
                                     group_multi_callback, &m, n);
    secp256k1_scratch_space_destroy(variant_ctx, scratch);
    if (!ret) {
        /* A failed batch leaves a partial sum, which depends on the batch sizes
         * and so on the struct sizes of the build. */
        secp256k1_gej_set_infinity(res);
    }
    return ret;
}

/* The first n registers to affine at once, as the ecmult tables do. The
 * constant-time batch rejects infinity. */
static void group_batch_affine(struct transcript *t, const secp256k1_gej *reg, size_t n) {
    secp256k1_ge ge[GROUP_REGS];
    size_t i;
    int any_infinity = 0;

    secp256k1_ge_set_all_gej_var(ge, reg, n);
    for (i = 0; i < n; i++) {
        group_record_ge(t, &ge[i]);
        any_infinity |= reg[i].infinity;
    }
    if (!any_infinity) {
        secp256k1_ge_set_all_gej(ge, reg, n);
        for (i = 0; i < n; i++) {
            group_record_ge(t, &ge[i]);
        }
    }
}

static size_t target_group(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    secp256k1_gej reg[GROUP_REGS];
    int i, large = group_large_due(in, len);

    for (i = 0; i < GROUP_REGS; i++) {
        secp256k1_gej_set_infinity(&reg[i]);
    }

    for (i = 0; i < GROUP_MAX_OPS && !reader_empty(&r); i++) {
        unsigned int op = reader_u8(&r) % GROUP_OP_COUNT, sel = reader_u8(&r);
        secp256k1_gej *d = &reg[sel % GROUP_REGS];
        const secp256k1_gej *a = &reg[(sel / GROUP_REGS) % GROUP_REGS];
        const secp256k1_gej *b = &reg[(sel / (GROUP_REGS * GROUP_REGS)) % GROUP_REGS];
        /* Results go to res first, so no op sees its output alias an input. */
        secp256k1_gej res = *d;
        secp256k1_ge ga, gb, ge;
        secp256k1_scalar s1, s2;
        secp256k1_fe f1, f2, f3, rzr;
        unsigned int flags;
        int ret;

        group_affine(&ga, a);
        group_affine(&gb, b);
        transcript_u8(&t, op);
        switch ((enum group_op)op) {
        case GROUP_GEN:
            group_take_scalar(&r, &s1);
            secp256k1_ecmult_gen_gej(&variant_ctx->ecmult_gen_ctx, &res, &s1);
            break;
        case GROUP_SET_XO:
            group_take_fe(&r, &f1);
            ret = secp256k1_ge_set_xo_var(&ge, &f1, (int)(reader_u8(&r) & 1));
            transcript_int(&t, ret);
            if (ret) {
                secp256k1_gej_set_ge(&res, &ge);
            }
            break;
        case GROUP_SET_INFINITY:
            secp256k1_gej_set_infinity(&res);
            break;
        case GROUP_ADD_VAR:
            /* rzr is only defined when a is not infinity. */
            if (a->infinity) {
                secp256k1_gej_add_var(&res, a, b, NULL);
            } else {
                secp256k1_gej_add_var(&res, a, b, &rzr);
                group_record_rzr(&t, &res, a, &rzr);
            }
            break;
        case GROUP_ADD_GE:
            /* The constant-time addition rejects an infinite b. */
            if (!gb.infinity) {
                secp256k1_gej_add_ge(&res, a, &gb);
            }
            break;
        case GROUP_ADD_GE_VAR:
            if (a->infinity) {
                secp256k1_gej_add_ge_var(&res, a, &gb, NULL);
            } else {
                secp256k1_gej_add_ge_var(&res, a, &gb, &rzr);
                group_record_rzr(&t, &res, a, &rzr);
            }
            break;
        case GROUP_ADD_ZINV_VAR:
            /* b as the jacobian (X*z^2, Y*z^3, z) for a fuzzed z, passing 1/z.
             * Infinity has no coordinates to scale, so it goes as it is. */
            group_take_nonzero_fe(&r, &f1);
            ge = gb;
            f2 = f1;
            if (!gb.infinity) {
                secp256k1_fe_sqr(&f2, &f1);
                secp256k1_fe_mul(&ge.x, &gb.x, &f2);
                secp256k1_fe_mul(&f3, &f2, &f1);
                secp256k1_fe_mul(&ge.y, &gb.y, &f3);
                secp256k1_fe_inv_var(&f2, &f1);
            }
            secp256k1_gej_add_zinv_var(&res, a, &ge, &f2);
            break;
        case GROUP_DOUBLE:
            secp256k1_gej_double(&res, a);
            break;
        case GROUP_DOUBLE_VAR:
            secp256k1_gej_double_var(&res, a, &rzr);
            if (!a->infinity) {
                group_record_rzr(&t, &res, a, &rzr);
            }
            break;
        case GROUP_NEG:
            secp256k1_gej_neg(&res, a);
            break;
        case GROUP_RESCALE:
            /* Changes z but not the point. */
            group_take_nonzero_fe(&r, &f1);
            if (!res.infinity) {
                secp256k1_gej_rescale(&res, &f1);
            }
            break;
        case GROUP_MUL_LAMBDA:
            secp256k1_ge_mul_lambda(&ge, &ga);
            secp256k1_gej_set_ge(&res, &ge);
            break;
        case GROUP_ECMULT:
            group_take_scalar(&r, &s1);
            group_take_scalar(&r, &s2);
            flags = reader_u8(&r);
            secp256k1_ecmult(&res, a, &s1, (flags & 1) ? NULL : &s2);
            break;
        case GROUP_ECMULT_CONST:
            group_take_scalar(&r, &s1);
            secp256k1_ecmult_const_gej(&res, &ga, &s1);
            break;
        case GROUP_ECMULT_CONST_XONLY:
            group_ecmult_const_xonly(&t, &r, &ga);
            break;
        case GROUP_ECMULT_MULTI:
            transcript_int(&t, group_ecmult_multi(&r, &res, reg, &large));
            break;
        case GROUP_BATCH_AFFINE:
            /* All four registers, two, one or none. */
            group_batch_affine(&t, reg, GROUP_REGS >> (sel >> 6));
            break;
        case GROUP_QUERY:
            group_query(&t, &r, a, b, &ga, &gb);
            break;
        case GROUP_OP_COUNT:
            abort();
        }
        *d = res;
        group_affine(&ge, d);
        group_record_ge(&t, &ge);
    }

    return t.len;
}
