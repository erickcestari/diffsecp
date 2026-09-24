/* Key operations as wallets use them: BIP32-style tweaks, negation,
 * combination, sorting, taproot keypair tweaks and ECDH, driven as a register
 * machine over the public API.
 *
 * Secret keys are plain bytes and any value is a legal argument, but an invalid
 * pubkey or keypair object is an illegal one, so a pubkey register that fails
 * an op is emptied and skipped by the ops that read it.
 *
 * Input: repeated [op, selector, operands...]. The selector picks the
 * destination and two source registers. */

#define KEYS_REGS 4
#define KEYS_MAX_OPS 64

enum keys_op {
    KEYS_SECKEY_LOAD,
    KEYS_SECKEY_NEGATE,
    KEYS_SECKEY_TWEAK_ADD,
    KEYS_SECKEY_TWEAK_MUL,
    KEYS_PUBKEY_CREATE,
    KEYS_PUBKEY_PARSE,
    KEYS_PUBKEY_NEGATE,
    KEYS_PUBKEY_TWEAK_ADD,
    KEYS_PUBKEY_TWEAK_MUL,
    KEYS_PUBKEY_COMBINE,
    KEYS_PUBKEY_CMP,
    KEYS_PUBKEY_SORT,
    KEYS_KEYPAIR_TWEAK,
    KEYS_XONLY,
    KEYS_ECDH,
    KEYS_OP_COUNT
};

struct keys_reg {
    unsigned char sk[32];
    secp256k1_pubkey pk;
    int pk_ok;
};

/* cmp functions only promise the sign of their result. */
static int keys_sign(int c) {
    return (c > 0) - (c < 0);
}

static void keys_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[33];
    size_t len = sizeof(ser);

    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
}

static void keys_record_reg(struct transcript *t, const struct keys_reg *reg) {
    transcript_put(t, reg->sk, sizeof(reg->sk));
    transcript_int(t, reg->pk_ok);
    if (reg->pk_ok) {
        keys_record_pubkey(t, &reg->pk);
    }
}

/* A seckey op that fails leaves "some unspecified value", so zero it instead. */
static void keys_seckey_result(struct transcript *t, unsigned char *sk, int ret) {
    transcript_int(t, ret);
    if (!ret) {
        memset(sk, 0, 32);
    }
}

/* The raw shared point, to compare more than the default hash. */
static int keys_ecdh_xy(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    memcpy(output, x32, 32);
    memcpy(output + 32, y32, 32);
    return 1;
}

static void keys_ecdh(struct transcript *t, const struct keys_reg *a, const struct keys_reg *b) {
    unsigned char hashed[32], xy[64];
    int ret;

    ret = secp256k1_ecdh(variant_ctx, hashed, &a->pk, b->sk, NULL, NULL);
    transcript_int(t, ret);
    if (ret) {
        transcript_put(t, hashed, sizeof(hashed));
    }
    ret = secp256k1_ecdh(variant_ctx, xy, &a->pk, b->sk, keys_ecdh_xy, NULL);
    transcript_int(t, ret);
    if (ret) {
        transcript_put(t, xy, sizeof(xy));
    }
}

/* Taproot key-path signing tweaks the keypair; the result lands in d. */
static void keys_keypair_tweak(struct transcript *t, struct keys_reg *d, const struct keys_reg *a,
                               const unsigned char *tweak) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;
    unsigned char ser[32];
    int ret, parity;

    ret = secp256k1_keypair_create(variant_ctx, &keypair, a->sk);
    transcript_int(t, ret);
    if (!ret) {
        return;
    }
    secp256k1_keypair_xonly_pub(variant_ctx, &xonly, &parity, &keypair);
    secp256k1_xonly_pubkey_serialize(variant_ctx, ser, &xonly);
    transcript_int(t, parity);
    transcript_put(t, ser, sizeof(ser));
    ret = secp256k1_keypair_xonly_tweak_add(variant_ctx, &keypair, tweak);
    transcript_int(t, ret);
    if (ret) {
        secp256k1_keypair_sec(variant_ctx, d->sk, &keypair);
        secp256k1_keypair_pub(variant_ctx, &d->pk, &keypair);
        d->pk_ok = 1;
    }
}

/* x-only views of a and b, their order, and a's x-only tweak into d. */
static void keys_xonly(struct transcript *t, struct keys_reg *d, const struct keys_reg *a,
                       const struct keys_reg *b, const unsigned char *tweak) {
    secp256k1_xonly_pubkey xa, xb;
    secp256k1_pubkey tweaked;
    unsigned char ser[32];
    int ret, parity;

    if (!a->pk_ok) {
        return;
    }
    secp256k1_xonly_pubkey_from_pubkey(variant_ctx, &xa, &parity, &a->pk);
    secp256k1_xonly_pubkey_serialize(variant_ctx, ser, &xa);
    transcript_int(t, parity);
    transcript_put(t, ser, sizeof(ser));
    if (b->pk_ok) {
        secp256k1_xonly_pubkey_from_pubkey(variant_ctx, &xb, &parity, &b->pk);
        transcript_int(t, keys_sign(secp256k1_xonly_pubkey_cmp(variant_ctx, &xa, &xb)));
    }
    ret = secp256k1_xonly_pubkey_tweak_add(variant_ctx, &tweaked, &xa, tweak);
    transcript_int(t, ret);
    if (ret) {
        d->pk = tweaked;
        d->pk_ok = 1;
    }
}

static void keys_sort(struct transcript *t, const struct keys_reg *reg) {
    const secp256k1_pubkey *ptrs[KEYS_REGS];
    size_t n = 0, i;

    for (i = 0; i < KEYS_REGS; i++) {
        if (reg[i].pk_ok) {
            ptrs[n++] = &reg[i].pk;
        }
    }
    if (n == 0) {
        return;
    }
    transcript_int(t, secp256k1_ec_pubkey_sort(variant_ctx, ptrs, n));
    /* Equal keys may swap places, so record keys rather than register numbers. */
    for (i = 0; i < n; i++) {
        keys_record_pubkey(t, ptrs[i]);
    }
}

static size_t target_keys(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    struct keys_reg reg[KEYS_REGS];
    int i;

    memset(reg, 0, sizeof(reg));

    for (i = 0; i < KEYS_MAX_OPS && !reader_empty(&r); i++) {
        unsigned int op = reader_u8(&r) % KEYS_OP_COUNT, sel = reader_u8(&r);
        struct keys_reg *d = &reg[sel % KEYS_REGS];
        const struct keys_reg *a = &reg[(sel / KEYS_REGS) % KEYS_REGS];
        const struct keys_reg *b = &reg[(sel / (KEYS_REGS * KEYS_REGS)) % KEYS_REGS];
        /* Ops build the result from copies, so d may alias a or b. */
        struct keys_reg res = *d;
        unsigned char tweak[32], ser[65];
        const secp256k1_pubkey *ptrs[KEYS_REGS];
        unsigned int flags;
        size_t n, j;

        transcript_u8(&t, op);
        switch ((enum keys_op)op) {
        case KEYS_SECKEY_LOAD:
            reader_take(&r, res.sk, sizeof(res.sk));
            transcript_int(&t, secp256k1_ec_seckey_verify(variant_ctx, res.sk));
            break;
        case KEYS_SECKEY_NEGATE:
            memcpy(res.sk, a->sk, sizeof(res.sk));
            keys_seckey_result(&t, res.sk, secp256k1_ec_seckey_negate(variant_ctx, res.sk));
            break;
        case KEYS_SECKEY_TWEAK_ADD:
            reader_take(&r, tweak, sizeof(tweak));
            memcpy(res.sk, a->sk, sizeof(res.sk));
            keys_seckey_result(&t, res.sk, secp256k1_ec_seckey_tweak_add(variant_ctx, res.sk, tweak));
            break;
        case KEYS_SECKEY_TWEAK_MUL:
            reader_take(&r, tweak, sizeof(tweak));
            memcpy(res.sk, a->sk, sizeof(res.sk));
            keys_seckey_result(&t, res.sk, secp256k1_ec_seckey_tweak_mul(variant_ctx, res.sk, tweak));
            break;
        case KEYS_PUBKEY_CREATE:
            res.pk_ok = secp256k1_ec_pubkey_create(variant_ctx, &res.pk, a->sk);
            break;
        case KEYS_PUBKEY_PARSE:
            /* 33 or 65 bytes; 65 also admits the hybrid 0x06/0x07 prefixes. */
            n = (reader_u8(&r) & 1) ? 65 : 33;
            reader_take(&r, ser, n);
            res.pk_ok = secp256k1_ec_pubkey_parse(variant_ctx, &res.pk, ser, n);
            break;
        case KEYS_PUBKEY_NEGATE:
            if (a->pk_ok) {
                res.pk = a->pk;
                res.pk_ok = secp256k1_ec_pubkey_negate(variant_ctx, &res.pk);
            }
            break;
        case KEYS_PUBKEY_TWEAK_ADD:
            reader_take(&r, tweak, sizeof(tweak));
            if (a->pk_ok) {
                res.pk = a->pk;
                res.pk_ok = secp256k1_ec_pubkey_tweak_add(variant_ctx, &res.pk, tweak);
            }
            break;
        case KEYS_PUBKEY_TWEAK_MUL:
            reader_take(&r, tweak, sizeof(tweak));
            if (a->pk_ok) {
                res.pk = a->pk;
                res.pk_ok = secp256k1_ec_pubkey_tweak_mul(variant_ctx, &res.pk, tweak);
            }
            break;
        case KEYS_PUBKEY_COMBINE:
            /* Sums the valid registers the mask picks; a zero sum fails. */
            flags = reader_u8(&r);
            for (j = 0, n = 0; j < KEYS_REGS; j++) {
                if (((flags >> j) & 1) && reg[j].pk_ok) {
                    ptrs[n++] = &reg[j].pk;
                }
            }
            if (n > 0) {
                res.pk_ok = secp256k1_ec_pubkey_combine(variant_ctx, &res.pk, ptrs, n);
            }
            break;
        case KEYS_PUBKEY_CMP:
            if (a->pk_ok && b->pk_ok) {
                transcript_int(&t, keys_sign(secp256k1_ec_pubkey_cmp(variant_ctx, &a->pk, &b->pk)));
            }
            break;
        case KEYS_PUBKEY_SORT:
            keys_sort(&t, reg);
            break;
        case KEYS_KEYPAIR_TWEAK:
            reader_take(&r, tweak, sizeof(tweak));
            keys_keypair_tweak(&t, &res, a, tweak);
            break;
        case KEYS_XONLY:
            reader_take(&r, tweak, sizeof(tweak));
            keys_xonly(&t, &res, a, b, tweak);
            break;
        case KEYS_ECDH:
            if (a->pk_ok) {
                keys_ecdh(&t, a, b);
            }
            break;
        case KEYS_OP_COUNT:
            abort();
        }
        if (!res.pk_ok) {
            /* Failed ops leave the object invalid; never pass it on. */
            memset(&res.pk, 0, sizeof(res.pk));
        }
        *d = res;
        keys_record_reg(&t, d);
    }

    return t.len;
}
