/* ElligatorSwift, the BIP324 key encoding: decoding arbitrary 64-byte
 * encodings, encoding with fuzzed randomness, and the x-only ECDH both peers
 * run. Builds that disagree here split the P2P network rather than the chain.
 *
 * Encoding costs about as much as ten decodings, so flags pick the expensive
 * steps rather than every input paying for all of them.
 *
 * Input: flags, ell64, rnd32, then seckey32 and auxrnd32 for each party,
 * then prefix64, then the inverse's mode and u32. */

enum ellswift_flag {
    ELLSWIFT_AUX0 = 1 << 0,       /* party 0 creates its encoding with auxrnd */
    ELLSWIFT_AUX1 = 1 << 1,
    ELLSWIFT_FUZZ_PEER = 1 << 2,  /* the responder sends the fuzzed encoding instead */
    ELLSWIFT_ENCODE = 1 << 3,     /* re-encode the fuzzed encoding's point with rnd */
    ELLSWIFT_PREFIX = 1 << 4,     /* hash with the fuzzed prefix instead of the BIP324 tag */
    ELLSWIFT_RAW = 1 << 5,        /* also derive the bare shared x (ellswift_raw_x) */
    ELLSWIFT_INV = 1 << 6         /* invert an x for a chosen u (ellswift_inv) */
};

/* Where ellswift_inv takes x and u from, in the mode's bits above c. */
enum ellswift_inv_kind {
    ELLSWIFT_INV_FUZZED,  /* the fuzzed encoding's x and a fuzzed u */
    ELLSWIFT_INV_U_IS_X,  /* s = x - u is zero, so r is too */
    ELLSWIFT_INV_R_ZERO,  /* x = u + s for the nonzero s that zeroes r (ellswift_x_r_zero) */
    ELLSWIFT_INV_KINDS
};

/* A custom hash function that returns the shared x itself. */
static int ellswift_xdh_raw(unsigned char *output, const unsigned char *x32, const unsigned char *ell_a64,
                            const unsigned char *ell_b64, void *data) {
    (void)ell_a64;
    (void)ell_b64;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

/* Party 0's bare shared x, through a custom hash function, then hashed by the
 * exported hashfp outside any context, which must give the session secret. */
static void ellswift_raw_x(struct transcript *t, const unsigned char *ell_a64, const unsigned char *ell_b64,
                           const unsigned char *seckey, secp256k1_ellswift_xdh_hash_function hashfp,
                           unsigned char *prefix) {
    unsigned char x[32], shared[32];
    int ret;

    ret = secp256k1_ellswift_xdh(variant_ctx, x, ell_a64, ell_b64, seckey, 0, ellswift_xdh_raw, NULL);
    transcript_int(t, ret);
    if (ret) {
        transcript_put(t, x, sizeof(x));
        transcript_int(t, hashfp(shared, x, ell_a64, ell_b64, prefix));
        transcript_put(t, shared, sizeof(shared));
    }
}

/* x = u + s for s = -4(u^3 + 7)/(3u^2), which zeroes r = sqrt(-s(4(u^3 + 7) +
 * 3u^2 s)) in the x3 branches. Half the time x is not on the curve. */
static void ellswift_x_r_zero(secp256k1_fe *x, const secp256k1_fe *u) {
    secp256k1_fe u2, num, den;

    secp256k1_fe_sqr(&u2, u);
    secp256k1_fe_mul(&num, &u2, u);
    secp256k1_fe_add_int(&num, SECP256K1_B);
    secp256k1_fe_mul_int(&num, 4);
    den = u2;
    secp256k1_fe_mul_int(&den, 3);
    secp256k1_fe_inv_var(&den, &den);
    secp256k1_fe_mul(x, &num, &den);
    secp256k1_fe_negate(x, x, 1);
    secp256k1_fe_add(x, u);
    secp256k1_fe_normalize_var(x);
}

/* The encoder's inverse map, called directly: the public API hashes u, so only
 * here can u be chosen. c, the mode's low bits, picks the branch, where r = 0
 * fails the odd x3 ones and s = 0 the even ones. */
static void ellswift_inv(struct transcript *t, unsigned int mode, const unsigned char *u32,
                         const secp256k1_pubkey *pk) {
    secp256k1_ge p;
    secp256k1_fe u, x, res;
    unsigned char b32[32];
    int ret;

    secp256k1_fe_set_b32_mod(&u, u32);
    if (secp256k1_fe_normalizes_to_zero_var(&u)) {
        /* The inverse is undefined for u = 0. */
        secp256k1_fe_set_int(&u, 1);
    }
    secp256k1_pubkey_load(variant_ctx, &p, pk);
    x = p.x;
    switch ((mode >> 3) % ELLSWIFT_INV_KINDS) {
    case ELLSWIFT_INV_U_IS_X:
        u = x;
        break;
    case ELLSWIFT_INV_R_ZERO:
        ellswift_x_r_zero(&x, &u);
        break;
    }
    ret = secp256k1_ge_x_on_curve_var(&x);
    transcript_int(t, ret);
    if (!ret) {
        return;
    }
    ret = secp256k1_ellswift_xswiftec_inv_var(&res, &x, &u, (int)(mode & 7));
    transcript_int(t, ret);
    if (ret) {
        secp256k1_fe_normalize_var(&res);
        secp256k1_fe_get_b32(b32, &res);
        transcript_put(t, b32, sizeof(b32));
    }
}

static void ellswift_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[33];
    size_t len = sizeof(ser);

    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
}

/* Fills ell64 with party's own encoding, or with fallback if its key is invalid:
 * any 64 bytes are a valid encoding to hand the peer. */
static void ellswift_own_encoding(struct transcript *t, unsigned char *ell64, const unsigned char *seckey,
                                  const unsigned char *aux, const unsigned char *fallback) {
    int ret = secp256k1_ellswift_create(variant_ctx, ell64, seckey, aux);

    transcript_int(t, ret);
    if (ret) {
        transcript_put(t, ell64, 64);
    } else {
        memcpy(ell64, fallback, 64);
    }
}

static size_t target_ellswift(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char ell[64], rnd[32], seckey[2][32], aux[2][32], prefix[64], inv_u[32], ours[2][64], shared[32];
    secp256k1_pubkey pk;
    secp256k1_ellswift_xdh_hash_function hashfp;
    unsigned int flags, inv_mode;
    int party, ret;

    flags = reader_u8(&r);
    reader_take(&r, ell, sizeof(ell));
    reader_take(&r, rnd, sizeof(rnd));
    for (party = 0; party < 2; party++) {
        reader_take(&r, seckey[party], sizeof(seckey[party]));
        reader_take(&r, aux[party], sizeof(aux[party]));
    }
    reader_take(&r, prefix, sizeof(prefix));
    inv_mode = reader_u8(&r);
    reader_take(&r, inv_u, sizeof(inv_u));

    /* Every 64-byte string decodes to a point. */
    transcript_int(&t, secp256k1_ellswift_decode(variant_ctx, &pk, ell));
    ellswift_record_pubkey(&t, &pk);
    if (flags & ELLSWIFT_INV) {
        ellswift_inv(&t, inv_mode, inv_u, &pk);
    }
    if (flags & ELLSWIFT_ENCODE) {
        transcript_int(&t, secp256k1_ellswift_encode(variant_ctx, ours[0], &pk, rnd));
        transcript_put(&t, ours[0], sizeof(ours[0]));
        transcript_int(&t, secp256k1_ellswift_decode(variant_ctx, &pk, ours[0]));
        ellswift_record_pubkey(&t, &pk);
    }

    ellswift_own_encoding(&t, ours[0], seckey[0], (flags & ELLSWIFT_AUX0) ? aux[0] : NULL, ell);
    if (flags & ELLSWIFT_FUZZ_PEER) {
        memcpy(ours[1], ell, sizeof(ell));
    } else {
        ellswift_own_encoding(&t, ours[1], seckey[1], (flags & ELLSWIFT_AUX1) ? aux[1] : NULL, ell);
    }

    /* Both peers derive the session secret; with honest encodings they agree. */
    hashfp = (flags & ELLSWIFT_PREFIX) ? secp256k1_ellswift_xdh_hash_function_prefix
                                       : secp256k1_ellswift_xdh_hash_function_bip324;
    for (party = 0; party < 2; party++) {
        ret = secp256k1_ellswift_xdh(variant_ctx, shared, ours[0], ours[1], seckey[party], party, hashfp, prefix);
        transcript_int(&t, ret);
        if (ret) {
            transcript_put(&t, shared, sizeof(shared));
        }
    }
    if (flags & ELLSWIFT_RAW) {
        ellswift_raw_x(&t, ours[0], ours[1], seckey[0], hashfp, prefix);
    }

    return t.len;
}
