/* ECDSA as Bitcoin Core uses it in consensus: pubkey parsing, strict and lax DER,
 * low-S normalization and verification. Signing yields valid signatures that the
 * mutations then perturb, reaching verify paths random bytes almost never hit.
 * Constructed keys reach the ones no signer can: verification recomputing R at
 * infinity, or with an x at least the group order.
 *
 * Input: mode, msg[32], then seckey[32] (+ ndata[32]), or R's kind, x[32] and
 * sig64 to construct the key from, or raw pubkey and sig64; then mutations, and
 * the rest is parsed as a DER signature. */

enum ecdsa_mode {
    ECDSA_SIGN = 1 << 0,
    ECDSA_COMPRESSED = 1 << 1,
    ECDSA_NDATA = 1 << 2,      /* sign with extra nonce data */
    ECDSA_CONSTRUCT = 1 << 3   /* without ECDSA_SIGN, construct the key from R */
};

enum ecdsa_r {
    ECDSA_R_INFINITY,
    ECDSA_R_FROM_X,
    ECDSA_R_ABOVE_ORDER,
    ECDSA_R_COUNT
};

static void ecdsa_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[65];
    size_t len;

    len = 33;
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
    len = 65;
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_UNCOMPRESSED);
    transcript_put(t, ser, len);
}

static void ecdsa_record_sig(struct transcript *t, const secp256k1_ecdsa_signature *sig) {
    unsigned char der[72], compact[64];
    size_t len = sizeof(der);
    int ret;

    ret = secp256k1_ecdsa_signature_serialize_der(variant_ctx, der, &len, sig);
    transcript_int(t, ret);
    if (ret) {
        transcript_put(t, der, len);
    }
    secp256k1_ecdsa_signature_serialize_compact(variant_ctx, compact, sig);
    transcript_put(t, compact, sizeof(compact));
}

/* Records normalization and, when a pubkey is available, verification. */
static void ecdsa_record_checks(struct transcript *t, const secp256k1_ecdsa_signature *sig,
                                const unsigned char *msg, const secp256k1_pubkey *pk) {
    secp256k1_ecdsa_signature low;

    ecdsa_record_sig(t, sig);
    transcript_int(t, secp256k1_ecdsa_signature_normalize(variant_ctx, &low, sig));
    ecdsa_record_sig(t, &low);
    if (pk != NULL) {
        transcript_int(t, secp256k1_ecdsa_verify(variant_ctx, sig, msg, pk));
        transcript_int(t, secp256k1_ecdsa_verify(variant_ctx, &low, msg, pk));
    }
}

/* Sets pkser to P = r^-1 (s*R - z*G), so verifying sig64 on msg against P
 * recomputes exactly R, and sets sig64's r to x(R) mod n unless R is infinity.
 * Returns 0 when R or P is not a valid point. */
static int ecdsa_construct(unsigned char *pkser, size_t pklen, unsigned char *sig64, const unsigned char *msg,
                           unsigned int kind, int odd, const unsigned char *x32) {
    secp256k1_scalar r, s, z, rinv, zr, na, ng;
    secp256k1_gej rj, pj;
    secp256k1_ge ge;
    secp256k1_fe x;
    secp256k1_pubkey pk;
    unsigned char b32[32];
    size_t len = pklen;

    secp256k1_scalar_set_b32(&r, sig64, NULL);
    secp256k1_scalar_set_b32(&s, sig64 + 32, NULL);
    secp256k1_scalar_set_b32(&z, msg, NULL);
    if (kind == ECDSA_R_INFINITY) {
        secp256k1_gej_set_infinity(&rj);
    } else {
        if (kind == ECDSA_R_ABOVE_ORDER) {
            /* n plus the low 128 bits of x32, which stays below p. */
            memset(b32, 0, 16);
            memcpy(b32 + 16, x32 + 16, 16);
            secp256k1_fe_set_b32_mod(&x, b32);
            secp256k1_fe_add(&x, &secp256k1_ecdsa_const_order_as_fe);
            secp256k1_fe_normalize_var(&x);
        } else if (!secp256k1_fe_set_b32_limit(&x, x32)) {
            return 0;
        }
        if (!secp256k1_ge_set_xo_var(&ge, &x, odd)) {
            return 0;
        }
        secp256k1_gej_set_ge(&rj, &ge);
        secp256k1_fe_get_b32(b32, &x);
        secp256k1_scalar_set_b32(&r, b32, NULL);
    }

    /* A zero r has no inverse and makes P infinity. */
    secp256k1_scalar_inverse_var(&rinv, &r);
    secp256k1_scalar_mul(&na, &s, &rinv);
    secp256k1_scalar_mul(&zr, &z, &rinv);
    secp256k1_scalar_negate(&ng, &zr);
    secp256k1_ecmult(&pj, &rj, &na, &ng);
    if (secp256k1_gej_is_infinity(&pj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&ge, &pj);
    secp256k1_pubkey_save(&pk, &ge);
    secp256k1_ec_pubkey_serialize(variant_ctx, pkser, &len, &pk,
                                  pklen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    /* Reduced, so the signature parses. */
    secp256k1_scalar_get_b32(sig64, &r);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static size_t target_ecdsa(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], ndata[32], x32[32], pkser[65], sig64[64];
    size_t pklen;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    unsigned int mode, kind, nmut, i;
    int ok, pk_ok;

    mode = reader_u8(&r);
    pklen = (mode & ECDSA_COMPRESSED) ? 33 : 65;
    reader_take(&r, msg, sizeof(msg));
    memset(pkser, 0, sizeof(pkser));
    memset(sig64, 0, sizeof(sig64));

    if (mode & ECDSA_SIGN) {
        reader_take(&r, seckey, sizeof(seckey));
        ok = secp256k1_ec_pubkey_create(variant_ctx, &pk, seckey);
        transcript_int(&t, ok);
        if (ok) {
            secp256k1_ec_pubkey_serialize(variant_ctx, pkser, &pklen, &pk,
                                          (mode & ECDSA_COMPRESSED) ? SECP256K1_EC_COMPRESSED
                                                                    : SECP256K1_EC_UNCOMPRESSED);
            if (mode & ECDSA_NDATA) {
                reader_take(&r, ndata, sizeof(ndata));
            }
            ok = secp256k1_ecdsa_sign(variant_ctx, &sig, msg, seckey, NULL, (mode & ECDSA_NDATA) ? ndata : NULL);
            transcript_int(&t, ok);
            if (ok) {
                secp256k1_ecdsa_signature_serialize_compact(variant_ctx, sig64, &sig);
                transcript_put(&t, sig64, sizeof(sig64));
            }
        }
    } else if (mode & ECDSA_CONSTRUCT) {
        kind = reader_u8(&r);
        reader_take(&r, x32, sizeof(x32));
        reader_take(&r, sig64, sizeof(sig64));
        transcript_int(&t, ecdsa_construct(pkser, pklen, sig64, msg, (kind >> 1) % ECDSA_R_COUNT,
                                           (int)(kind & 1), x32));
    } else {
        reader_take(&r, pkser, pklen);
        reader_take(&r, sig64, sizeof(sig64));
    }

    nmut = reader_u8(&r) % 8;
    for (i = 0; i < nmut; i++) {
        unsigned int which = reader_u8(&r) % 3, pos = reader_u8(&r), mask = reader_u8(&r);

        switch (which) {
        case 0: sig64[pos % sizeof(sig64)] ^= (unsigned char)mask; break;
        case 1: msg[pos % sizeof(msg)] ^= (unsigned char)mask; break;
        default: pkser[pos % pklen] ^= (unsigned char)mask; break;
        }
    }

    pk_ok = secp256k1_ec_pubkey_parse(variant_ctx, &pk, pkser, pklen);
    transcript_int(&t, pk_ok);
    if (pk_ok) {
        ecdsa_record_pubkey(&t, &pk);
    }

    ok = secp256k1_ecdsa_signature_parse_compact(variant_ctx, &sig, sig64);
    transcript_int(&t, ok);
    if (ok) {
        ecdsa_record_checks(&t, &sig, msg, pk_ok ? &pk : NULL);
    }

    ok = secp256k1_ecdsa_signature_parse_der(variant_ctx, &sig, r.p, r.left);
    transcript_int(&t, ok);
    if (ok) {
        ecdsa_record_checks(&t, &sig, msg, pk_ok ? &pk : NULL);
    }

    ok = ecdsa_signature_parse_der_lax(variant_ctx, &sig, r.p, r.left);
    transcript_int(&t, ok);
    if (ok) {
        ecdsa_record_checks(&t, &sig, msg, pk_ok ? &pk : NULL);
    }

    return t.len;
}
