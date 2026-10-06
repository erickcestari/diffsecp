/* ECDSA as Bitcoin Core uses it in consensus: pubkey parsing, strict and lax DER,
 * low-S normalization and verification. Signing yields valid signatures that the
 * mutations then perturb, reaching verify paths random bytes almost never hit.
 * Constructed keys reach the ones no signer can: verification recomputing R at
 * infinity, or with an x at least the group order.
 *
 * Input: mode, msg[32], then seckey[32] (+ ndata[32]) (+ the nonce function's
 * flags and two nonces[32]), or R's kind, x[32] and sig64 to construct the key
 * from, or raw pubkey and sig64; then a built DER
 * encoding (ecdsa_der_build) in DER_BUILD mode; then mutations, and the rest is
 * parsed as a DER signature, after sig64's DER encoding in DER mode or the built
 * one in DER_BUILD mode. */

enum ecdsa_mode {
    ECDSA_SIGN = 1 << 0,
    ECDSA_COMPRESSED = 1 << 1,
    ECDSA_NDATA = 1 << 2,      /* sign with extra nonce data */
    ECDSA_CONSTRUCT = 1 << 3,  /* without ECDSA_SIGN, construct the key from R */
    ECDSA_DER = 1 << 4,        /* DER-encode sig64, so mutations reach the strict parser */
    ECDSA_DER_BUILD = 1 << 5,  /* build a DER encoding from fuzzed integers instead */
    ECDSA_NONCE = 1 << 6       /* with ECDSA_SIGN, sign through ecdsa_nonce */
};

enum ecdsa_r {
    ECDSA_R_INFINITY,
    ECDSA_R_FROM_X,
    ECDSA_R_ABOVE_ORDER,
    ECDSA_R_COUNT
};

/* The longest encoding (a built one: 30 82 LL, then two of 02 81 L and 255
 * bytes, and 3 more inside the sequence), one byte inserted per mutation, and
 * the rest of the input. */
#define ECDSA_DER_MAX (4 + 2 * (3 + 255) + 3 + 8 + DIFFSECP_INPUT_MAX)

/* Writes DER length octets for len and returns their count: the short form,
 * unless long_form asks for the long one, which DER forbids below 128. */
static size_t ecdsa_der_len(unsigned char *out, size_t len, int long_form) {
    if (len < 128 && !long_form) {
        out[0] = (unsigned char)len;
        return 1;
    }
    if (len < 256) {
        out[0] = 0x81;
        out[1] = (unsigned char)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)len;
    return 3;
}

/* A DER signature built from two fuzzed integers of up to 255 bytes, with the
 * lengths computed. Flags pick long-form lengths (bit 0 the sequence's, bits 1
 * and 2 the integers') and a sequence length short by bits 3-4, or with bit 5
 * that many input bytes after the integers, inside the sequence. Mutating a
 * signer's encoding almost never keeps every length consistent, and the strict
 * parser checks lengths before anything else, so its length and padding rules
 * are only reached this way. */
static size_t ecdsa_der_build(struct reader *r, unsigned char *der) {
    unsigned int flags = reader_u8(r), i;
    unsigned char body[2 * (3 + 255) + 3];
    size_t n = 0, len, pos, short_by = flags >> 3 & 3;

    for (i = 0; i < 2; i++) {
        len = reader_u8(r);
        body[n++] = 0x02;
        n += ecdsa_der_len(body + n, len, (int)(flags >> (1 + i) & 1));
        reader_take(r, body + n, len);
        n += len;
    }
    if (flags & 32) {
        reader_take(r, body + n, short_by);
        n += short_by;
        short_by = 0;
    }
    der[0] = 0x30;
    pos = 1 + ecdsa_der_len(der + 1, n - short_by, (int)(flags & 1));
    memcpy(der + pos, body, n);
    return pos + n;
}

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
        /* A byte too small fails, and reports the size it needs. */
        len--;
        transcript_int(t, secp256k1_ecdsa_signature_serialize_der(variant_ctx, der, &len, sig));
        transcript_u32(t, (uint32_t)len);
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
    /* Without an output, it only tells whether s is high. */
    transcript_int(t, secp256k1_ecdsa_signature_normalize(variant_ctx, NULL, sig));
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

enum ecdsa_nonce_flag {
    ECDSA_NONCE_ZERO_S = 1 << 4,   /* pick msg so the first fixed nonce gives s = 0 */
    ECDSA_NONCE_ALGO = 1 << 5,     /* RFC6979 attempts pass an algorithm name */
    ECDSA_NONCE_DEFAULT = 1 << 6   /* the exported RFC6979 pointer, which signing treats as the default */
};

/* Signing retries until the nonce function gives a nonce that signs. Its first
 * n_fixed attempts return fuzzed nonces, so it reaches the retries no RFC6979
 * output does: a zero nonce, one at least the order, one giving s = 0. The
 * attempt numbered fail_at fails the signing (3 is never reached). The rest
 * come from the exported RFC6979 function, which a retry calls with a nonzero
 * counter. */
struct ecdsa_nonce {
    unsigned char fixed[2][32];
    unsigned int n_fixed, fail_at;
    const unsigned char *algo16, *ndata;
};

static int ecdsa_nonce(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32,
                       const unsigned char *algo16, void *data, unsigned int counter) {
    const struct ecdsa_nonce *n = data;

    (void)algo16;
    if (counter == n->fail_at) {
        return 0;
    }
    if (counter < n->n_fixed) {
        memcpy(nonce32, n->fixed[counter], 32);
        return 1;
    }
    return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, n->algo16, (void *)n->ndata, counter);
}

/* Sets msg32 to -r*d for r = x(k*G) mod n, so signing with nonce k computes
 * s = k^-1 (msg + r*d) = 0 and must retry. */
static int ecdsa_zero_s(unsigned char *msg32, const unsigned char *seckey, const unsigned char *k32) {
    secp256k1_pubkey kg;
    secp256k1_scalar r, d;
    unsigned char ser[33];
    size_t len = sizeof(ser);

    if (!secp256k1_ec_pubkey_create(variant_ctx, &kg, k32)) {
        return 0;
    }
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, &kg, SECP256K1_EC_COMPRESSED);
    secp256k1_scalar_set_b32(&r, ser + 1, NULL);
    secp256k1_scalar_set_b32(&d, seckey, NULL);
    secp256k1_scalar_mul(&r, &r, &d);
    secp256k1_scalar_negate(&r, &r);
    secp256k1_scalar_get_b32(msg32, &r);
    return 1;
}

/* Signs through ecdsa_nonce, configured by a flags byte (bits 0-1 n_fixed,
 * bits 2-3 fail_at, then ecdsa_nonce_flag), or through the exported RFC6979
 * pointer. */
static int ecdsa_sign_nonce(struct transcript *t, struct reader *r, secp256k1_ecdsa_signature *sig,
                            unsigned char *msg, const unsigned char *seckey, const unsigned char *ndata) {
    static const unsigned char algo16[17] = "diffsecp/ecdsa16";
    struct ecdsa_nonce n;
    unsigned int flags = reader_u8(r);

    reader_take(r, n.fixed[0], sizeof(n.fixed[0]));
    reader_take(r, n.fixed[1], sizeof(n.fixed[1]));
    if (flags & ECDSA_NONCE_DEFAULT) {
        return secp256k1_ecdsa_sign(variant_ctx, sig, msg, seckey, secp256k1_nonce_function_rfc6979, ndata);
    }
    n.n_fixed = (flags & 3) % 3;
    n.fail_at = flags >> 2 & 3;
    n.algo16 = (flags & ECDSA_NONCE_ALGO) ? algo16 : NULL;
    n.ndata = ndata;
    if (flags & ECDSA_NONCE_ZERO_S) {
        transcript_int(t, ecdsa_zero_s(msg, seckey, n.fixed[0]));
    }
    return secp256k1_ecdsa_sign(variant_ctx, sig, msg, seckey, ecdsa_nonce, &n);
}

static size_t target_ecdsa(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], ndata[32], x32[32], pkser[65], sig64[64], der[ECDSA_DER_MAX];
    size_t pklen, derlen, tail;
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
            if (mode & ECDSA_NONCE) {
                ok = ecdsa_sign_nonce(&t, &r, &sig, msg, seckey, (mode & ECDSA_NDATA) ? ndata : NULL);
            } else {
                ok = secp256k1_ecdsa_sign(variant_ctx, &sig, msg, seckey, NULL, (mode & ECDSA_NDATA) ? ndata : NULL);
            }
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

    derlen = 0;
    if (mode & ECDSA_DER_BUILD) {
        derlen = ecdsa_der_build(&r, der);
    } else if ((mode & ECDSA_DER) && secp256k1_ecdsa_signature_parse_compact(variant_ctx, &sig, sig64)) {
        derlen = ECDSA_DER_MAX;
        transcript_int(&t, secp256k1_ecdsa_signature_serialize_der(variant_ctx, der, &derlen, &sig));
    }

    nmut = reader_u8(&r) % 8;
    for (i = 0; i < nmut; i++) {
        unsigned int which = reader_u8(&r) % 5, pos = reader_u8(&r), mask = reader_u8(&r);

        switch (which) {
        case 0: sig64[pos % sizeof(sig64)] ^= (unsigned char)mask; break;
        case 1: msg[pos % sizeof(msg)] ^= (unsigned char)mask; break;
        case 2: pkser[pos % pklen] ^= (unsigned char)mask; break;
        case 3:
            if (derlen > 0) {
                der[pos % derlen] ^= (unsigned char)mask;
            }
            break;
        default:
            /* Inserting reaches padding and long-form lengths, which XOR can't. */
            pos %= derlen + 1;
            memmove(der + pos + 1, der + pos, derlen - pos);
            der[pos] = (unsigned char)mask;
            derlen++;
            break;
        }
    }
    /* Trailing bytes, or the whole encoding outside DER mode. */
    tail = r.left;
    reader_take(&r, der + derlen, tail);
    derlen += tail;

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

    ok = secp256k1_ecdsa_signature_parse_der(variant_ctx, &sig, der, derlen);
    transcript_int(&t, ok);
    if (ok) {
        ecdsa_record_checks(&t, &sig, msg, pk_ok ? &pk : NULL);
    }

    ok = ecdsa_signature_parse_der_lax(variant_ctx, &sig, der, derlen);
    transcript_int(&t, ok);
    if (ok) {
        ecdsa_record_checks(&t, &sig, msg, pk_ok ? &pk : NULL);
    }

    return t.len;
}
