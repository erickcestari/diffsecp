/* ECDSA as Bitcoin Core uses it in consensus: pubkey parsing, strict and lax DER,
 * low-S normalization and verification. Signing yields valid signatures that the
 * mutations then perturb, reaching verify paths random bytes almost never hit.
 *
 * Input: mode, msg[32], then seckey[32] (+ ndata[32]) or raw pubkey and sig64,
 * then mutations, and the rest is parsed as a DER signature. */

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

static size_t target_ecdsa(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], ndata[32], pkser[65], sig64[64];
    size_t pklen;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    unsigned int mode, nmut, i;
    int ok, pk_ok;

    mode = reader_u8(&r);
    pklen = (mode & 2) ? 33 : 65;
    reader_take(&r, msg, sizeof(msg));
    memset(pkser, 0, sizeof(pkser));
    memset(sig64, 0, sizeof(sig64));

    if (mode & 1) {
        reader_take(&r, seckey, sizeof(seckey));
        ok = secp256k1_ec_pubkey_create(variant_ctx, &pk, seckey);
        transcript_int(&t, ok);
        if (ok) {
            secp256k1_ec_pubkey_serialize(variant_ctx, pkser, &pklen, &pk,
                                          (mode & 2) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
            if (mode & 4) {
                reader_take(&r, ndata, sizeof(ndata));
            }
            ok = secp256k1_ecdsa_sign(variant_ctx, &sig, msg, seckey, NULL, (mode & 4) ? ndata : NULL);
            transcript_int(&t, ok);
            if (ok) {
                secp256k1_ecdsa_signature_serialize_compact(variant_ctx, sig64, &sig);
                transcript_put(&t, sig64, sizeof(sig64));
            }
        }
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
