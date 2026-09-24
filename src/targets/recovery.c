/* ECDSA public key recovery, as Bitcoin Core's signmessage and verifymessage
 * use it. Like the ecdsa target, valid signatures are produced first and then
 * mutated, reaching recovery paths random bytes almost never hit.
 *
 * Input: mode, msg[32], then seckey[32] (+ ndata[32]) or raw sig64 and recid,
 * then mutations. */

static void recovery_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[65];
    size_t len;

    len = 33;
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
    len = 65;
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_UNCOMPRESSED);
    transcript_put(t, ser, len);
}

/* Recovers the key and checks the plain signature against it. */
static void recovery_record_checks(struct transcript *t, const secp256k1_ecdsa_recoverable_signature *rsig,
                                   const unsigned char *msg) {
    secp256k1_ecdsa_signature sig, low;
    secp256k1_pubkey pk;
    unsigned char sig64[64];
    int recid, ok;

    secp256k1_ecdsa_recoverable_signature_serialize_compact(variant_ctx, sig64, &recid, rsig);
    transcript_put(t, sig64, sizeof(sig64));
    transcript_int(t, recid);
    secp256k1_ecdsa_recoverable_signature_convert(variant_ctx, &sig, rsig);
    secp256k1_ecdsa_signature_serialize_compact(variant_ctx, sig64, &sig);
    transcript_put(t, sig64, sizeof(sig64));

    ok = secp256k1_ecdsa_recover(variant_ctx, &pk, rsig, msg);
    transcript_int(t, ok);
    if (ok) {
        recovery_record_pubkey(t, &pk);
        /* Verify rejects high S, so check the normalized form too. */
        transcript_int(t, secp256k1_ecdsa_verify(variant_ctx, &sig, msg, &pk));
        transcript_int(t, secp256k1_ecdsa_signature_normalize(variant_ctx, &low, &sig));
        transcript_int(t, secp256k1_ecdsa_verify(variant_ctx, &low, msg, &pk));
    }
}

static size_t target_recovery(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], ndata[32], sig64[64];
    secp256k1_ecdsa_recoverable_signature rsig;
    unsigned int mode, nmut, i;
    int ok, recid;

    mode = reader_u8(&r);
    reader_take(&r, msg, sizeof(msg));
    memset(sig64, 0, sizeof(sig64));
    recid = 0;

    if (mode & 1) {
        reader_take(&r, seckey, sizeof(seckey));
        if (mode & 2) {
            reader_take(&r, ndata, sizeof(ndata));
        }
        ok = secp256k1_ecdsa_sign_recoverable(variant_ctx, &rsig, msg, seckey, NULL, (mode & 2) ? ndata : NULL);
        transcript_int(&t, ok);
        if (ok) {
            secp256k1_ecdsa_recoverable_signature_serialize_compact(variant_ctx, sig64, &recid, &rsig);
            transcript_put(&t, sig64, sizeof(sig64));
            transcript_int(&t, recid);
        }
    } else {
        reader_take(&r, sig64, sizeof(sig64));
        recid = (int)(reader_u8(&r) & 3);
    }

    nmut = reader_u8(&r) % 8;
    for (i = 0; i < nmut; i++) {
        unsigned int which = reader_u8(&r) % 3, pos = reader_u8(&r), mask = reader_u8(&r);

        switch (which) {
        case 0: sig64[pos % sizeof(sig64)] ^= (unsigned char)mask; break;
        case 1: msg[pos % sizeof(msg)] ^= (unsigned char)mask; break;
        default: recid ^= (int)(mask & 3); break;
        }
    }

    /* recid outside 0..3 is an illegal argument, and the mutations keep it inside. */
    ok = secp256k1_ecdsa_recoverable_signature_parse_compact(variant_ctx, &rsig, sig64, recid);
    transcript_int(&t, ok);
    if (ok) {
        recovery_record_checks(&t, &rsig, msg);
    }

    return t.len;
}
