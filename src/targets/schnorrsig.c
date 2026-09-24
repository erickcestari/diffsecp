/* BIP340 and the taproot commitment check, the Schnorr paths Bitcoin Core uses in
 * consensus. Like the ECDSA target, valid signatures are produced first and then
 * mutated.
 *
 * Input: mode, msg[32], then seckey[32] + aux[32] or raw xonly_pk[32] and sig64,
 * then mutations, then tweak[32] and a mutation of the tweaked key. */

static void schnorrsig_record_tweak(struct transcript *t, struct reader *r,
                                    const secp256k1_xonly_pubkey *internal) {
    unsigned char tweak[32], tweaked32[32];
    secp256k1_pubkey tweaked;
    secp256k1_xonly_pubkey tweaked_xonly;
    unsigned int flip, pos, mask;
    int parity, ok;

    reader_take(r, tweak, sizeof(tweak));
    ok = secp256k1_xonly_pubkey_tweak_add(variant_ctx, &tweaked, internal, tweak);
    transcript_int(t, ok);
    if (!ok) {
        return;
    }
    ok = secp256k1_xonly_pubkey_from_pubkey(variant_ctx, &tweaked_xonly, &parity, &tweaked);
    transcript_int(t, ok);
    if (!ok) {
        return;
    }
    secp256k1_xonly_pubkey_serialize(variant_ctx, tweaked32, &tweaked_xonly);
    transcript_int(t, parity);
    transcript_put(t, tweaked32, sizeof(tweaked32));
    transcript_int(t, secp256k1_xonly_pubkey_tweak_add_check(variant_ctx, tweaked32, parity, internal, tweak));

    flip = reader_u8(r);
    pos = reader_u8(r);
    mask = reader_u8(r);
    parity ^= (int)(flip & 1);
    tweaked32[pos % sizeof(tweaked32)] ^= (unsigned char)mask;
    transcript_int(t, secp256k1_xonly_pubkey_tweak_add_check(variant_ctx, tweaked32, parity, internal, tweak));
}

static size_t target_schnorrsig(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], aux[32], pk32[32], sig64[64];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk;
    unsigned int mode, nmut, i;
    int ok, parity;

    mode = reader_u8(&r);
    reader_take(&r, msg, sizeof(msg));
    memset(pk32, 0, sizeof(pk32));
    memset(sig64, 0, sizeof(sig64));

    if (mode & 1) {
        reader_take(&r, seckey, sizeof(seckey));
        reader_take(&r, aux, sizeof(aux));
        ok = secp256k1_keypair_create(variant_ctx, &keypair, seckey);
        transcript_int(&t, ok);
        if (ok) {
            secp256k1_keypair_xonly_pub(variant_ctx, &pk, &parity, &keypair);
            secp256k1_xonly_pubkey_serialize(variant_ctx, pk32, &pk);
            transcript_int(&t, parity);
            transcript_put(&t, pk32, sizeof(pk32));
            ok = secp256k1_schnorrsig_sign32(variant_ctx, sig64, msg, &keypair, (mode & 2) ? aux : NULL);
            transcript_int(&t, ok);
            transcript_put(&t, sig64, sizeof(sig64));
        }
    } else {
        reader_take(&r, pk32, sizeof(pk32));
        reader_take(&r, sig64, sizeof(sig64));
    }

    nmut = reader_u8(&r) % 8;
    for (i = 0; i < nmut; i++) {
        unsigned int which = reader_u8(&r) % 3, pos = reader_u8(&r), mask = reader_u8(&r);

        switch (which) {
        case 0: sig64[pos % sizeof(sig64)] ^= (unsigned char)mask; break;
        case 1: msg[pos % sizeof(msg)] ^= (unsigned char)mask; break;
        default: pk32[pos % sizeof(pk32)] ^= (unsigned char)mask; break;
        }
    }

    ok = secp256k1_xonly_pubkey_parse(variant_ctx, &pk, pk32);
    transcript_int(&t, ok);
    if (ok) {
        transcript_int(&t, secp256k1_schnorrsig_verify(variant_ctx, sig64, msg, sizeof(msg), &pk));
        schnorrsig_record_tweak(&t, &r, &pk);
    }

    return t.len;
}
