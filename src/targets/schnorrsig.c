/* BIP340 and the taproot commitment check, the Schnorr paths Bitcoin Core uses in
 * consensus. Like the ECDSA target, valid signatures are produced first and then
 * mutated.
 *
 * Input: mode, msg[32], then seckey[32] + aux[32] or raw xonly_pk[32] and sig64,
 * then mutations, then tweak[32] and a mutation of the tweaked key, then a
 * variable-length message, nonce[32] and a signature mutation. Mode bit 3 turns
 * the signature into one whose R has an odd y. */

/* Turns a valid signature (r, s) into (r, 2ed - s), which verification computes
 * as -R: the right x with an odd y, which BIP340 rejects. Only the signer's key
 * produces one, so fuzzed bytes never do. */
static int schnorrsig_odd_r(unsigned char *sig64, const unsigned char *msg32, const secp256k1_keypair *keypair,
                            int parity, const unsigned char *pk32) {
    static const unsigned char tag[] = "BIP0340/challenge";
    unsigned char buf[96], e[32], d[32], ed[32], neg_s[32];

    memcpy(buf, sig64, 32);
    memcpy(buf + 32, pk32, 32);
    memcpy(buf + 64, msg32, 32);
    memcpy(neg_s, sig64 + 32, 32);
    /* BIP340 signs with the key whose public key has an even y. */
    if (!secp256k1_tagged_sha256(variant_ctx, e, tag, sizeof(tag) - 1, buf, sizeof(buf)) ||
        !secp256k1_keypair_sec(variant_ctx, d, keypair) ||
        (parity && !secp256k1_ec_seckey_negate(variant_ctx, d)) ||
        !secp256k1_ec_seckey_tweak_mul(variant_ctx, d, e)) {
        return 0;
    }
    memcpy(ed, d, sizeof(d));
    if (!secp256k1_ec_seckey_tweak_add(variant_ctx, d, ed) ||
        !secp256k1_ec_seckey_negate(variant_ctx, neg_s) ||
        !secp256k1_ec_seckey_tweak_add(variant_ctx, d, neg_s)) {
        return 0;
    }
    memcpy(sig64 + 32, d, sizeof(d));
    return 1;
}

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

/* Returns the fuzzed nonce in data, so signing reaches a zero nonce and nonces
 * above the group order. */
static int schnorrsig_fixed_nonce(unsigned char *nonce32, const unsigned char *msg, size_t msglen,
                                  const unsigned char *key32, const unsigned char *xonly_pk32,
                                  const unsigned char *algo, size_t algolen, void *data) {
    (void)msg;
    (void)msglen;
    (void)key32;
    (void)xonly_pk32;
    (void)algo;
    (void)algolen;
    memcpy(nonce32, data, 32);
    return 1;
}

/* BIP340 takes messages of any length, which only sign_custom and verify
 * accept. pk is the parsed, possibly mutated key; signer and keypair are set
 * when the input signed. */
static void schnorrsig_record_custom(struct transcript *t, struct reader *r, unsigned int mode,
                                     const unsigned char *sig64, const secp256k1_xonly_pubkey *pk,
                                     const secp256k1_keypair *keypair, const secp256k1_xonly_pubkey *signer) {
    secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    unsigned char msg[255], nonce[32], sig[64];
    size_t msglen;
    unsigned int pos, mask;
    int ok;

    msglen = reader_u8(r);
    reader_take(r, msg, msglen);
    reader_take(r, nonce, sizeof(nonce));
    pos = reader_u8(r);
    mask = reader_u8(r);

    if (pk != NULL) {
        transcript_int(t, secp256k1_schnorrsig_verify(variant_ctx, sig64, msg, msglen, pk));
    }
    if (keypair == NULL) {
        return;
    }
    /* Mode bit 2 signs with the fuzzed nonce, otherwise the BIP340 nonce
     * function takes it as aux_rand when bit 1 is set. */
    if (mode & 4) {
        extraparams.noncefp = schnorrsig_fixed_nonce;
    }
    extraparams.ndata = (mode & 6) ? nonce : NULL;
    ok = secp256k1_schnorrsig_sign_custom(variant_ctx, sig, msg, msglen, keypair, &extraparams);
    transcript_int(t, ok);
    if (ok) {
        transcript_put(t, sig, sizeof(sig));
        sig[pos % sizeof(sig)] ^= (unsigned char)mask;
        transcript_int(t, secp256k1_schnorrsig_verify(variant_ctx, sig, msg, msglen, signer));
    }
}

static size_t target_schnorrsig(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    unsigned char msg[32], seckey[32], aux[32], pk32[32], sig64[64];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pk, signer;
    unsigned int mode, nmut, i;
    int ok, parity, signed_ok = 0;

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
            signed_ok = 1;
            secp256k1_keypair_xonly_pub(variant_ctx, &signer, &parity, &keypair);
            secp256k1_xonly_pubkey_serialize(variant_ctx, pk32, &signer);
            transcript_int(&t, parity);
            transcript_put(&t, pk32, sizeof(pk32));
            ok = secp256k1_schnorrsig_sign32(variant_ctx, sig64, msg, &keypair, (mode & 2) ? aux : NULL);
            transcript_int(&t, ok);
            transcript_put(&t, sig64, sizeof(sig64));
            if (mode & 8) {
                transcript_int(&t, schnorrsig_odd_r(sig64, msg, &keypair, parity, pk32));
                transcript_put(&t, sig64, sizeof(sig64));
            }
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
    schnorrsig_record_custom(&t, &r, mode, sig64, ok ? &pk : NULL, signed_ok ? &keypair : NULL, &signer);

    return t.len;
}
