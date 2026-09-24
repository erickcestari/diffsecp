/* MuSig2 (BIP327) end to end: key aggregation with optional tweaks, nonce
 * generation, aggregation and processing, partial signing and verification,
 * and the final BIP340 signature. A fuzzed nonce, aggregate nonce or partial
 * signature can replace an honest one, reaching the parsers and the failing
 * verification paths.
 *
 * Every object handed back to the library must come from a successful call:
 * the API checks their magic, and signing zeroes the secnonce, so using one
 * twice is an illegal argument. The protocol stops at the first failure.
 *
 * Input: flags, signer count, victim, msg[32], extra[32], two tweaks, per
 * signer seckey[32] and secrand[32], then fuzzed pubnonce[66], aggnonce[66]
 * and partial_sig[32]. */

#define MUSIG_MAX_SIGNERS 3

enum musig_flag {
    MUSIG_SORT = 1 << 0,
    MUSIG_EC_TWEAK = 1 << 1,
    MUSIG_XONLY_TWEAK = 1 << 2,
    MUSIG_COUNTER = 1 << 3,         /* nonce_gen_counter instead of nonce_gen */
    MUSIG_NONCE_INPUTS = 1 << 4,    /* pass nonce generation its optional inputs */
    MUSIG_FUZZ_PUBNONCE = 1 << 5,
    MUSIG_FUZZ_AGGNONCE = 1 << 6,
    MUSIG_FUZZ_PARTIAL_SIG = 1 << 7
};

struct musig_input {
    unsigned int flags, n, victim;
    unsigned char msg[32], extra[32], tweak[2][32];
    unsigned char seckey[MUSIG_MAX_SIGNERS][32], secrand[MUSIG_MAX_SIGNERS][32];
    unsigned char pubnonce[66], aggnonce[66], partial_sig[32];
};

static void musig_read(struct reader *r, struct musig_input *in) {
    unsigned int i;

    in->flags = reader_u8(r);
    in->n = 1 + reader_u8(r) % MUSIG_MAX_SIGNERS;
    in->victim = reader_u8(r) % in->n;
    reader_take(r, in->msg, sizeof(in->msg));
    reader_take(r, in->extra, sizeof(in->extra));
    reader_take(r, in->tweak[0], sizeof(in->tweak[0]));
    reader_take(r, in->tweak[1], sizeof(in->tweak[1]));
    for (i = 0; i < in->n; i++) {
        reader_take(r, in->seckey[i], sizeof(in->seckey[i]));
        reader_take(r, in->secrand[i], sizeof(in->secrand[i]));
    }
    reader_take(r, in->pubnonce, sizeof(in->pubnonce));
    reader_take(r, in->aggnonce, sizeof(in->aggnonce));
    reader_take(r, in->partial_sig, sizeof(in->partial_sig));
}

static void musig_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[33];
    size_t len = sizeof(ser);

    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
}

static size_t target_musig(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    struct musig_input mi;
    unsigned char ser[66], sig64[64];
    secp256k1_keypair keypair[MUSIG_MAX_SIGNERS];
    secp256k1_pubkey pubkey[MUSIG_MAX_SIGNERS], agg;
    const secp256k1_pubkey *pubkey_ptrs[MUSIG_MAX_SIGNERS];
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_musig_keyagg_cache cache;
    secp256k1_musig_secnonce secnonce[MUSIG_MAX_SIGNERS];
    secp256k1_musig_pubnonce pubnonce[MUSIG_MAX_SIGNERS], fuzz_pubnonce;
    const secp256k1_musig_pubnonce *pubnonce_ptrs[MUSIG_MAX_SIGNERS];
    secp256k1_musig_aggnonce aggnonce, fuzz_aggnonce;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig psig[MUSIG_MAX_SIGNERS], fuzz_psig;
    const secp256k1_musig_partial_sig *psig_ptrs[MUSIG_MAX_SIGNERS];
    unsigned int i, j;
    int ok, parity;

    musig_read(&r, &mi);

    /* Key aggregation, optionally over the sorted keys as BIP327 suggests. */
    for (i = 0; i < mi.n; i++) {
        ok = secp256k1_keypair_create(variant_ctx, &keypair[i], mi.seckey[i]);
        transcript_int(&t, ok);
        if (!ok) {
            return t.len;
        }
        secp256k1_keypair_pub(variant_ctx, &pubkey[i], &keypair[i]);
        pubkey_ptrs[i] = &pubkey[i];
    }
    if (mi.flags & MUSIG_SORT) {
        transcript_int(&t, secp256k1_ec_pubkey_sort(variant_ctx, pubkey_ptrs, mi.n));
    }
    ok = secp256k1_musig_pubkey_agg(variant_ctx, &agg_xonly, &cache, pubkey_ptrs, mi.n);
    transcript_int(&t, ok);
    if (!ok) {
        return t.len;
    }
    secp256k1_xonly_pubkey_serialize(variant_ctx, ser, &agg_xonly);
    transcript_put(&t, ser, 32);
    transcript_int(&t, secp256k1_musig_pubkey_get(variant_ctx, &agg, &cache));
    musig_record_pubkey(&t, &agg);

    /* Tweaks as BIP32 derivation (plain) and taproot (x-only) apply them. */
    if (mi.flags & MUSIG_EC_TWEAK) {
        ok = secp256k1_musig_pubkey_ec_tweak_add(variant_ctx, &agg, &cache, mi.tweak[0]);
        transcript_int(&t, ok);
        if (!ok) {
            return t.len;
        }
        musig_record_pubkey(&t, &agg);
    }
    if (mi.flags & MUSIG_XONLY_TWEAK) {
        ok = secp256k1_musig_pubkey_xonly_tweak_add(variant_ctx, &agg, &cache, mi.tweak[1]);
        transcript_int(&t, ok);
        if (!ok) {
            return t.len;
        }
        musig_record_pubkey(&t, &agg);
    }

    for (i = 0; i < mi.n; i++) {
        int inputs = (mi.flags & MUSIG_NONCE_INPUTS) != 0;

        if (mi.flags & MUSIG_COUNTER) {
            uint64_t counter = 0;

            for (j = 0; j < 8; j++) {
                counter = counter << 8 | mi.secrand[i][j];
            }
            ok = secp256k1_musig_nonce_gen_counter(variant_ctx, &secnonce[i], &pubnonce[i], counter, &keypair[i],
                                                   inputs ? mi.msg : NULL, inputs ? &cache : NULL,
                                                   inputs ? mi.extra : NULL);
        } else {
            /* A zero secrand fails, as it would from a broken RNG. */
            ok = secp256k1_musig_nonce_gen(variant_ctx, &secnonce[i], &pubnonce[i], mi.secrand[i],
                                           inputs ? mi.seckey[i] : NULL, &pubkey[i], inputs ? mi.msg : NULL,
                                           inputs ? &cache : NULL, inputs ? mi.extra : NULL);
        }
        transcript_int(&t, ok);
        if (!ok) {
            return t.len;
        }
        secp256k1_musig_pubnonce_serialize(variant_ctx, ser, &pubnonce[i]);
        transcript_put(&t, ser, 66);
        pubnonce_ptrs[i] = &pubnonce[i];
    }
    if (mi.flags & MUSIG_FUZZ_PUBNONCE) {
        ok = secp256k1_musig_pubnonce_parse(variant_ctx, &fuzz_pubnonce, mi.pubnonce);
        transcript_int(&t, ok);
        if (ok) {
            pubnonce_ptrs[mi.victim] = &fuzz_pubnonce;
        }
    }
    ok = secp256k1_musig_nonce_agg(variant_ctx, &aggnonce, pubnonce_ptrs, mi.n);
    transcript_int(&t, ok);
    if (!ok) {
        return t.len;
    }
    if (mi.flags & MUSIG_FUZZ_AGGNONCE) {
        ok = secp256k1_musig_aggnonce_parse(variant_ctx, &fuzz_aggnonce, mi.aggnonce);
        transcript_int(&t, ok);
        if (ok) {
            aggnonce = fuzz_aggnonce;
        }
    }
    secp256k1_musig_aggnonce_serialize(variant_ctx, ser, &aggnonce);
    transcript_put(&t, ser, 66);
    ok = secp256k1_musig_nonce_process(variant_ctx, &session, &aggnonce, mi.msg, &cache);
    transcript_int(&t, ok);
    if (!ok) {
        return t.len;
    }

    for (i = 0; i < mi.n; i++) {
        ok = secp256k1_musig_partial_sign(variant_ctx, &psig[i], &secnonce[i], &keypair[i], &cache, &session);
        transcript_int(&t, ok);
        if (!ok) {
            return t.len;
        }
        secp256k1_musig_partial_sig_serialize(variant_ctx, ser, &psig[i]);
        transcript_put(&t, ser, 32);
        psig_ptrs[i] = &psig[i];
    }
    for (i = 0; i < mi.n; i++) {
        transcript_int(&t, secp256k1_musig_partial_sig_verify(variant_ctx, &psig[i], &pubnonce[i], &pubkey[i],
                                                              &cache, &session));
    }
    if (mi.flags & MUSIG_FUZZ_PARTIAL_SIG) {
        ok = secp256k1_musig_partial_sig_parse(variant_ctx, &fuzz_psig, mi.partial_sig);
        transcript_int(&t, ok);
        if (ok) {
            transcript_int(&t, secp256k1_musig_partial_sig_verify(variant_ctx, &fuzz_psig, &pubnonce[mi.victim],
                                                                  &pubkey[mi.victim], &cache, &session));
            psig_ptrs[mi.victim] = &fuzz_psig;
        }
    }

    ok = secp256k1_musig_partial_sig_agg(variant_ctx, sig64, &session, psig_ptrs, mi.n);
    transcript_int(&t, ok);
    if (ok) {
        transcript_put(&t, sig64, sizeof(sig64));
        /* agg holds the tweaked key when tweaks were applied. */
        secp256k1_xonly_pubkey_from_pubkey(variant_ctx, &agg_xonly, &parity, &agg);
        transcript_int(&t, parity);
        transcript_int(&t, secp256k1_schnorrsig_verify(variant_ctx, sig64, mi.msg, sizeof(mi.msg), &agg_xonly));
    }

    return t.len;
}
