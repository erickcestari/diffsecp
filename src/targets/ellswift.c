/* ElligatorSwift, the BIP324 key encoding: decoding arbitrary 64-byte
 * encodings, encoding with fuzzed randomness, and the x-only ECDH both peers
 * run. Builds that disagree here split the P2P network rather than the chain.
 *
 * Encoding costs about as much as ten decodings, so flags pick the expensive
 * steps rather than every input paying for all of them.
 *
 * Input: flags, ell64, rnd32, then seckey32 and auxrnd32 for each party,
 * then prefix64. */

enum ellswift_flag {
    ELLSWIFT_AUX0 = 1 << 0,       /* party 0 creates its encoding with auxrnd */
    ELLSWIFT_AUX1 = 1 << 1,
    ELLSWIFT_FUZZ_PEER = 1 << 2,  /* the responder sends the fuzzed encoding instead */
    ELLSWIFT_ENCODE = 1 << 3,     /* re-encode the fuzzed encoding's point with rnd */
    ELLSWIFT_PREFIX = 1 << 4      /* hash with the fuzzed prefix instead of the BIP324 tag */
};

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
    unsigned char ell[64], rnd[32], seckey[2][32], aux[2][32], prefix[64], ours[2][64], shared[32];
    secp256k1_pubkey pk;
    unsigned int flags;
    int party, ret;

    flags = reader_u8(&r);
    reader_take(&r, ell, sizeof(ell));
    reader_take(&r, rnd, sizeof(rnd));
    for (party = 0; party < 2; party++) {
        reader_take(&r, seckey[party], sizeof(seckey[party]));
        reader_take(&r, aux[party], sizeof(aux[party]));
    }
    reader_take(&r, prefix, sizeof(prefix));

    /* Every 64-byte string decodes to a point. */
    transcript_int(&t, secp256k1_ellswift_decode(variant_ctx, &pk, ell));
    ellswift_record_pubkey(&t, &pk);
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
    for (party = 0; party < 2; party++) {
        ret = secp256k1_ellswift_xdh(variant_ctx, shared, ours[0], ours[1], seckey[party], party,
                                     (flags & ELLSWIFT_PREFIX) ? secp256k1_ellswift_xdh_hash_function_prefix
                                                               : secp256k1_ellswift_xdh_hash_function_bip324,
                                     prefix);
        transcript_int(&t, ret);
        if (ret) {
            transcript_put(&t, shared, sizeof(shared));
        }
    }

    return t.len;
}
