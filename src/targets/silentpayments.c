/* Silent Payments (BIP352): the sender derives outputs from its input keys,
 * and the recipient rebuilds the prevouts summary from the input public keys
 * and scans the outputs, with and without a label. A second recipient group
 * and a fuzzed foreign output exercise output ordering and the scanning loop.
 *
 * Opaque objects (prevouts summary, label) are never recorded raw: their
 * layout is platform dependent.
 *
 * Input: flags, outpoint[36], input count and kinds, per input seckey[32],
 * scan, spend and foreign seckeys, label m, recipient count and label mask,
 * then a raw x-only output, its position and a raw label. */

#define SP_MAX_INPUTS 3
#define SP_MAX_RECIPIENTS 3

enum sp_flag {
    SP_LABEL = 1 << 0,
    SP_FOREIGN = 1 << 1,      /* the last recipient belongs to someone else */
    SP_FUZZ_OUTPUT = 1 << 2   /* insert a fuzzed output among the generated ones */
};

struct sp_label_cache {
    unsigned char label33[33];
    unsigned char tweak32[32];
};

static const unsigned char *sp_label_lookup(const unsigned char *label33, const void *label_context) {
    const struct sp_label_cache *cache = label_context;

    return memcmp(label33, cache->label33, sizeof(cache->label33)) == 0 ? cache->tweak32 : NULL;
}

struct sp_input {
    unsigned int flags, n_inputs, kinds, n_recipients, labeled, out_pos;
    unsigned char outpoint[36], seckey[SP_MAX_INPUTS][32], scan[32], spend[32], foreign[32];
    unsigned char output[32], label[33];
    uint32_t m;
};

static void sp_read(struct reader *r, struct sp_input *in) {
    unsigned int i;

    in->flags = reader_u8(r);
    reader_take(r, in->outpoint, sizeof(in->outpoint));
    in->n_inputs = 1 + reader_u8(r) % SP_MAX_INPUTS;
    in->kinds = reader_u8(r);
    for (i = 0; i < in->n_inputs; i++) {
        reader_take(r, in->seckey[i], sizeof(in->seckey[i]));
    }
    reader_take(r, in->scan, sizeof(in->scan));
    reader_take(r, in->spend, sizeof(in->spend));
    reader_take(r, in->foreign, sizeof(in->foreign));
    /* Two statements: the order of calls within one expression is unspecified. */
    in->m = (uint32_t)reader_u16(r) << 16;
    in->m |= reader_u16(r);
    in->n_recipients = 1 + reader_u8(r) % SP_MAX_RECIPIENTS;
    in->labeled = reader_u8(r);
    reader_take(r, in->output, sizeof(in->output));
    in->out_pos = reader_u8(r);
    reader_take(r, in->label, sizeof(in->label));
}

static void sp_record_pubkey(struct transcript *t, const secp256k1_pubkey *pk) {
    unsigned char ser[33];
    size_t len = sizeof(ser);

    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, pk, SECP256K1_EC_COMPRESSED);
    transcript_put(t, ser, len);
}

static void sp_record_xonly(struct transcript *t, const secp256k1_xonly_pubkey *pk) {
    unsigned char ser[32];

    secp256k1_xonly_pubkey_serialize(variant_ctx, ser, pk);
    transcript_put(t, ser, sizeof(ser));
}

/* A raw label parses to a point; only its serialization is comparable. */
static void sp_label_roundtrip(struct transcript *t, const unsigned char *in33) {
    secp256k1_silentpayments_label label;
    unsigned char ser[33];
    int ok;

    ok = secp256k1_silentpayments_recipient_label_parse(variant_ctx, &label, in33);
    transcript_int(t, ok);
    if (ok) {
        secp256k1_silentpayments_recipient_label_serialize(variant_ctx, ser, &label);
        transcript_put(t, ser, sizeof(ser));
    }
}

static void sp_scan(struct transcript *t, const struct sp_input *in, const secp256k1_xonly_pubkey *outputs,
                    size_t n_outputs, const secp256k1_silentpayments_prevouts_summary *summary,
                    const secp256k1_pubkey *spend_pk, const struct sp_label_cache *cache) {
    secp256k1_xonly_pubkey tx[SP_MAX_RECIPIENTS + 1];
    const secp256k1_xonly_pubkey *tx_ptrs[SP_MAX_RECIPIENTS + 1];
    secp256k1_silentpayments_found_output found[SP_MAX_RECIPIENTS + 1];
    secp256k1_silentpayments_found_output *found_ptrs[SP_MAX_RECIPIENTS + 1];
    secp256k1_xonly_pubkey foreign;
    unsigned char ser[33];
    size_t n_tx = 0, i, pos = SIZE_MAX;
    uint32_t n_found;
    int ok;

    if ((in->flags & SP_FUZZ_OUTPUT) && secp256k1_xonly_pubkey_parse(variant_ctx, &foreign, in->output)) {
        pos = in->out_pos % (n_outputs + 1);
    }
    for (i = 0; i < n_outputs; i++) {
        if (i == pos) {
            tx[n_tx++] = foreign;
        }
        tx[n_tx++] = outputs[i];
    }
    if (pos == n_outputs) {
        tx[n_tx++] = foreign;
    }
    for (i = 0; i < n_tx; i++) {
        tx_ptrs[i] = &tx[i];
        found_ptrs[i] = &found[i];
    }

    ok = secp256k1_silentpayments_recipient_scan_outputs(variant_ctx, found_ptrs, &n_found, tx_ptrs, n_tx,
                                                         in->scan, summary, spend_pk,
                                                         cache != NULL ? sp_label_lookup : NULL, cache);
    transcript_int(t, ok);
    if (!ok) {
        return;
    }
    transcript_u32(t, n_found);
    for (i = 0; i < n_found; i++) {
        sp_record_xonly(t, &found[i].output);
        transcript_put(t, found[i].tweak, sizeof(found[i].tweak));
        transcript_int(t, found[i].found_with_label);
        /* The label is only set when the output was found with one. */
        if (found[i].found_with_label) {
            secp256k1_silentpayments_recipient_label_serialize(variant_ctx, ser, &found[i].label);
            transcript_put(t, ser, sizeof(ser));
        }
    }
}

static size_t target_silentpayments(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    struct sp_input si;
    struct sp_label_cache cache;
    secp256k1_keypair keypairs[SP_MAX_INPUTS];
    const secp256k1_keypair *keypair_ptrs[SP_MAX_INPUTS];
    const unsigned char *seckey_ptrs[SP_MAX_INPUTS];
    secp256k1_xonly_pubkey xonly[SP_MAX_INPUTS], outputs[SP_MAX_RECIPIENTS];
    const secp256k1_xonly_pubkey *xonly_ptrs[SP_MAX_INPUTS];
    secp256k1_xonly_pubkey *output_ptrs[SP_MAX_RECIPIENTS];
    secp256k1_pubkey pubkeys[SP_MAX_INPUTS], scan_pk, spend_pk, labeled_pk, foreign_pk;
    const secp256k1_pubkey *pubkey_ptrs[SP_MAX_INPUTS];
    secp256k1_silentpayments_label label;
    secp256k1_silentpayments_recipient recipients[SP_MAX_RECIPIENTS];
    const secp256k1_silentpayments_recipient *recipient_ptrs[SP_MAX_RECIPIENTS];
    secp256k1_silentpayments_prevouts_summary summary;
    size_t n_keypairs = 0, n_seckeys = 0, n_xonly = 0, n_pubkeys = 0, i;
    int ok, sent, label_ok = 0, foreign_ok = 0;

    sp_read(&r, &si);
    sp_label_roundtrip(&t, si.label);

    /* Inputs: taproot ones as keypairs (an invalid keypair is an illegal
     * argument, so failed ones are left out), others as raw seckeys, which
     * the sender itself rejects when invalid. */
    for (i = 0; i < si.n_inputs; i++) {
        if ((si.kinds >> i) & 1) {
            ok = secp256k1_keypair_create(variant_ctx, &keypairs[n_keypairs], si.seckey[i]);
            transcript_int(&t, ok);
            if (ok) {
                secp256k1_keypair_xonly_pub(variant_ctx, &xonly[n_xonly], NULL, &keypairs[n_keypairs]);
                xonly_ptrs[n_xonly] = &xonly[n_xonly];
                keypair_ptrs[n_keypairs] = &keypairs[n_keypairs];
                n_xonly++;
                n_keypairs++;
            }
        } else {
            seckey_ptrs[n_seckeys++] = si.seckey[i];
            ok = secp256k1_ec_pubkey_create(variant_ctx, &pubkeys[n_pubkeys], si.seckey[i]);
            transcript_int(&t, ok);
            if (ok) {
                pubkey_ptrs[n_pubkeys] = &pubkeys[n_pubkeys];
                n_pubkeys++;
            }
        }
    }

    ok = secp256k1_ec_pubkey_create(variant_ctx, &scan_pk, si.scan);
    transcript_int(&t, ok);
    if (!ok) {
        return t.len;
    }
    ok = secp256k1_ec_pubkey_create(variant_ctx, &spend_pk, si.spend);
    transcript_int(&t, ok);
    if (!ok) {
        return t.len;
    }
    if (si.flags & SP_LABEL) {
        label_ok = secp256k1_silentpayments_recipient_label_create(variant_ctx, &label, cache.tweak32, si.scan, si.m);
        transcript_int(&t, label_ok);
        if (label_ok) {
            secp256k1_silentpayments_recipient_label_serialize(variant_ctx, cache.label33, &label);
            transcript_put(&t, cache.label33, sizeof(cache.label33));
            transcript_put(&t, cache.tweak32, sizeof(cache.tweak32));
            label_ok = secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(variant_ctx, &labeled_pk,
                                                                                      &spend_pk, &label);
            transcript_int(&t, label_ok);
            if (label_ok) {
                sp_record_pubkey(&t, &labeled_pk);
            }
        }
    }
    if (si.flags & SP_FOREIGN) {
        foreign_ok = secp256k1_ec_pubkey_create(variant_ctx, &foreign_pk, si.foreign);
        transcript_int(&t, foreign_ok);
    }

    /* Recipients sharing a scan key form a group whose outputs count k up. */
    for (i = 0; i < si.n_recipients; i++) {
        int foreign = foreign_ok && i + 1 == si.n_recipients;

        recipients[i].scan_pubkey = foreign ? foreign_pk : scan_pk;
        recipients[i].spend_pubkey = foreign ? foreign_pk
                                   : (label_ok && ((si.labeled >> i) & 1)) ? labeled_pk : spend_pk;
        recipients[i].index = i;
        recipient_ptrs[i] = &recipients[i];
        output_ptrs[i] = &outputs[i];
    }
    sent = 0;
    if (n_keypairs + n_seckeys > 0) {
        sent = secp256k1_silentpayments_sender_create_outputs(variant_ctx, output_ptrs, recipient_ptrs,
                                                              si.n_recipients, si.outpoint,
                                                              n_keypairs > 0 ? keypair_ptrs : NULL, n_keypairs,
                                                              n_seckeys > 0 ? seckey_ptrs : NULL, n_seckeys);
        transcript_int(&t, sent);
        if (sent) {
            for (i = 0; i < si.n_recipients; i++) {
                sp_record_xonly(&t, &outputs[i]);
            }
        }
    }

    if (n_xonly + n_pubkeys == 0) {
        return t.len;
    }
    ok = secp256k1_silentpayments_recipient_prevouts_summary_create(variant_ctx, &summary, si.outpoint,
                                                                    n_xonly > 0 ? xonly_ptrs : NULL, n_xonly,
                                                                    n_pubkeys > 0 ? pubkey_ptrs : NULL, n_pubkeys);
    transcript_int(&t, ok);
    if (ok && sent) {
        sp_scan(&t, &si, outputs, si.n_recipients, &summary, &spend_pk, label_ok ? &cache : NULL);
    }

    return t.len;
}
