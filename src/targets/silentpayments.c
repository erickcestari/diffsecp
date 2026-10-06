/* Silent Payments (BIP352): the sender derives outputs from its input keys,
 * and the recipient rebuilds the prevouts summary from the input public keys
 * and scans the outputs, with and without a label. A second recipient group
 * and fuzzed foreign outputs exercise output ordering and the scanning loop.
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
    SP_FOREIGN = 1 << 1,       /* the last recipient belongs to someone else */
    SP_FUZZ_OUTPUT = 1 << 2,   /* insert a fuzzed output among the generated ones */
    SP_LABEL_CANCEL = 1 << 3,  /* label the spend key with its negation (sp_label_cancel) */
    SP_SCAN_FOREIGN = 1 << 4,  /* scan with the foreign seckey, which may be invalid */
    SP_PAD = 1 << 5,           /* insert LABEL_BATCH_SIZE copies of the fuzzed output, a full label batch */
    SP_TWIN = 1 << 6,          /* scan the twin output first (target_silentpayments) */
    SP_LIMIT = 1 << 7          /* the recipient group limit, in 1 of SP_LIMIT_ODDS inputs (sp_limit_due) */
};

/* The scanned transaction: the twin, the generated outputs and the padding. */
#define SP_MAX_TX (1 + SP_MAX_RECIPIENTS + LABEL_BATCH_SIZE)
#define SP_GROUP_LIMIT SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT
#define SP_LIMIT_ODDS 4096

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

/* Scans the transaction tx and records what the recipient finds. */
static void sp_scan_record(struct transcript *t, const unsigned char *scan_key,
                           const secp256k1_xonly_pubkey *const *tx, size_t n_tx,
                           const secp256k1_silentpayments_prevouts_summary *summary,
                           const secp256k1_pubkey *spend_pk, const struct sp_label_cache *cache) {
    /* Static: the group limit's transaction is too large for the stack. */
    static secp256k1_silentpayments_found_output found[SP_GROUP_LIMIT + 1];
    static secp256k1_silentpayments_found_output *found_ptrs[SP_GROUP_LIMIT + 1];
    unsigned char ser[33];
    uint32_t n_found;
    size_t i;
    int ok;

    for (i = 0; i < n_tx; i++) {
        found_ptrs[i] = &found[i];
    }
    ok = secp256k1_silentpayments_recipient_scan_outputs(variant_ctx, found_ptrs, &n_found, tx, n_tx, scan_key,
                                                         summary, spend_pk, cache != NULL ? sp_label_lookup : NULL,
                                                         cache);
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

/* Scans the generated outputs, after twin when set, with the fuzzed output
 * inserted at out_pos: once, or a run of LABEL_BATCH_SIZE copies that fills a
 * label batch. */
static void sp_scan(struct transcript *t, const struct sp_input *in, const secp256k1_xonly_pubkey *outputs,
                    size_t n_outputs, const secp256k1_xonly_pubkey *twin,
                    const secp256k1_silentpayments_prevouts_summary *summary,
                    const secp256k1_pubkey *spend_pk, const struct sp_label_cache *cache) {
    const secp256k1_xonly_pubkey *tx[SP_MAX_TX];
    secp256k1_xonly_pubkey foreign;
    size_t n_tx = 0, n_foreign = 0, i, j, pos = SIZE_MAX;

    if ((in->flags & SP_FUZZ_OUTPUT) && secp256k1_xonly_pubkey_parse(variant_ctx, &foreign, in->output)) {
        pos = in->out_pos % (n_outputs + 1);
        n_foreign = (in->flags & SP_PAD) ? LABEL_BATCH_SIZE : 1;
    }
    if (twin != NULL) {
        tx[n_tx++] = twin;
    }
    for (i = 0; i <= n_outputs; i++) {
        if (i == pos) {
            for (j = 0; j < n_foreign; j++) {
                tx[n_tx++] = &foreign;
            }
        }
        if (i < n_outputs) {
            tx[n_tx++] = &outputs[i];
        }
    }
    sp_scan_record(t, (in->flags & SP_SCAN_FOREIGN) ? in->foreign : in->scan, tx, n_tx, summary, spend_pk, cache);
}

/* The label -B_spend: the labeled spend key would be infinity, so creating it
 * must fail. Labels are hashes, so only a raw one reaches this. */
static void sp_label_cancel(struct transcript *t, const secp256k1_pubkey *spend_pk) {
    secp256k1_pubkey neg = *spend_pk, labeled_pk;
    secp256k1_silentpayments_label label;
    unsigned char ser[33];
    size_t len = sizeof(ser);
    int ok;

    secp256k1_ec_pubkey_negate(variant_ctx, &neg);
    secp256k1_ec_pubkey_serialize(variant_ctx, ser, &len, &neg, SECP256K1_EC_COMPRESSED);
    ok = secp256k1_silentpayments_recipient_label_parse(variant_ctx, &label, ser);
    transcript_int(t, ok);
    if (ok) {
        transcript_int(t, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(variant_ctx, &labeled_pk,
                                                                                          spend_pk, &label));
    }
}

/* One recipient more than a group may have: the sender must refuse, as the
 * recipient stops scanning at the limit. Then the recipient scans a transaction
 * of more outputs than the limit, the generated ones padded with copies of
 * the first. Without labels, scanning stops at the first k with no match, so
 * only the sender pays for the limit. */
static void sp_limit(struct transcript *t, const struct sp_input *in, const secp256k1_pubkey *scan_pk,
                     const secp256k1_pubkey *spend_pk, const secp256k1_keypair *const *keypairs, size_t n_keypairs,
                     const unsigned char *const *seckeys, size_t n_seckeys, const secp256k1_xonly_pubkey *outputs,
                     size_t n_outputs, const secp256k1_silentpayments_prevouts_summary *summary) {
    static secp256k1_silentpayments_recipient recipients[SP_GROUP_LIMIT + 1];
    static const secp256k1_silentpayments_recipient *recipient_ptrs[SP_GROUP_LIMIT + 1];
    static secp256k1_xonly_pubkey generated[SP_GROUP_LIMIT + 1];
    static secp256k1_xonly_pubkey *generated_ptrs[SP_GROUP_LIMIT + 1];
    static const secp256k1_xonly_pubkey *tx[SP_GROUP_LIMIT + 1];
    size_t i;

    for (i = 0; i <= SP_GROUP_LIMIT; i++) {
        recipients[i].scan_pubkey = *scan_pk;
        recipients[i].spend_pubkey = *spend_pk;
        recipients[i].index = i;
        recipient_ptrs[i] = &recipients[i];
        generated_ptrs[i] = &generated[i];
        tx[i] = &outputs[i < n_outputs ? i : 0];
    }
    transcript_int(t, secp256k1_silentpayments_sender_create_outputs(variant_ctx, generated_ptrs, recipient_ptrs,
                                                                     SP_GROUP_LIMIT + 1, in->outpoint,
                                                                     keypairs, n_keypairs, seckeys, n_seckeys));
    sp_scan_record(t, in->scan, tx, SP_GROUP_LIMIT + 1, summary, spend_pk, NULL);
}

/* The group limit costs thousands of point multiplications per build, so it
 * runs only when a hash of the whole input (FNV-1a) falls in its lowest
 * 1/SP_LIMIT_ODDS. A flag alone would not do: mutations of an input that has
 * it mostly keep it, while any mutation rerolls the hash. */
static int sp_limit_due(const unsigned char *in, size_t len) {
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < len; i++) {
        h = (h ^ in[i]) * 16777619u;
    }
    return h <= UINT32_MAX / SP_LIMIT_ODDS;
}

static size_t target_silentpayments(const unsigned char *in, size_t len, unsigned char *out, size_t cap) {
    struct reader r = {in, len};
    struct transcript t = {out, cap, 0};
    struct sp_input si;
    struct sp_label_cache cache;
    secp256k1_keypair keypairs[SP_MAX_INPUTS];
    const secp256k1_keypair *keypair_ptrs[SP_MAX_INPUTS];
    const unsigned char *seckey_ptrs[SP_MAX_INPUTS];
    secp256k1_xonly_pubkey xonly[SP_MAX_INPUTS], outputs[SP_MAX_RECIPIENTS], twin;
    const secp256k1_xonly_pubkey *xonly_ptrs[SP_MAX_INPUTS];
    secp256k1_xonly_pubkey *output_ptrs[SP_MAX_RECIPIENTS];
    secp256k1_pubkey pubkeys[SP_MAX_INPUTS], scan_pk, spend_pk, labeled_pk, foreign_pk;
    const secp256k1_pubkey *pubkey_ptrs[SP_MAX_INPUTS];
    secp256k1_silentpayments_label label;
    secp256k1_silentpayments_recipient recipients[SP_MAX_RECIPIENTS], twin_recipient;
    const secp256k1_silentpayments_recipient *recipient_ptrs[SP_MAX_RECIPIENTS], *twin_recipient_ptr;
    secp256k1_xonly_pubkey *twin_ptr;
    secp256k1_silentpayments_prevouts_summary summary;
    size_t n_keypairs = 0, n_seckeys = 0, n_xonly = 0, n_pubkeys = 0, i;
    int ok, sent, label_ok = 0, foreign_ok = 0, twin_ok = 0;

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
    if (si.flags & SP_LABEL_CANCEL) {
        sp_label_cancel(&t, &spend_pk);
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
    /* Recipient 0's twin uses the other spend key, labeled for an unlabeled one
     * and back, and gets the same k = 0 when sent alone. Scanned first, a label
     * match can come before the direct match of the same k. */
    if ((si.flags & SP_TWIN) && sent && label_ok && !(foreign_ok && si.n_recipients == 1)) {
        twin_recipient.scan_pubkey = scan_pk;
        twin_recipient.spend_pubkey = (si.labeled & 1) ? spend_pk : labeled_pk;
        twin_recipient.index = 0;
        twin_recipient_ptr = &twin_recipient;
        twin_ptr = &twin;
        twin_ok = secp256k1_silentpayments_sender_create_outputs(variant_ctx, &twin_ptr, &twin_recipient_ptr, 1,
                                                                 si.outpoint,
                                                                 n_keypairs > 0 ? keypair_ptrs : NULL, n_keypairs,
                                                                 n_seckeys > 0 ? seckey_ptrs : NULL, n_seckeys);
        transcript_int(&t, twin_ok);
        if (twin_ok) {
            sp_record_xonly(&t, &twin);
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
        sp_scan(&t, &si, outputs, si.n_recipients, twin_ok ? &twin : NULL, &summary, &spend_pk,
                label_ok ? &cache : NULL);
        if ((si.flags & SP_LIMIT) && sp_limit_due(in, len)) {
            sp_limit(&t, &si, &scan_pk, &spend_pk, n_keypairs > 0 ? keypair_ptrs : NULL, n_keypairs,
                     n_seckeys > 0 ? seckey_ptrs : NULL, n_seckeys, outputs, si.n_recipients, &summary);
        }
    }

    return t.len;
}
