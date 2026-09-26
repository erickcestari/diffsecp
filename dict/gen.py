#!/usr/bin/env python3
"""Writes the libFuzzer dictionaries in this directory: common.dict for every
target and <target>.dict for values only that target reaches with fuzzed bytes.
`make fuzz` hands each fuzzer common.dict plus its own file.

Every value is a secp256k1 constant or an edge case libsecp's own tests pick,
derived here once so the files never drift from each other. Run it after
editing; it checks the constants before writing anything."""

import os

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72

assert (GY * GY - GX**3 - 7) % P == 0
assert pow(BETA, 3, P) == 1 and pow(LAMBDA, 3, N) == 1

# ecmult_const_impl.h: with the default group size of 5 it recodes 130-bit
# halves and feeds split_lambda s = (q + K) / 2, K = (2^130 - 2^129 - 1)(1 + lambda).
K = (2**130 - 2**129 - 1) * (1 + LAMBDA) % N

# tests.c, fill_scalars_near_split_bounds: a*lambda + b/2 give split_lambda the
# largest halves it can return.
SPLIT_BOUNDS = [(a * LAMBDA + b * pow(2, -1, N)) % N for a in (-2, -1, 0, 1, 2) for b in (-3, -1, 1, 3)]

# tests.c, run_modinv_tests: inputs needing the most safegcd steps (631 to 637
# against at most about 562 for random inputs), the most constant-time steps
# (564, 565), and the ones that exposed broken eta handling.
INV_HARD_P = [
    0xE34E9C956BEE8A840DCB632ADB8A13206688540806F3F9967C11CA8419199EC3,
    0xF6D89CBD6057F86E063ACAB2C2420C8B30FF7EC7A8FF5AD506932F2DA7CFAEC3,
    0x7F6F36B4A070CEDE95908E6287B1E4D85F8E744A78D1B454DB5C00718D1063AE,
    0x5C93D4F8E38F631DECD79C2E0CF89277F0D830B6567D1EAE25E38BCDBDC31B37,
]
INV_HARD_N = [
    0x1686F0ED30BF9AF68E8425AEAAD1CA8E6120581729CCD7D05FF1D1136C0195ED,
    0xC68BC424A18611355BBB06A4E9ABA7F5DAB72850BB5B19B63C569608C28485ED,
    0xEBBF7E9639F8C8E72A7E18F2C1F66E7070CE6DDC535A51DD6F1EA8475CEB8432,
    0x5CA2E11C3AD8BF320916FC7909945708C5AE9D0494C487DA7FA3EE41B877FEB9,
]


def b32(v):
    return v.to_bytes(32, "big")


def group(comment, entries):
    return comment, entries


# Scalars reaching ecmult_const as they are: q = -K makes s zero, and
# q = 2*bound - K makes s a split bound.
ECMULT_CONST = group("ecmult_const: q = -K makes the scalar it splits zero, 2*bound - K a split bound.",
                     [("ecmult_const_zero", b32(-K % N))] +
                     [("ecmult_const_bound%d" % i, b32((2 * s - K) % N)) for i, s in enumerate(SPLIT_BOUNDS)])
SPLIT = group("split_lambda: scalars whose halves reach the largest magnitude.",
              [("split_bound%d" % i, b32(s)) for i, s in enumerate(SPLIT_BOUNDS)])
# fe_normalize compares a value with p limb by limb. Each of these is p with
# one limb one lower, in both the 5x52 and the 10x26 layout: a limb in the
# middle, and the top one.
NEAR_P = group("Field: values below p that match all its limbs but one, which normalize's compare with p decides.",
               [("p_minus_2_52", b32(P - 2**52)), ("p_minus_2_234", b32(P - 2**234))])
INV_P = group("Field inversion: inputs mod p needing the most safegcd steps.",
              [("inv_hard_p%d" % i, b32(v)) for i, v in enumerate(INV_HARD_P)])
INV_N = group("Scalar inversion: inputs mod n needing the most safegcd steps.",
              [("inv_hard_n%d" % i, b32(v)) for i, v in enumerate(INV_HARD_N)])

def sqrt_mod_p(a):
    # p = 3 mod 4, so a square's root is a^((p+1)/4).
    r = pow(a, (P + 1) // 4, P)
    return r if r * r % P == a % P else None


# ellswift_xswiftec_frac_var: u^3 + 7 + t^2 = 0 makes g + s zero, a special case
# the decoding handles apart. Fuzzed bytes never solve for it.
GS_ZERO = []
for u in range(1, 100):
    t = sqrt_mod_p(-(u**3 + 7) % P)
    if t is not None and len(GS_ZERO) < 3:
        GS_ZERO.append((u, t))
assert all((u**3 + 7 + t * t) % P == 0 for u, t in GS_ZERO) and len(GS_ZERO) == 3
ELLSWIFT_GS_ZERO = group("ElligatorSwift encodings u || t with u^3 + 7 + t^2 = 0, where decoding special-cases g + s = 0.",
                         [("ellswift_gs_zero%d" % i, b32(u) + b32(t)) for i, (u, t) in enumerate(GS_ZERO)])
DER = group("DER framing, well formed and not: negative, padded, indefinite length.", [
    ("der_seq_32_32", b"\x30\x44\x02\x20"), ("der_seq_33_33", b"\x30\x46\x02\x21\x00"),
    ("der_int_33", b"\x02\x21\x00"), ("der_int_32", b"\x02\x20"), ("der_int_zero", b"\x02\x01\x00"),
    ("der_long_len", b"\x30\x81"), ("der_negative", b"\x02\x01\x80"), ("der_padded", b"\x02\x02\x00\x01"),
    ("der_indefinite", b"\x30\x80"),
])

DICTS = {
    "common": [
        group("Field: values at and around the modulus p, and the 2^256 - p a reduction folds in.",
              [("p", b32(P)), ("p_minus_1", b32(P - 1)), ("two256_minus_p", b32(2**256 - P))]),
        group("Scalars: the order n, its neighbours and the low-S boundary.",
              [("n", b32(N)), ("n_minus_1", b32(N - 1)), ("half_n", b32((N - 1) // 2)),
               ("half_n_plus_1", b32((N - 1) // 2 + 1)), ("two256_minus_n", b32(2**256 - N)), ("one", b32(1))]),
        group("x coordinates in [n, p) reduce mod n in ECDSA's r check.", [("p_minus_n", b32(P - N))]),
        group("The generator, raw and as serialized pubkeys.",
              [("gx", b32(GX)), ("gy", b32(GY)), ("neg_gy", b32(P - GY)),
               ("g_compressed", b"\x02" + b32(GX)), ("g_uncompressed", b"\x04" + b32(GX) + b32(GY))]),
        group("Endomorphism constants: beta*x and lambda*k give the same point.",
              [("beta", b32(BETA)), ("lambda", b32(LAMBDA))]),
    ],
    "field": [NEAR_P, INV_P],
    "scalar": [INV_N, SPLIT],
    "ecdsa": [DER, INV_N],
    "recovery": [INV_N],
    "group": [ECMULT_CONST, SPLIT],
    "keys": [ECMULT_CONST, SPLIT],
    "ellswift": [ECMULT_CONST, ELLSWIFT_GS_ZERO],
}

HEADER = {
    "common": "# Every target's dictionary starts with these. Generated by gen.py; edit that instead.",
}


def render(name, groups):
    out = [HEADER.get(name, "# Added to common.dict for the %s target. Generated by gen.py; edit that instead." % name), ""]
    for comment, entries in groups:
        out.append("# " + comment)
        for key, value in entries:
            out.append('%s="%s"' % (key, "".join("\\x%02x" % c for c in value)))
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    for name, groups in DICTS.items():
        with open(os.path.join(here, name + ".dict"), "w") as f:
            f.write(render(name, groups))
