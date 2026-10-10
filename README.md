# diffsecp

Differential fuzzing of [libsecp256k1](https://github.com/bitcoin-core/secp256k1).
Each input runs through many builds of libsecp in one process (compilers,
optimization levels, arithmetic implementations, table sizes, and the last
release next to master), and any difference in results aborts with a
reproducer. The corpus is then replayed on 32-bit ARM, aarch64, riscv64, ppc64,
ppc64le and Windows, and compared with x86_64.

Bitcoin nodes run libsecp built by different compilers for different CPUs, and
builds that disagree on whether a signature is valid split the chain. libsecp's
own tests check known answers; diffsecp checks that builds agree on inputs
nobody wrote down.

## Requirements

clang with libFuzzer, gcc, GNU make, binutils and python3, plus `llvm-profdata`
and `llvm-cov` of the same LLVM for `make coverage`. Docker for
cross-architecture runs, unless GCC 14 cross toolchains, clang 19 and qemu-user
are installed.

## Usage

```sh
git submodule update --init
make -j
make check                                         # selftest, corpus replay, short fuzz run
make -j fuzz FUZZ_TIME=3600                        # fuzz every target for an hour
make merge                                         # add the new inputs that raise coverage
make minimize                                      # rebuild the corpus from scratch
make coverage                                      # what the corpus reaches, in build/coverage
make mutation-score                                # which planted bugs the corpus exposes
make docker-cross                                  # replay the corpus on every architecture
build/fuzz_ecdsa build/crashes/ecdsa-crash-<hash>  # replay a divergence
```

`check`, `fuzz`, `merge` and `minimize` also run per target, as in
`make fuzz-ecdsa`. A divergence prints the two builds and the first differing
transcript byte.

## Targets

| Target           | Covers                                                                                                 |
|------------------|--------------------------------------------------------------------------------------------------------|
| `ecdsa`          | pubkey parsing, strict and lax DER, low-S normalization, sign with any nonce function, verify          |
| `schnorrsig`     | BIP340 sign and verify with any message length and nonce function, x-only parsing, taproot tweak check |
| `recovery`       | recoverable ECDSA signing and public key recovery                                                      |
| `keys`           | seckey and pubkey tweaks, negation, combination, sorting, taproot keypair tweaks, ECDH                 |
| `musig`          | MuSig2 key aggregation and tweaks, nonces, partial signatures and their aggregation                    |
| `silentpayments` | BIP352 outputs, labels, prevouts summary, scanning, a corrupt label cache, the recipient group limit   |
| `ellswift`       | BIP324 ElligatorSwift encoding, its inverse for a chosen u, decoding, x-only ECDH                      |
| `field`          | field arithmetic via a register machine (internal API)                                                 |
| `scalar`         | scalar arithmetic via a register machine (internal API)                                                |
| `group`          | point addition, doubling, single and multi-point multiplication via a register machine (internal API)  |

The signature targets sign first and then mutate the signature, message or key,
reaching verify paths random bytes almost never hit. Each target also builds
inputs fuzzed bytes can't, such as R at infinity or keys that sum to zero; its
source in `src/targets` lists them.

## How it works

`src/variant.c` holds all of libsecp and the targets in one translation unit, so
targets reach static internals. It is compiled once per build in `variants.mk`,
and `objcopy` localizes the libsecp symbols so every build links into one
binary. A target writes every result it observes to a transcript, and
`src/fuzz.c` compares the transcripts byte for byte against the first build,
`guide`, which has coverage, ASan, UBSan and libsecp's `VERIFY` and steers the
fuzzer. `baseline` builds libsecp v0.8.0, so any behavior change on master shows
up as a divergence. Targets must be deterministic, or the harness reports false
divergences.

`GCC` and `CLANG` pick the compilers of every build. CI uses `gcc-14` and
`clang-19`, as Guix does, and `make gcc_release_CC=gcc-15` overrides one build.

`make check` and `make cross` include a selftest: a build that flips the last
transcript byte, which every target must report.

## Cross-architecture

`make cross` (or `make docker-cross`, with the toolchains in `ci/Dockerfile`)
builds `src/replay.c` statically for each architecture in `arches.mk`, replays
the corpus under qemu-user or wine and compares transcript digests with x86_64.
To locate a divergence, diff the transcripts:

```sh
diff <(build/docker/cross/x86_64/replay -d ecdsa corpus/ecdsa/<hash>) \
     <(qemu-ppc64 build/docker/cross/ppc64/replay -d ecdsa corpus/ecdsa/<hash>)
```

The corpus keeps only inputs that raise x86 coverage, so `ORACLE_ARCHES` also
compares a fraction `ORACLE_RATE` of the inputs while fuzzing:

```sh
make docker-cross-replays
make -j fuzz ORACLE_DIR=build/docker/cross ORACLE_ARCHES='arm aarch64 riscv64 ppc64 ppc64le'
```

## Corpus and mutants

`corpus/<target>` is committed. `make merge` adds only the inputs that raise
coverage and skips any that diverge. Fuzzing uses the boundary values in `dict/`
(`FUZZ_DICT=` turns them off), and `field` and `scalar` also use libFuzzer's
value profile.

Coverage can't tell whether the fuzzer fed the values where arithmetic goes
wrong, such as p or n. `mutants/mutants.txt` plants bugs that show only at such
values, and `src/fuzz.c` runs each input through the ones it reaches. Reaching
or killing a new mutant counts as coverage, so the corpus keeps those inputs.
`make mutation-score` lists the mutants the corpus doesn't kill: masked ones
were triggered but changed no transcript, missed ones never were.

## CI

- `ci.yml` runs `make check`, `make oracle-selftest` and `make docker-cross` on
  pushes and pull requests.
- `bump-secp256k1.yml` moves `external/secp256k1` to upstream master daily, and
  fast-forwards master only if CI passes; a failed bump stays on the
  `bump-secp256k1` branch.
- `fuzz.yml` fuzzes every target for 30 minutes daily with the oracle, and
  commits the new corpus and this README's coverage table once CI passes.
- `latest-compilers.yml` builds with Arch Linux's newest GCC and clang weekly
  and fuzzes for two hours: distros ship new compilers before Guix does.

Reproducers are uploaded encrypted to `ci/maintainer.asc`, since artifacts of a
public repository are public:

```sh
gh run download <run-id> -n reproducers && gpg -d reproducers.tar.gz.gpg | tar -xz
```

## Coverage

What the corpus reaches, from `make coverage`: `guide`'s flags without
sanitizers or `VERIFY`, whose assertions can't fail but would count as missed
branches. Refreshed daily with clang 19, since branch counts differ between LLVM
versions. `COVERAGE_VARIANT=guide_int64` shows the int64 arithmetic instead.

<!-- coverage:begin -->

libsecp `22245aedf400`: 93.12% of lines, 76.20% of branches, 94.60% of functions.

Mutation score: 70 of 70 mutants killed, 0 masked, 0 missed.

| File | Lines | Branches | Functions |
|------|------:|---------:|----------:|
| `contrib/lax_der_parsing.c` | 100.00% | 100.00% | 100.00% |
| `src/assumptions.h` | 0.00% | - | 0.00% |
| `src/ecdsa_impl.h` | 100.00% | 99.00% | 100.00% |
| `src/eckey_impl.h` | 100.00% | 100.00% | 100.00% |
| `src/ecmult_const_impl.h` | 100.00% | 84.21% | 100.00% |
| `src/ecmult_gen_impl.h` | 100.00% | 86.36% | 100.00% |
| `src/ecmult_impl.h` | 92.39% | 87.87% | 88.00% |
| `src/field_5x52_impl.h` | 97.76% | 100.00% | 96.55% |
| `src/field_5x52_int128_impl.h` | 100.00% | - | 100.00% |
| `src/field_impl.h` | 100.00% | 92.31% | 100.00% |
| `src/group_impl.h` | 96.86% | 73.40% | 95.74% |
| `src/hash_impl.h` | 82.41% | 73.33% | 88.89% |
| `src/hsort_impl.h` | 94.55% | 93.75% | 100.00% |
| `src/int128_native_impl.h` | 60.29% | - | 63.16% |
| `src/modinv64_impl.h` | 99.31% | 97.83% | 100.00% |
| `src/modules/ecdh/main_impl.h` | 100.00% | 70.00% | 100.00% |
| `src/modules/ellswift/main_impl.h` | 99.32% | 69.35% | 100.00% |
| `src/modules/extrakeys/main_impl.h` | 92.65% | 62.00% | 100.00% |
| `src/modules/musig/keyagg_impl.h` | 93.48% | 75.86% | 100.00% |
| `src/modules/musig/session_impl.h` | 92.13% | 66.36% | 100.00% |
| `src/modules/recovery/main_impl.h` | 96.00% | 64.58% | 100.00% |
| `src/modules/schnorrsig/main_impl.h` | 98.84% | 74.14% | 100.00% |
| `src/modules/silentpayments/main_impl.h` | 90.23% | 70.75% | 100.00% |
| `src/scalar_4x64_impl.h` | 100.00% | 95.83% | 100.00% |
| `src/scalar_impl.h` | 100.00% | - | 100.00% |
| `src/scratch_impl.h` | 67.09% | 57.69% | 100.00% |
| `src/secp256k1.c` | 95.15% | 65.52% | 100.00% |
| `src/selftest.h` | 83.33% | 33.33% | 100.00% |
| `src/util.h` | 61.73% | 90.00% | 65.00% |

<!-- coverage:end -->
