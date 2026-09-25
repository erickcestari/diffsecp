# diffsecp

Differential fuzzing of [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
across builds, architectures and library versions. On x86_64 and aarch64, each
input runs through every build in one process (compilers, optimization levels,
arithmetic implementations, table sizes, and libsecp's last release next to
master), and any difference in results aborts with a reproducer. The corpus the
fuzzer grows is then replayed on 32-bit ARM, aarch64, riscv64, ppc64, ppc64le
and Windows, and every result is compared with x86_64.

Bitcoin nodes run libsecp256k1 built by different compilers for different CPUs:
Guix release builds use GCC for Linux and Windows and clang for macOS, and
distros use whatever they ship. Builds that disagree on whether a signature is
valid split the chain.
libsecp256k1's own tests check known answers; diffsecp checks that builds
agree on inputs nobody wrote down.

## Requirements

clang with libFuzzer, gcc, GNU make and binutils (`objcopy`), plus
`llvm-profdata` and `llvm-cov` of the same LLVM for `make coverage`. Docker for
cross-architecture runs, unless GCC 14 cross toolchains, clang 19 and qemu-user
are installed.

## Usage

```sh
git submodule update --init
make -j
make check                                         # selftest, corpus replay, short fuzz run
make -j fuzz FUZZ_TIME=3600                        # fuzz every target from the corpus for an hour
make merge                                         # add the new inputs that raise coverage to the corpus
make coverage                                      # what the corpus reaches, in build/coverage
build/fuzz_ecdsa build/crashes/ecdsa-crash-<hash>  # replay a divergence
```

A divergence prints the two builds, the first differing transcript byte and the
bytes around it.

## Targets

| Target           | Covers                                                                                 |
|------------------|----------------------------------------------------------------------------------------|
| `ecdsa`          | pubkey parsing, strict and lax DER, low-S normalization, sign, verify                  |
| `schnorrsig`     | BIP340 sign and verify with any message length, x-only parsing, taproot tweak check    |
| `recovery`       | recoverable ECDSA signing and public key recovery                                      |
| `keys`           | seckey and pubkey tweaks, negation, combination, sorting, taproot keypair tweaks, ECDH |
| `musig`          | MuSig2 key aggregation and tweaks, nonces, partial signatures and their aggregation    |
| `silentpayments` | BIP352 output creation, labels, prevouts summary and scanning                          |
| `ellswift`       | BIP324 ElligatorSwift encoding and decoding, x-only ECDH                               |
| `field`          | field arithmetic via a register machine (internal API)                                 |
| `scalar`         | scalar arithmetic via a register machine (internal API)                                |
| `group`          | point addition, doubling and multiplication via a register machine (internal API)      |

The signature targets sign first and then mutate the signature, message or key,
reaching verify paths random bytes almost never hit. `ecdsa` also mutates the
signature's DER encoding, reaching the strict parser, and builds the key from a
chosen R, so verification recomputes infinity or an x at least the group order,
which no signer can reach. `group` builds its points as k·G from fuzzed
scalars, so it reaches the exceptional cases of point addition (doubling,
P + (-P), infinity) that signatures can't.

## Variants

`variants.mk` lists the builds: a name, a compiler and flags. Every transcript is
compared against the first variant, `guide`, which is built with coverage, ASan,
UBSan and libsecp's `VERIFY` checks. It steers the fuzzer and catches the harness
misusing internal APIs. `guide_int64` does the same on the int64 arithmetic
(10x26 field, 8x32 scalar), which `guide` never runs, at the cost of about 40%
fewer executions per second. The others cover release builds with GCC and clang,
optimizer extremes (`-O0`, `-Os`, `-O3 -march=native`), each arithmetic
implementation (int128, int128_struct, int64) and the smallest tables.
`gcc_release_sha256` installs the harness's own SHA256 compression function
with `secp256k1_context_set_sha256_compression`, as Bitcoin Core installs its
hardware-accelerated ones, so every hash-dependent result goes through it.
`baseline` builds `external/secp256k1-baseline`, libsecp v0.8.0, the oldest
release that builds every target, so any behavior change master makes since
then shows up as a divergence. It stays put: move it only when a target needs a
newer API, and only to a commit that shows no divergence.

To add one, append its name to `VARIANTS` and set `<name>_CC` and
`<name>_CFLAGS`, and optionally `<name>_SECP` for another libsecp tree.
`GCC` and `CLANG` pick the compilers of all variants: CI uses
`GCC=gcc-14 CLANG=clang-19`, the versions Guix builds releases with, and a local
build uses the system ones. Single variants can be overridden too, for example
`make gcc_release_CC=gcc-15`.

## Cross-architecture

Builds for other architectures can't share a process, so `make cross` replays
the corpus out of process instead. `src/replay.c` runs one build over every
corpus input and prints a digest of each transcript. It is built statically for
each entry in `arches.mk` and run under qemu-user or wine, and the digests are
compared against x86_64.

The architectures follow the Guix release targets that run on Linux or Wine:
32-bit ARM, aarch64, riscv64, big-endian ppc64 and win64, built with GCC 14 as
Guix does. macOS needs Apple's SDK and has no user-mode emulator, so
`aarch64_clang` stands in for arm64 macOS: clang 19 with `-mcpu=apple-m1`,
targeting Linux. ppc64le is also covered, although Guix currently leaves it out
over build nondeterminism.

```sh
make docker-cross           # toolchains from ci/Dockerfile; seeds a missing corpus first
make cross                  # same, with cross toolchains installed locally
make docker-cross-selftest  # only the cross selftest, see below
```

To locate a divergence, dump both transcripts and diff them. The static binaries
also run on the host through its own qemu-user:

```sh
diff <(build/docker/cross/x86_64/replay -d ecdsa corpus/ecdsa/<hash>) \
     <(qemu-ppc64 build/docker/cross/ppc64/replay -d ecdsa corpus/ecdsa/<hash>)
```

## How it works

`src/variant.c` is one translation unit holding all of libsecp256k1 and the
targets, so targets can reach static internals. It is compiled once per variant,
then `objcopy` localizes the libsecp symbols, leaving `diffsecp_variant_<name>`
as the only global so all variants link into one binary.

A target writes every result it observes (return codes, serialized outputs) to a
transcript, and `src/fuzz.c` compares the transcripts byte for byte. Targets must
be deterministic and free of unspecified behavior, or the harness itself will
report false divergences. Each variant blinds its context with a seed hashed
from its name, so a result that depends on blinding diverges.

`make selftest` checks the harness itself. It links an extra copy of `guide`
that flips the last transcript byte and expects every fuzzer to report it, so
it fails if per-variant flags stop reaching the compiler or the comparison
misses a byte or a variant. `make check` includes it. `make cross-selftest`
does the same for the digests: it replays the corpus on the first architecture
with that byte flipped and expects every target to diverge. `make cross`
includes it.

## Corpus

`corpus/<target>` is committed. It was grown by coverage-guided fuzzing and
minimized with `-merge=1`. `make check` replays it through every variant and
`make cross` on every architecture.

`make fuzz` writes new inputs to `build/new` and reproducers to `build/crashes`,
and `FUZZ_ARGS` passes libFuzzer flags such as `-fork=8`. `make merge` then adds
only the inputs that raise coverage and skips any that diverge. `make minimize`
rebuilds each corpus from scratch after a target or libsecp changes what inputs
reach. Every one of them also exists per target, as in `make fuzz-ecdsa`.

`make coverage` replays the corpus through `guide`'s flags without sanitizers and
writes an llvm-cov report to `build/coverage`: a per-file summary in `report.txt`
and annotated sources in `html/`. `COVERAGE_VARIANT=guide_int64` shows the int64
arithmetic instead.

## CI

`.github/workflows/ci.yml` runs `make check` on x86_64 and aarch64 runners and
`make docker-cross` on pushes to master and on pull requests, so every change
replays the corpus. `make check` runs in Debian trixie with GCC 14 and clang 19.

`.github/workflows/bump-secp256k1.yml` moves `external/secp256k1` to upstream
master daily, runs CI on the bump and fast-forwards master to it only if CI
passes. A failed run leaves the bump on the `bump-secp256k1` branch: upstream
broke a target or changed behavior against the baseline.

`.github/workflows/fuzz.yml` fuzzes every target for two hours daily on x86_64
and aarch64, adds the x86_64 inputs that raise coverage once CI passes on them,
and uploads a coverage report. A divergence fails the run without printing it,
skips that day's corpus update, and uploads its reproducer and logs encrypted to
the maintainer's PGP key (`ci/maintainer.asc`), since artifacts of a public
repository are public:

```sh
gh run download <run-id> -n reproducers && gpg -d reproducers.tar.gz.gpg | tar -xz
# reproducers-aarch64 for the aarch64 job
```

## Coverage

What the corpus reaches in libsecp, replayed through `guide`'s configuration by
`make coverage`. The daily fuzzing workflow refreshes it with
`make readme-coverage`, using clang 19: branch counts differ between LLVM
versions.

<!-- coverage:begin -->

libsecp `b63c6afb9924`: 85.99% of lines, 59.03% of branches, 88.66% of functions.

| File | Lines | Branches | Functions |
|------|------:|---------:|----------:|
| `contrib/lax_der_parsing.c` | 100.00% | 100.00% | 100.00% |
| `src/assumptions.h` | 0.00% | - | 0.00% |
| `src/ecdsa_impl.h` | 79.69% | 63.46% | 100.00% |
| `src/eckey_impl.h` | 93.10% | 75.00% | 100.00% |
| `src/ecmult_const_impl.h` | 100.00% | 74.14% | 100.00% |
| `src/ecmult_gen_impl.h` | 94.92% | 78.12% | 85.71% |
| `src/ecmult_impl.h` | 41.10% | 32.69% | 44.00% |
| `src/field_5x52_impl.h` | 97.85% | 66.67% | 96.67% |
| `src/field_5x52_int128_impl.h` | 100.00% | 50.00% | 100.00% |
| `src/field_impl.h` | 96.61% | 66.07% | 96.77% |
| `src/group_impl.h` | 96.41% | 71.47% | 95.74% |
| `src/hash_impl.h` | 79.31% | 63.04% | 83.33% |
| `src/hsort_impl.h` | 94.55% | 76.92% | 100.00% |
| `src/int128_native_impl.h` | 91.18% | 60.71% | 89.47% |
| `src/modinv64_impl.h` | 99.18% | 62.24% | 100.00% |
| `src/modules/ecdh/main_impl.h` | 93.62% | 58.33% | 66.67% |
| `src/modules/ellswift/main_impl.h` | 95.29% | 61.18% | 88.89% |
| `src/modules/extrakeys/main_impl.h` | 91.87% | 57.94% | 100.00% |
| `src/modules/musig/keyagg_impl.h` | 92.39% | 62.16% | 100.00% |
| `src/modules/musig/session_impl.h` | 92.09% | 63.67% | 100.00% |
| `src/modules/recovery/main_impl.h` | 96.00% | 60.61% | 100.00% |
| `src/modules/schnorrsig/main_impl.h` | 93.64% | 64.06% | 90.00% |
| `src/modules/silentpayments/main_impl.h` | 87.60% | 65.95% | 100.00% |
| `src/scalar_4x64_impl.h` | 100.00% | 52.74% | 100.00% |
| `src/scalar_impl.h` | 100.00% | 59.09% | 100.00% |
| `src/scratch_impl.h` | 0.00% | 0.00% | 0.00% |
| `src/secp256k1.c` | 78.16% | 47.93% | 76.00% |
| `src/selftest.h` | 83.33% | 33.33% | 100.00% |
| `src/util.h` | 62.42% | 70.00% | 65.00% |

<!-- coverage:end -->
