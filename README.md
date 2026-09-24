# diffsecp

Differential fuzzing of [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
across builds: compilers, optimization levels and library configurations. Each
input runs through every build in one process, and any difference in results
aborts with a reproducer.

Bitcoin nodes run libsecp256k1 built by different compilers: Guix release builds
use GCC for Linux and Windows and clang for macOS, and distros use whatever they
ship. Builds that disagree on whether a signature is valid split the chain.
libsecp256k1's own tests check known answers; diffsecp checks that builds
agree on inputs nobody wrote down.

## Requirements

clang with libFuzzer, gcc, GNU make and binutils (`objcopy`). Docker for
cross-architecture runs, unless GCC 14 cross toolchains, clang 19 and qemu-user
are installed.

## Usage

```sh
git submodule update --init
make -j
make check                                              # selftest, corpus replay, short fuzz run
mkdir -p build/new/ecdsa
build/fuzz_ecdsa build/new/ecdsa corpus/ecdsa           # fuzz from the corpus until stopped
build/fuzz_ecdsa -merge=1 corpus/ecdsa build/new/ecdsa  # keep inputs with new coverage
build/fuzz_ecdsa crash-<hash>                           # replay a divergence
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
reaching verify paths random bytes almost never hit. `group` builds its points as
k·G from fuzzed scalars, so it reaches the exceptional cases of point addition
(doubling, P + (-P), infinity) that signatures can't.

## Variants

`variants.mk` lists the builds: a name, a compiler and flags. Every transcript is
compared against the first variant, `guide`, which is built with coverage, ASan,
UBSan and libsecp's `VERIFY` checks. It steers the fuzzer and catches the harness
misusing internal APIs. `guide_int64` does the same on the int64 arithmetic
(10x26 field, 8x32 scalar), which `guide` never runs, at the cost of about 40%
fewer executions per second. The others cover release builds with GCC and clang,
optimizer extremes (`-O0`, `-Os`, `-O3 -march=native`), each arithmetic
implementation (int128, int128_struct, int64) and the smallest tables.
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
make docker-cross        # toolchains from ci/Dockerfile; seeds a missing corpus first
make cross               # same, with cross toolchains installed locally
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
report false divergences.

`make selftest` checks the harness itself. It links an extra copy of `guide`
that flips the last transcript byte and expects every fuzzer to report it, so
it fails if per-variant flags stop reaching the compiler or the comparison
misses a byte or a variant. `make check` includes it.

## Corpus

`corpus/<target>` is committed. It was grown by coverage-guided fuzzing and
minimized with `-merge=1`. `make check` replays it through every variant and
`make cross` on every architecture. Merging new inputs, instead of fuzzing
straight into `corpus/`, keeps only those that add coverage.

## CI

`.github/workflows/ci.yml` runs `make check` and `make docker-cross` on pushes
to master and on pull requests, so every change replays the corpus. `make check`
runs in Debian trixie with GCC 14 and clang 19.
