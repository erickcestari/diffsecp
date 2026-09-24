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
cross-architecture runs, unless the cross toolchains and qemu-user are installed.

## Usage

```sh
git submodule update --init
make -j
make check                               # short run of every target
mkdir -p corpus/ecdsa
build/fuzz_ecdsa corpus/ecdsa            # fuzz until stopped
build/fuzz_ecdsa crash-<hash>            # replay a divergence
```

A divergence prints the two builds, the first differing transcript byte and the
bytes around it.

## Targets

| Target       | Covers                                                             |
|--------------|--------------------------------------------------------------------|
| `ecdsa`      | pubkey parsing, strict and lax DER, low-S normalization, sign, verify |
| `schnorrsig` | BIP340 sign and verify, x-only parsing, taproot tweak check         |
| `field`      | field arithmetic via a register machine (internal API)              |
| `scalar`     | scalar arithmetic via a register machine (internal API)             |

The signature targets sign first and then mutate the signature, message or key,
reaching verify paths random bytes almost never hit.

## Variants

`variants.mk` lists the builds: a name, a compiler and flags. Every transcript is
compared against the first variant, `guide`, which is built with coverage, ASan,
UBSan and libsecp's `VERIFY` checks. It steers the fuzzer and catches the harness
misusing internal APIs. The others cover release builds with GCC and clang,
optimizer extremes (`-O0`, `-Os`, `-O3 -march=native`), each arithmetic
implementation (int128, int128_struct, int64) and the smallest tables.

To add one, append its name to `VARIANTS` and set `<name>_CC` and
`<name>_CFLAGS`. Overrides also work from the command line, for example
`make gcc_release_CC=gcc-14`.

## Cross-architecture

Builds for other architectures can't share a process, so `make cross` replays
the corpus out of process instead. `src/replay.c` runs one build over every
corpus input and prints a digest of each transcript. It is built statically for
each entry in `arches.mk` and run under qemu-user or wine, and the digests are
compared against x86_64.

The architectures follow the Guix release targets that run on Linux or Wine:
32-bit ARM, aarch64, riscv64, big-endian ppc64 and win64. macOS is missing
because it needs Apple's SDK and has no user-mode emulator.

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
