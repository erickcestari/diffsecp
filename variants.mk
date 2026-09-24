# Builds of libsecp256k1 compared against each other. Each name must be a C
# identifier and needs <name>_CC and <name>_CFLAGS. The first variant is the
# reference every other transcript is compared to. Every variant costs time on
# every input, so each one should change the generated code in a new way.
#
# Other knobs: compiler versions (gcc-14, clang-19), -DECMULT_WINDOW_SIZE=2..15,
# COMB_BLOCKS/COMB_TEETH as 2/5, 11/6 or 43/6. Avoid -flto: variants must be
# native objects.
#
# Sanitized variants must use clang, since the driver links clang's runtimes,
# and need SANITIZE_CFLAGS: without it ASan puts each global in a comdat named
# after it, and the linker drops the tables of all but one sanitized variant.

VARIANTS := guide \
            gcc_release clang_release \
            gcc_O0 clang_Os \
            gcc_O3_native clang_O3_native \
            gcc_O2_int64 clang_O2_int64 gcc_O2_int128_struct \
            clang_O2_small_tables

SANITIZE_CFLAGS := -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all \
                   -fno-sanitize-address-globals-dead-stripping

# libsecp's own build defaults: ECMULT_WINDOW_SIZE=15, ECMULT_GEN_KB=86, and
# x86_64 asm when available. Compiling src/secp256k1.c without them, as guide
# does, gives a 22 kB signing table instead.
RELEASE_CFLAGS := -O2 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6
ifeq ($(shell uname -m),x86_64)
RELEASE_CFLAGS += -DUSE_ASM_X86_64
endif

# Steers the fuzzer: coverage, ASan, UBSan, and libsecp's VERIFY checks, which
# also catch the harness calling internals outside their contract.
guide_CC     := clang
guide_CFLAGS := -O1 -DVERIFY $(SANITIZE_CFLAGS)

# What ships: Guix builds Bitcoin Core with GCC for Linux and Windows and with
# clang for macOS.
gcc_release_CC     := gcc
gcc_release_CFLAGS := $(RELEASE_CFLAGS)

clang_release_CC     := clang
clang_release_CFLAGS := $(RELEASE_CFLAGS)

# Optimizer extremes. -O0 is the closest thing to the source's plain semantics;
# -Os changes inlining decisions.
gcc_O0_CC     := gcc
gcc_O0_CFLAGS := -O0

clang_Os_CC     := clang
clang_Os_CFLAGS := -Os

# Aggressive optimization plus host instructions (BMI2/ADX mulx and adcx on
# x86_64). Reproducers may not replay on a CPU without them.
gcc_O3_native_CC     := gcc
gcc_O3_native_CFLAGS := -O3 -march=native

clang_O3_native_CC     := clang
clang_O3_native_CFLAGS := -O3 -march=native

# The other arithmetic implementations: 10x26 field and 8x32 scalar (int64),
# and 5x52/4x64 on top of the portable 128-bit struct (int128_struct).
gcc_O2_int64_CC     := gcc
gcc_O2_int64_CFLAGS := -O2 -DUSE_FORCE_WIDEMUL_INT64

clang_O2_int64_CC     := clang
clang_O2_int64_CFLAGS := -O2 -DUSE_FORCE_WIDEMUL_INT64

gcc_O2_int128_struct_CC     := gcc
gcc_O2_int128_struct_CFLAGS := -O2 -DUSE_FORCE_WIDEMUL_INT128_STRUCT

# Smallest tables, which change the window and comb code paths in ecmult and
# ecmult_gen.
clang_O2_small_tables_CC     := clang
clang_O2_small_tables_CFLAGS := -O2 -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5
