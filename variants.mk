# Builds of libsecp256k1 compared against each other. Each name must be a C
# identifier and needs <name>_CC and <name>_CFLAGS. The first variant is the
# reference every other transcript is compared to.
#
# Useful knobs: -O levels, -march, compiler versions (gcc-14, clang-19),
# -DUSE_FORCE_WIDEMUL_INT64 (10x26 field, 8x32 scalar),
# -DUSE_FORCE_WIDEMUL_INT128_STRUCT, -DUSE_ASM_X86_64 (x86_64 only),
# -DECMULT_WINDOW_SIZE=2..15. Avoid -flto: variants must be native objects.
#
# Sanitized variants must use clang, since the driver links clang's runtimes,
# and need SANITIZE_CFLAGS: without it ASan puts each global in a comdat named
# after it, and the linker drops the tables of all but one sanitized variant.

VARIANTS := guide gcc_O2 clang_O2 gcc_O2_int64

SANITIZE_CFLAGS := -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all \
                   -fno-sanitize-address-globals-dead-stripping

# Steers the fuzzer: coverage, ASan, UBSan, and libsecp's VERIFY checks, which
# also catch the harness calling internals outside their contract.
guide_CC     := clang
guide_CFLAGS := -O1 -DVERIFY $(SANITIZE_CFLAGS)

gcc_O2_CC     := gcc
gcc_O2_CFLAGS := -O2

clang_O2_CC     := clang
clang_O2_CFLAGS := -O2

gcc_O2_int64_CC     := gcc
gcc_O2_int64_CFLAGS := -O2 -DUSE_FORCE_WIDEMUL_INT64
