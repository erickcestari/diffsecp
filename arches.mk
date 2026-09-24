# Architectures for `make cross`, which replays the corpus on each and compares
# transcript digests against the first. Each needs <arch>_CC, <arch>_CFLAGS and
# <arch>_RUN (the emulator, empty to run natively), plus <arch>_EXE when the
# toolchain appends a suffix to executables. Binaries are static, so qemu-user
# needs no sysroot.
#
# The list mirrors the Guix release targets that run on Linux or Wine, built
# with the compiler Guix uses for them, GCC 14. Compilers are named by version
# so a toolchain bump in ci/Dockerfile fails instead of silently testing another
# compiler. Each is built with libsecp's defaults, so the widemul choice is
# automatic: 32-bit ARM gets the int64 code. macOS is missing because it needs
# Apple's SDK and has no user-mode emulator.

CROSS_GCC_VERSION ?= 14

ARCHES := x86_64 arm aarch64 riscv64 ppc64 win64

x86_64_CC     := gcc-$(CROSS_GCC_VERSION)
x86_64_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS) $(LIBSECP_ASM_X86_64)
x86_64_RUN    :=

# 32-bit.
arm_CC     := arm-linux-gnueabihf-gcc-$(CROSS_GCC_VERSION)
arm_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS)
arm_RUN    := qemu-arm

aarch64_CC     := aarch64-linux-gnu-gcc-$(CROSS_GCC_VERSION)
aarch64_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS)
aarch64_RUN    := qemu-aarch64

riscv64_CC     := riscv64-linux-gnu-gcc-$(CROSS_GCC_VERSION)
riscv64_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS)
riscv64_RUN    := qemu-riscv64

# Big-endian.
ppc64_CC     := powerpc64-linux-gnu-gcc-$(CROSS_GCC_VERSION)
ppc64_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS)
ppc64_RUN    := qemu-ppc64

# LLP64 and the Windows calling convention.
win64_CC     := x86_64-w64-mingw32-gcc-$(CROSS_GCC_VERSION)-win32
win64_CFLAGS := $(LIBSECP_DEFAULT_CFLAGS) $(LIBSECP_ASM_X86_64)
win64_RUN    := wine
win64_EXE    := .exe
