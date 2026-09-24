# Toolchains and emulators for `make cross`: the versioned compilers arches.mk
# names (GCC 14 and clang 19, as Guix uses), qemu-user for the Linux targets
# and wine for win64.
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        make gcc-14 libc6-dev \
        gcc-14-arm-linux-gnueabihf libc6-dev-armhf-cross \
        gcc-14-aarch64-linux-gnu libc6-dev-arm64-cross \
        gcc-14-riscv64-linux-gnu libc6-dev-riscv64-cross \
        gcc-14-powerpc64-linux-gnu libc6-dev-ppc64-cross \
        clang-19 \
        gcc-mingw-w64-x86-64-win32 wine wine64 \
        qemu-user \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
