# Toolchains and emulators for `make cross`: one cross compiler per entry in
# arches.mk, qemu-user for the Linux targets and wine for win64.
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        make gcc libc6-dev \
        gcc-arm-linux-gnueabihf libc6-dev-armhf-cross \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
        gcc-riscv64-linux-gnu libc6-dev-riscv64-cross \
        gcc-powerpc64-linux-gnu libc6-dev-ppc64-cross \
        gcc-mingw-w64-x86-64-win32 wine wine64 \
        qemu-user \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
