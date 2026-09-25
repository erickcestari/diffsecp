#!/bin/sh
# Encrypts fuzzing reproducers and logs to the maintainer's PGP key before CI
# uploads them: artifacts of a public repository are public, and a divergence
# can split the chain. The key is committed and pinned by fingerprint rather
# than fetched, so whoever serves it can't swap it. It expires 2028-07-22, after
# which gpg refuses it: re-export maintainer.asc once the expiry is extended.
# Missing paths are skipped.
#
# Usage: ci/seal-reproducers.sh OUTPUT PATH...
set -eu

FINGERPRINT=3C1BED5D0CF3A270BC690D3AD7D17E26F2FC3F3C

out=$1
shift
home=$(mktemp -d)
trap 'gpgconf --homedir "$home" --kill all; rm -rf "$home"' EXIT

gpg --homedir "$home" --batch --quiet --import "$(dirname "$0")/maintainer.asc"
tar -czf "$home/reproducers.tar.gz" --ignore-failed-read "$@"
gpg --homedir "$home" --batch --yes --trust-model always --recipient "$FINGERPRINT" \
    --output "$out" --encrypt "$home/reproducers.tar.gz"
