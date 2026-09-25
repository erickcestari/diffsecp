# Security

A divergence between builds of libsecp256k1 can split the chain or the P2P
network, so never report one in a public issue. Report it privately to the
libsecp256k1 maintainers as their
[security policy](https://github.com/bitcoin-core/secp256k1/blob/master/SECURITY.md)
describes, whether the cause is libsecp or a compiler building it.

For anything else sensitive about diffsecp, email erickcestari03@gmail.com,
encrypted to `3C1B ED5D 0CF3 A270 BC69 0D3A D7D1 7E26 F2FC 3F3C`
(`ci/maintainer.asc`). CI encrypts its own reproducers to the same key.
