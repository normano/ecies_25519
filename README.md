# ECIES X25519

Elliptic Curve Integrated Encryption Scheme is a way to encrypt arbitrary sized data using a receiver's public keys.

This project specifically implements ECIES with X25519 curve, AES-256-GCM and HKDF SHA-256 on multiple languages. These are some of the best in the industry cryptographic algorithms to stand the test of time.

Currently supports Java, Javascript and Rust for the forseeable future. If more languages are needed due to internal requirements then they will be implemented and published.

Note: My thought is that the most ideal interface for a ECIES inteface would be encrypt/decrypt.