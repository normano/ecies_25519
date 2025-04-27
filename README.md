# ECIES X25519 - Cross-Language Implementation

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
<!-- Add other badges as needed, e.g., build status for each language -->

## Overview

This project provides implementations of the **Elliptic Curve Integrated Encryption Scheme (ECIES)** designed for interoperability across different programming languages.

ECIES is a hybrid encryption scheme that combines the convenience of asymmetric (public-key) cryptography with the efficiency of symmetric encryption. It allows anyone to encrypt data using a recipient's public key, ensuring that only the holder of the corresponding private key can decrypt it.

## Cryptographic Primitives

This implementation standardizes on the following modern, secure, and widely-adopted cryptographic algorithms:

*   **Key Exchange:** `X25519` (Curve25519 for ECDH - Elliptic Curve Diffie-Hellman)
*   **Key Derivation:** `HKDF-SHA256` (HMAC-based Key Derivation Function using SHA-256)
*   **Symmetric Encryption:** `AES-256-GCM` (Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode - provides authenticated encryption with associated data - AEAD)

These choices provide strong confidentiality and integrity protection for encrypted data and are expected to remain secure for the foreseeable future.

## Core Concept: `encrypt` / `decrypt`

The primary goal across all language implementations is to offer a simple and consistent core interface:

1.  **`encrypt(recipientPublicKey, plaintext)`:** Takes the recipient's X25519 public key and the data to encrypt. It generates an ephemeral keypair, performs ECDH, derives a symmetric key using HKDF, encrypts the data using AES-256-GCM, and returns a formatted ciphertext. This ciphertext typically includes the ephemeral public key needed for decryption.
2.  **`decrypt(recipientPrivateKey, ciphertext)`:** Takes the recipient's X25519 private key and the formatted ciphertext produced by the `encrypt` function. It extracts the ephemeral public key, performs ECDH, derives the *same* symmetric key using HKDF, and uses AES-256-GCM to decrypt and authenticate the data. It returns the original plaintext if successful, or throws an error if decryption/authentication fails.

The precise output format of `encrypt` and the expected input format for `decrypt` are designed to be **compatible** across the supported language implementations.

## Supported Languages

Implementations are currently available for:

*   **Java:** [[Link to Java Implementation](https://github.com/normano/ecies_25519/tree/main/java)]
*   **JavaScript:** [[Link to JavaScript Implementation](https://github.com/normano/ecies_25519/tree/main/nodejs)]
*   **Rust:** [[Link to Rust Implementation](https://github.com/normano/ecies_25519/tree/main/rust)]

*(Additional languages may be added based on future requirements.)*

## Getting Started

Please refer to the specific README and documentation within each language implementation linked above for detailed installation instructions, usage examples, and any language-specific considerations.

## Use Cases

*   Securely transmitting messages or data to a recipient knowing only their public key.
*   Encrypting configuration secrets for a specific service instance.
*   Building cross-platform applications requiring secure data exchange.

## License

This project and its implementations are licensed under the Mozilla Public License 2.0 (MPL-2.0). See the LICENSE file(s) in the respective implementations for details.

<!-- Optional: Add Contributing section -->
<!--
## Contributing
Contributions are welcome! Please read the CONTRIBUTING.md guide (link TBD) before submitting pull requests.
-->