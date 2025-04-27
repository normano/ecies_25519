# ecies_25519 Rust API Reference (v0.2.0)

This document provides a quick reference for the public API of the `ecies_25519` Rust crate.

## Core Functionality (`EciesX25519`)

The main struct for performing ECIES operations.

*   **`EciesX25519::new() -> Self`**
    *   Creates a new instance with default settings (uses `"ecies_x25519"` as HKDF info).

*   **`ecies_inst.encrypt<R: CryptoRng + RngCore>(&self, receiver_pub: &PublicKey, msg: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>`**
    *   Encrypts the byte slice `msg` for the recipient identified by `receiver_pub`.
    *   Requires a cryptographically secure random number generator `rng`.
    *   Generates an ephemeral X25519 key pair internally for each encryption.
    *   Performs X25519 ECDH, derives an AES-256-GCM key using HKDF-SHA256, and encrypts the data.
    *   Returns the ciphertext `Vec<u8>` on success, formatted as: `[ephemeral_public_key (32 bytes) | AES-GCM nonce (12 bytes) | ciphertext + tag]`.
    *   Returns `Err(Error)` on failure (e.g., RNG error, AES encryption failure).

*   **`ecies_inst.decrypt(&self, receiver_sk: &StaticSecret, packed_msg: &[u8]) -> Result<Vec<u8>, Error>`**
    *   Decrypts the `packed_msg` (as produced by `encrypt`) using the recipient's `receiver_sk`.
    *   Extracts the ephemeral public key, performs ECDH, re-derives the AES key via HKDF, and decrypts/authenticates using AES-256-GCM.
    *   Returns the original plaintext `Vec<u8>` on success.
    *   Returns `Err(Error)` on failure (e.g., ciphertext too short, AES decryption/authentication failure).

## Key Generation & Parsing

These functions handle key creation and parsing from standard formats (PEM/DER - PKCS#8 v1, SubjectPublicKeyInfo). They transparently convert Ed25519 keys to their X25519 counterparts.

*   **`generate_keypair<T: RngCore + CryptoRng>(csprng: &mut T) -> KeyPairDer`**
    *   Generates a new X25519 key pair using the provided `csprng`.
    *   Returns a `KeyPairDer` struct containing the DER-encoded public (SPKI) and private (PKCS#8 v1) keys.

*   **`parse_public_key(pem_or_der_bytes: &[u8]) -> Result<PublicKey, KeyParsingError>`**
    *   Parses a public key, automatically detecting PEM (`PUBLIC KEY` tag) or DER (SubjectPublicKeyInfo) format.
    *   Accepts both X25519 and Ed25519 formats (converts Ed25519).
    *   Returns the corresponding X25519 `PublicKey`.

*   **`parse_private_key(pem_or_der_bytes: &[u8]) -> Result<StaticSecret, KeyParsingError>`**
    *   Parses a private key, automatically detecting PEM (`PRIVATE KEY` tag) or DER (PKCS#8 v1) format.
    *   Accepts both X25519 and Ed25519 formats (converts Ed25519).
    *   Returns the corresponding X25519 `StaticSecret`.

## Core Types

*   **`PublicKey`** (re-export of `x25519_dalek::PublicKey`)
    *   Represents an X25519 public key. Used as input for encryption and derived during parsing/generation.

*   **`StaticSecret`** (re-export of `x25519_dalek::StaticSecret`)
    *   Represents an X25519 private key. Used as input for decryption and derived during parsing.

*   **`KeyPairDer`** (re-export of `parser::KeyPairDer`)
    *   A struct returned by `generate_keypair`.
    *   Fields:
        *   `public_der: Vec<u8>`: SubjectPublicKeyInfo DER bytes.
        *   `private_der: Vec<u8>`: PKCS#8 v1 DER bytes.
    *   Methods:
        *   `public_to_pem(&self) -> String`: Converts `public_der` to PEM.
        *   `private_to_pem(&self) -> String`: Converts `private_der` to PEM.

## Error Types

*   **`enum Error`**: Returned by `encrypt` and `decrypt`. Variants indicate failures during the ECIES process.
*   **`enum KeyParsingError`** (from `parser` module): Returned by `parse_public_key` and `parse_private_key`. Variants indicate failures during key parsing (invalid format, tag, length, bytes, etc.).