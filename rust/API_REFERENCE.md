# ecies_25519 Rust API Reference (v0.2.0+)

This document provides a quick reference for the public API of the `ecies_25519` Rust crate (as of v0.2.0).

**Important Note on Error Handling (v0.2.0):**
This version of the library has certain internal operations that will `panic` on failure rather than returning a `Result::Err`. Specifically:
*   Errors during HKDF key derivation (used in both encryption and decryption) will cause a panic.
*   Errors during the internal parsing of *ephemeral keys* generated during encryption will cause a panic.
*   Providing an invalid ephemeral public key (e.g., all zeros) within the `packed_msg` to `decrypt` may cause a panic during its conversion to a `PublicKey` type.
Future versions may improve this to return `Error` variants for all failure modes.

## Core Functionality (`EciesX25519`)

The main struct for performing ECIES operations.

*   **`EciesX25519::new() -> Self`**
    *   Creates a new instance with default settings (uses `"ecies_x25519"` as HKDF info).

*   **`ecies_inst.encrypt<R: CryptoRng + RngCore>(&self, receiver_pub: &PublicKey, msg: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>`**
    *   Encrypts the byte slice `msg` for the recipient identified by `receiver_pub`.
    *   Requires a cryptographically secure random number generator `rng`.
    *   **Process:**
        1.  Generates an ephemeral X25519 key pair internally for each encryption. (Note: Parsing these self-generated keys uses `.unwrap()` internally in v0.2.0, which would panic on an unexpected generation/parsing issue).
        2.  Performs X25519 ECDH with the `receiver_pub` and the ephemeral private key.
        3.  Derives an AES-256-GCM key using HKDF-SHA256 from the ECDH shared secret and the ephemeral public key. (Note: HKDF errors currently cause a panic in v0.2.0).
        4.  Encrypts the `msg` using AES-256-GCM with a randomly generated 12-byte nonce.
    *   **Output:** Returns the ciphertext `Vec<u8>` on success, formatted as: `[ephemeral_public_key (32 bytes) | AES-GCM nonce (12 bytes) | ciphertext_with_AEAD_tag (variable)]`.
    *   **Errors:** Returns `Err(Error)` for specific failures (see `Error` enum variants `EncryptionFailed`, `EncryptionFailedRng`). Other internal failures may panic (see note above).

*   **`ecies_inst.decrypt(&self, receiver_sk: &StaticSecret, packed_msg: &[u8]) -> Result<Vec<u8>, Error>`**
    *   Decrypts the `packed_msg` (as produced by `encrypt`) using the recipient's `receiver_sk`.
    *   **Process:**
        1.  Checks if `packed_msg` is long enough to contain at least an ephemeral public key.
        2.  Extracts the ephemeral public key from `packed_msg`. (Note: Conversion to `PublicKey` type may panic if the bytes are invalid in v0.2.0, e.g., all zeros).
        3.  Performs X25519 ECDH with `receiver_sk` and the extracted ephemeral public key.
        4.  Re-derives the AES key via HKDF-SHA256. (Note: HKDF errors currently cause a panic in v0.2.0).
        5.  Extracts the nonce and actual ciphertext from `packed_msg`.
        6.  Decrypts and authenticates the ciphertext using AES-256-GCM.
    *   **Output:** Returns the original plaintext `Vec<u8>` on success.
    *   **Errors:** Returns `Err(Error)` on failure (see `Error` enum variants `DecryptionFailedCiphertextShort`, `DecryptionFailed`). Other internal failures may panic (see note above).

## Key Generation & Parsing

These functions handle key creation and parsing from standard formats (PEM/DER - PKCS#8 v1, SubjectPublicKeyInfo). They transparently convert Ed25519 keys to their X25519 counterparts.

*   **`generate_keypair<T: RngCore + CryptoRng>(csprng: &mut T) -> KeyPairDer`**
    *   Generates a new X25519 key pair using the provided `csprng`.
    *   The private key is generated from a 32-byte random seed; this seed is what's stored in the PKCS#8 DER structure for X25519. The `StaticSecret` derived from this seed internally applies clamping.
    *   Returns a `KeyPairDer` struct containing the DER-encoded public (SubjectPublicKeyInfo) and private (PKCS#8 v1) keys.

*   **`parse_public_key(pem_or_der_bytes: &[u8]) -> Result<PublicKey, KeyParsingError>`**
    *   Parses a public key, automatically detecting PEM (`PUBLIC KEY` tag) or DER (SubjectPublicKeyInfo) format.
    *   Accepts both X25519 (OID `1.3.101.110`) and Ed25519 (OID `1.3.101.112`) formats. Ed25519 public keys are converted to their corresponding X25519 Montgomery form.
    *   Returns the corresponding X25519 `PublicKey` or a `KeyParsingError`.

*   **`parse_private_key(pem_or_der_bytes: &[u8]) -> Result<StaticSecret, KeyParsingError>`**
    *   Parses a private key, automatically detecting PEM (`PRIVATE KEY` tag) or DER (PKCS#8 v1) format.
    *   Accepts both X25519 and Ed25519 formats. Ed25519 private key seeds are converted to X25519 private key seeds by taking the first 32 bytes of `SHA512(ed25519_seed)`.
    *   Returns the corresponding X25519 `StaticSecret` or a `KeyParsingError`.

## Core Types

*   **`PublicKey`** (re-export of `x25519_dalek::PublicKey`)
    *   Represents an X25519 public key (32 bytes). Used as input for encryption and derived during parsing/generation.

*   **`StaticSecret`** (re-export of `x25519_dalek::StaticSecret`)
    *   Represents an X25519 private key (32 bytes, clamped). Used as input for decryption and derived during parsing.

*   **`KeyPairDer`** (re-export of `parser::KeyPairDer`)
    *   A struct returned by `generate_keypair`.
    *   Fields:
        *   `public_der: Vec<u8>`: SubjectPublicKeyInfo DER bytes for the X25519 public key.
        *   `private_der: Vec<u8>`: PKCS#8 v1 DER bytes for the X25519 private key (containing the 32-byte seed).
    *   Methods:
        *   `public_to_pem(&self) -> String`: Converts `public_der` to PEM format.
        *   `private_to_pem(&self) -> String`: Converts `private_der` to PEM format.

## Error Types

*   **`enum Error`**: Returned by `encrypt` and `decrypt`.
    *   Variants directly returned by `encrypt` or `decrypt` in v0.2.0:
        *   `EncryptionFailed`: AES-GCM encryption itself failed.
        *   `EncryptionFailedRng`: The random number generator failed during nonce generation for AES.
        *   `DecryptionFailed`: AES-GCM decryption or authentication tag verification failed.
        *   `DecryptionFailedCiphertextShort`: The provided ciphertext was too short to contain necessary components (e.g., shorter than an ephemeral public key).
    *   Other defined variants (potential in future versions or via other library uses, but less likely directly from `encrypt`/`decrypt` in v0.2.0 due to current panic behavior for related paths):
        *   `InvalidPublicKeyBytes`: Indicates malformed public key bytes were encountered (more likely from direct use of `parse_public_key` if the input isn't from `generate_keypair`).
        *   `InvalidSecretKeyBytes`: Indicates malformed secret key bytes (similar context to above).

*   **`enum KeyParsingError`** (from `parser` module): Returned by `parse_public_key` and `parse_private_key`.
    *   Variants:
        *   `InvalidDerPrefix`: The DER encoding does not start with the expected prefix for X25519/Ed25519 keys.
        *   `InvalidDerLength { expected: usize, actual: usize }`: The DER encoding has an incorrect total length.
        *   `UnsupportedAlgorithm`: Defined in the enum, but current parsing logic for X25519/Ed25519 is specific; other OIDs would likely result in `InvalidDerPrefix`.
        *   `InvalidKeyBytes`: The key material itself is invalid (e.g., an Ed25519 point fails to decompress).
        *   `PemError(String)`: An error occurred during PEM decoding (e.g., invalid Base64).
        *   `InvalidPemTag { expected: String, actual: String }`: The PEM tag was not "PUBLIC KEY" or "PRIVATE KEY" as expected.