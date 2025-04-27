//! Efficient parsing and generation of X25519 keys in OpenSSL-compatible
//! DER (PKCS#8 v1 / SubjectPublicKeyInfo) and PEM formats.

use core::convert::TryInto;
use core::fmt;

use pem::PemError;
use sha2::{Digest, Sha512};
use thiserror::Error;

// Re-export core crypto types for convenience
use curve25519_dalek::edwards::CompressedEdwardsY;
pub use x25519_dalek::{PublicKey, StaticSecret};

// --- Constants ---

// PKCS#8 v1 structure for X25519 Private Key (RFC 5958 + RFC 8410 style for Curve25519)
// SEQUENCE {
//   version INTEGER (0),
//   privateKeyAlgorithm AlgorithmIdentifier { OID(1.3.101.110) }, -- id-X25519
//   privateKey OCTET STRING { OCTET STRING { 32-byte-seed } } -- Double Octet String
// }
// This prefix includes the Sequence, Integer(0), AlgorithmIdentifier Sequence+OID,
// and the start of the outer Octet String (tag 0x04, length 0x22) and
// the start of the inner Octet String (tag 0x04, length 0x20)
const PKCS8_X25519_PREFIX: &[u8] =
  b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20";
const PKCS8_X25519_LEN: usize = PKCS8_X25519_PREFIX.len() + 32;

// PKCS#8 v1 structure for Ed25519 Private Key (RFC 8410)
// SEQUENCE {
//   version INTEGER (0),
//   privateKeyAlgorithm AlgorithmIdentifier { OID(1.3.101.112) }, -- id-Ed25519
//   privateKey OCTET STRING { OCTET STRING { 32-byte-seed } } -- Double Octet String
// }
// Similar structure, different OID
const PKCS8_ED25519_PREFIX: &[u8] =
  b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";
const PKCS8_ED25519_LEN: usize = PKCS8_ED25519_PREFIX.len() + 32;

// SubjectPublicKeyInfo structure for X25519 Public Key (RFC 8410)
// SEQUENCE {
//   algorithm AlgorithmIdentifier { OID(1.3.101.110) }, -- id-X25519
//   subjectPublicKey BIT STRING { 32-byte-key }
// }
const SPKI_X25519_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00";
const SPKI_X25519_LEN: usize = SPKI_X25519_PREFIX.len() + 32;

// SubjectPublicKeyInfo structure for Ed25519 Public Key (RFC 8410)
// SEQUENCE {
//   algorithm AlgorithmIdentifier { OID(1.3.101.112) }, -- id-Ed25519
//   subjectPublicKey BIT STRING { 32-byte-compressed-point }
// }
const SPKI_ED25519_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";
const SPKI_ED25519_LEN: usize = SPKI_ED25519_PREFIX.len() + 32;

const PEM_PUBLIC_KEY_TAG: &str = "PUBLIC KEY";
const PEM_PRIVATE_KEY_TAG: &str = "PRIVATE KEY";
const KEY_LEN: usize = 32;

// --- Error Handling ---

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum KeyParsingError {
  #[error("Invalid DER prefix")]
  InvalidDerPrefix,
  #[error("Invalid DER length (expected {expected}, got {actual})")]
  InvalidDerLength { expected: usize, actual: usize },
  #[error("Unsupported algorithm or OID")]
  UnsupportedAlgorithm,
  #[error("Invalid key bytes (e.g., Ed25519 decompression failed)")]
  InvalidKeyBytes,
  #[error("PEM parsing error: {0}")]
  PemError(String), // Store string representation as PemError is not Eq/Clone
  #[error("Invalid PEM tag (expected '{expected}', got '{actual}')")]
  InvalidPemTag { expected: String, actual: String },
}

// Manual implementation because pem::PemError doesn't implement necessary traits
impl From<PemError> for KeyParsingError {
  fn from(e: PemError) -> Self {
    KeyParsingError::PemError(e.to_string())
  }
}

// --- Public Key Parsing ---

/// Parses an X25519 or Ed25519 public key from DER SubjectPublicKeyInfo format.
///
/// Handles both `id-X25519` and `id-Ed25519` OIDs, converting Ed25519 keys
/// to the corresponding X25519 (Montgomery form) public key.
pub fn parse_spki_der(der_bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
  if der_bytes.len() == SPKI_X25519_LEN && der_bytes.starts_with(SPKI_X25519_PREFIX) {
    // Direct X25519 SPKI
    let key_bytes: [u8; KEY_LEN] = der_bytes[SPKI_X25519_PREFIX.len()..]
      .try_into()
      // This panic should be impossible due to length check, but safer to handle
      .map_err(|_| KeyParsingError::InvalidDerLength {
        expected: SPKI_X25519_LEN,
        actual: der_bytes.len(),
      })?;
    Ok(PublicKey::from(key_bytes))
  } else if der_bytes.len() == SPKI_ED25519_LEN && der_bytes.starts_with(SPKI_ED25519_PREFIX) {
    // Ed25519 SPKI - requires conversion
    let compressed_bytes: [u8; KEY_LEN] = der_bytes[SPKI_ED25519_PREFIX.len()..]
      .try_into()
      .map_err(|_| KeyParsingError::InvalidDerLength {
        expected: SPKI_ED25519_LEN,
        actual: der_bytes.len(),
      })?;

    // --- Corrected Ed25519 Parsing Logic ---

    // 1. Attempt to parse the slice into a CompressedEdwardsY.
    //    Map the specific slice error to our generic InvalidKeyBytes error.
    let compressed = CompressedEdwardsY::from_slice(&compressed_bytes)
      .map_err(|_slice_error| KeyParsingError::InvalidKeyBytes)?; // Now we have CompressedEdwardsY

    // 2. Attempt to decompress the point.
    //    Convert the Option<EdwardsPoint> to Result<EdwardsPoint, KeyParsingError>.
    let edwards_point = compressed
      .decompress()
      .ok_or(KeyParsingError::InvalidKeyBytes)?; // Now we have EdwardsPoint

    // Optional: Check if the point is the identity element, which might be considered invalid for some uses.
    // if edwards_point.is_identity() {
    //     return Err(KeyParsingError::InvalidKeyBytes);
    // }

    // 3. Convert the valid EdwardsPoint to Montgomery form and then to PublicKey bytes.
    //    This final step doesn't return Result/Option.
    Ok(PublicKey::from(edwards_point.to_montgomery().to_bytes()))
  } else if der_bytes.starts_with(b"\x30") {
    // Check if it looks like DER
    // Determine expected length based on potential prefix
    let expected_len = if der_bytes.starts_with(&SPKI_X25519_PREFIX[..5]) {
      // Check common prefix part
      SPKI_X25519_LEN
    } else if der_bytes.starts_with(&SPKI_ED25519_PREFIX[..5]) {
      SPKI_ED25519_LEN
    } else {
      // Could check other common prefixes if needed
      return Err(KeyParsingError::InvalidDerPrefix);
    };
    Err(KeyParsingError::InvalidDerLength {
      expected: expected_len,
      actual: der_bytes.len(),
    })
  } else {
    Err(KeyParsingError::InvalidDerPrefix)
  }
}

/// Parses an X25519 or Ed25519 public key, automatically detecting PEM or DER format.
///
/// See [`parse_spki_der`] for details on DER parsing and key conversion.
pub fn parse_public_key(pem_or_der_bytes: &[u8]) -> Result<PublicKey, KeyParsingError> {
  match pem::parse(pem_or_der_bytes) {
    Ok(pem) => {
      if pem.tag() == PEM_PUBLIC_KEY_TAG {
        parse_spki_der(pem.contents())
      } else {
        Err(KeyParsingError::InvalidPemTag {
          expected: PEM_PUBLIC_KEY_TAG.to_string(),
          actual: pem.tag().to_string(),
        })
      }
    }
    Err(_) => {
      // If PEM parsing fails, assume it's DER
      parse_spki_der(pem_or_der_bytes)
    }
  }
}

// --- Private Key Parsing ---

/// Parses an X25519 or Ed25519 private key from DER PKCS#8 v1 format.
///
/// Handles both `id-X25519` and `id-Ed25519` OIDs, converting Ed25519 seeds
/// to the corresponding X25519 secret key via SHA512 hashing as required.
pub fn parse_pkcs8_v1_der(der_bytes: &[u8]) -> Result<StaticSecret, KeyParsingError> {
  if der_bytes.len() == PKCS8_X25519_LEN && der_bytes.starts_with(PKCS8_X25519_PREFIX) {
    // Direct X25519 PKCS#8
    let seed_bytes: [u8; KEY_LEN] =
      der_bytes[PKCS8_X25519_PREFIX.len()..]
        .try_into()
        .map_err(|_| KeyParsingError::InvalidDerLength {
          expected: PKCS8_X25519_LEN,
          actual: der_bytes.len(),
        })?;
    Ok(StaticSecret::from(seed_bytes))
  } else if der_bytes.len() == PKCS8_ED25519_LEN && der_bytes.starts_with(PKCS8_ED25519_PREFIX) {
    // Ed25519 PKCS#8 - requires conversion
    let ed_seed_bytes: [u8; KEY_LEN] =
      der_bytes[PKCS8_ED25519_PREFIX.len()..]
        .try_into()
        .map_err(|_| KeyParsingError::InvalidDerLength {
          expected: PKCS8_ED25519_LEN,
          actual: der_bytes.len(),
        })?;

    // X25519 secret = first 32 bytes of SHA512(Ed25519 seed)
    let hash = Sha512::digest(&ed_seed_bytes);
    let x_seed_bytes: [u8; KEY_LEN] = hash[..KEY_LEN]
      .try_into()
      .expect("SHA512 output is 64 bytes, slicing 32 should always work");
    Ok(StaticSecret::from(x_seed_bytes))
  } else if der_bytes.starts_with(b"\x30") {
    // Check if it looks like DER
    // Determine expected length based on potential prefix
    let expected_len = if der_bytes.starts_with(&PKCS8_X25519_PREFIX[..5]) {
      // Check common prefix part
      PKCS8_X25519_LEN
    } else if der_bytes.starts_with(&PKCS8_ED25519_PREFIX[..5]) {
      PKCS8_ED25519_LEN
    } else {
      return Err(KeyParsingError::InvalidDerPrefix);
    };
    Err(KeyParsingError::InvalidDerLength {
      expected: expected_len,
      actual: der_bytes.len(),
    })
  } else {
    Err(KeyParsingError::InvalidDerPrefix)
  }
}

/// Parses an X25519 or Ed25519 private key, automatically detecting PEM or DER format.
///
/// See [`parse_pkcs8_v1_der`] for details on DER parsing and key conversion.
pub fn parse_private_key(pem_or_der_bytes: &[u8]) -> Result<StaticSecret, KeyParsingError> {
  match pem::parse(pem_or_der_bytes) {
    Ok(pem) => {
      if pem.tag() == PEM_PRIVATE_KEY_TAG {
        parse_pkcs8_v1_der(pem.contents())
      } else {
        Err(KeyParsingError::InvalidPemTag {
          expected: PEM_PRIVATE_KEY_TAG.to_string(),
          actual: pem.tag().to_string(),
        })
      }
    }
    Err(_) => {
      // If PEM parsing fails, assume it's DER
      parse_pkcs8_v1_der(pem_or_der_bytes)
    }
  }
}

// --- Key Generation ---

use rand_core::{CryptoRng, RngCore};

/// Holds an X25519 key pair encoded in standard DER formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPairDer {
  /// SubjectPublicKeyInfo DER bytes.
  pub public_der: Vec<u8>,
  /// PKCS#8 v1 DER bytes.
  pub private_der: Vec<u8>,
}

impl KeyPairDer {
  /// Encodes the public key as PEM.
  pub fn public_to_pem(&self) -> String {
    let pem = pem::Pem::new(PEM_PUBLIC_KEY_TAG.to_string(), self.public_der.clone());
    pem::encode(&pem)
  }

  /// Encodes the private key as PEM.
  pub fn private_to_pem(&self) -> String {
    let pem = pem::Pem::new(PEM_PRIVATE_KEY_TAG.to_string(), self.private_der.clone());
    pem::encode(&pem)
  }
}

/// Generates a new X25519 keypair and returns it encoded in DER formats.
///
/// Uses the provided cryptographic random number generator.
pub fn generate_x25519_keypair_der<R>(rng: &mut R) -> KeyPairDer
where
  R: RngCore + CryptoRng,
{
  // 1. Generate a random 32-byte seed
  let mut seed = [0u8; KEY_LEN];
  rng.fill_bytes(&mut seed);

  // 2. Create the x25519 secret key (applies clamping internally)
  let secret_key = StaticSecret::from(seed);

  // 3. Derive the corresponding public key
  let public_key = PublicKey::from(&secret_key);

  // 4. Construct the DER encodings by prepending the fixed prefixes
  let mut private_der = Vec::with_capacity(PKCS8_X25519_LEN);
  private_der.extend_from_slice(PKCS8_X25519_PREFIX);
  private_der.extend_from_slice(&seed); // PKCS#8 for X25519 contains the raw seed

  let mut public_der = Vec::with_capacity(SPKI_X25519_LEN);
  public_der.extend_from_slice(SPKI_X25519_PREFIX);
  public_der.extend_from_slice(public_key.as_bytes());

  KeyPairDer {
    public_der,
    private_der,
  }
}

#[cfg(test)]
mod tests {
  use super::*; // Import items from parent module
  use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
  use ed25519_dalek::{SecretKey, SignatureError, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
  use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng}; // Deterministic RNG for tests

  // Helper to create a deterministic RNG for tests
  fn test_rng() -> ChaCha8Rng {
    ChaCha8Rng::from_seed([1; 32])
  }

  // === Generation Tests ===

  #[test]
  fn generated_der_keys_have_correct_structure_and_length() {
    let mut rng = test_rng();
    let keypair_der = generate_x25519_keypair_der(&mut rng);

    // Check lengths
    assert_eq!(keypair_der.public_der.len(), SPKI_X25519_LEN);
    assert_eq!(keypair_der.private_der.len(), PKCS8_X25519_LEN);

    // Check prefixes
    assert!(keypair_der.public_der.starts_with(SPKI_X25519_PREFIX));
    assert!(keypair_der.private_der.starts_with(PKCS8_X25519_PREFIX));

    // Basic check of key data lengths (should be KEY_LEN)
    assert_eq!(
      keypair_der.public_der.len() - SPKI_X25519_PREFIX.len(),
      KEY_LEN
    );
    assert_eq!(
      keypair_der.private_der.len() - PKCS8_X25519_PREFIX.len(),
      KEY_LEN
    );
  }

  #[test]
  fn generated_pem_encodings_are_valid() {
    let mut rng = test_rng();
    let keypair_der = generate_x25519_keypair_der(&mut rng);

    let public_pem = keypair_der.public_to_pem();
    let private_pem = keypair_der.private_to_pem();

    // Removed brittle start/end checks:
    // assert!(public_pem.starts_with(&format!("-----BEGIN {}-----", PEM_PUBLIC_KEY_TAG)));
    // assert!(public_pem.ends_with(&format!("-----END {}-----\n", PEM_PUBLIC_KEY_TAG)));
    // assert!(private_pem.starts_with(&format!("-----BEGIN {}-----", PEM_PRIVATE_KEY_TAG)));
    // assert!(private_pem.ends_with(&format!("-----END {}-----\n", PEM_PRIVATE_KEY_TAG)));

    // This parsing is the more robust check:
    let parsed_pub_pem = pem::parse(&public_pem).expect("Generated public PEM should be parseable");
    assert_eq!(parsed_pub_pem.tag(), PEM_PUBLIC_KEY_TAG);
    assert_eq!(parsed_pub_pem.contents(), keypair_der.public_der.as_slice());

    let parsed_priv_pem =
      pem::parse(&private_pem).expect("Generated private PEM should be parseable");
    assert_eq!(parsed_priv_pem.tag(), PEM_PRIVATE_KEY_TAG);
    assert_eq!(
      parsed_priv_pem.contents(),
      keypair_der.private_der.as_slice()
    );
  }

  #[test]
  fn generated_keys_are_consistent_after_reparsing() {
    let mut rng = test_rng();
    let keypair_der = generate_x25519_keypair_der(&mut rng);

    // Reparse DER
    let secret_from_der =
      parse_pkcs8_v1_der(&keypair_der.private_der).expect("Parsing generated private DER failed");
    let public_from_der =
      parse_spki_der(&keypair_der.public_der).expect("Parsing generated public DER failed");

    // Reparse PEM
    let public_pem_str = keypair_der.public_to_pem();
    let private_pem_str = keypair_der.private_to_pem();
    let secret_from_pem =
      parse_private_key(private_pem_str.as_bytes()).expect("Parsing generated private PEM failed");
    let public_from_pem =
      parse_public_key(public_pem_str.as_bytes()).expect("Parsing generated public PEM failed");

    // Check consistency
    assert_eq!(
      secret_from_der.to_bytes(),
      secret_from_pem.to_bytes(),
      "Secret keys from DER and PEM mismatch"
    );
    assert_eq!(
      public_from_der.as_bytes(),
      public_from_pem.as_bytes(),
      "Public keys from DER and PEM mismatch"
    );

    // Verify public key derivation
    let derived_public = PublicKey::from(&secret_from_der);
    assert_eq!(
      derived_public.as_bytes(),
      public_from_der.as_bytes(),
      "Derived public key doesn't match parsed public key"
    );
  }

  // === Manual Parsing Tests ===

  // Helper to construct DER bytes manually
  fn make_der(prefix: &[u8], key_data: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut der = Vec::with_capacity(prefix.len() + KEY_LEN);
    der.extend_from_slice(prefix);
    der.extend_from_slice(key_data);
    der
  }

  // Helper to construct PEM strings manually
  fn make_pem(tag: &str, der_content: &[u8]) -> String {
    let pem = pem::Pem::new(tag.to_string(), der_content.to_vec());
    pem::encode(&pem)
  }

  #[test]
  fn parse_manually_constructed_x25519_der() {
    let test_seed = [2u8; KEY_LEN];
    let expected_secret = StaticSecret::from(test_seed);
    let expected_public = PublicKey::from(&expected_secret);

    let public_der = make_der(SPKI_X25519_PREFIX, expected_public.as_bytes());
    let private_der = make_der(PKCS8_X25519_PREFIX, &test_seed); // Use raw seed for X25519 PKCS8

    let parsed_public = parse_spki_der(&public_der).unwrap();
    let parsed_secret = parse_pkcs8_v1_der(&private_der).unwrap();

    assert_eq!(parsed_public.as_bytes(), expected_public.as_bytes());
    assert_eq!(parsed_secret.to_bytes(), expected_secret.to_bytes());
  }

  #[test]
  fn parse_manually_constructed_ed25519_der_and_verify_conversion() {
    // --- Corrected Ed25519 keypair generation ---
    let mut ed_secret_bytes: SecretKey = [0u8; SECRET_KEY_LENGTH]; // Use the SecretKey type alias directly
    test_rng().fill_bytes(&mut ed_secret_bytes);
    // Create SigningKey directly from the secret bytes
    let ed_signing_key = SigningKey::from_bytes(&ed_secret_bytes);
    // --- End of corrected generation ---

    let ed_verifying_key = ed_signing_key.verifying_key();
    // ed_signing_key.to_bytes() returns the original 32 secret bytes (seed)
    let ed_seed: [u8; SECRET_KEY_LENGTH] = ed_signing_key.to_bytes();
    let ed_public_compressed_bytes = ed_verifying_key.to_bytes(); // Ed25519 SPKI uses the compressed point

    // Calculate the expected X25519 secret (SHA512 of Ed seed)
    let hash = Sha512::digest(&ed_seed);
    let expected_x_seed_bytes: [u8; KEY_LEN] = hash[..KEY_LEN].try_into().unwrap();
    let expected_x_secret = StaticSecret::from(expected_x_seed_bytes);

    // Calculate the expected X25519 public (Montgomery form of Ed public)
    let expected_x_public = PublicKey::from(ed_verifying_key.to_montgomery().to_bytes());

    // Construct the Ed25519 DER structures
    let ed_public_der = make_der(SPKI_ED25519_PREFIX, &ed_public_compressed_bytes);
    let ed_private_der = make_der(PKCS8_ED25519_PREFIX, &ed_seed);

    // Parse using our functions (which should convert to X25519)
    let parsed_x_public = parse_spki_der(&ed_public_der).expect("Parsing Ed public DER failed");
    let parsed_x_secret =
      parse_pkcs8_v1_der(&ed_private_der).expect("Parsing Ed private DER failed");

    // Verify the conversion results
    assert_eq!(
      parsed_x_public.as_bytes(),
      expected_x_public.as_bytes(),
      "Ed->X Public key conversion mismatch"
    );
    assert_eq!(
      parsed_x_secret.to_bytes(),
      expected_x_secret.to_bytes(),
      "Ed->X Secret key conversion mismatch"
    );

    // Verify internal consistency
    assert_eq!(
      PublicKey::from(&parsed_x_secret).as_bytes(),
      parsed_x_public.as_bytes(),
      "Derived key mismatch after Ed->X conversion"
    );
  }

  #[test]
  fn parse_manually_constructed_ed25519_pem_and_verify_conversion() {
    // --- Corrected Ed25519 keypair generation ---
    let mut ed_secret_bytes: SecretKey = [0u8; SECRET_KEY_LENGTH]; // Use the SecretKey type alias directly
    test_rng().fill_bytes(&mut ed_secret_bytes);
    // Create SigningKey directly from the secret bytes
    let ed_signing_key = SigningKey::from_bytes(&ed_secret_bytes);
    // --- End of corrected generation ---

    let ed_verifying_key = ed_signing_key.verifying_key();
    let ed_seed: [u8; SECRET_KEY_LENGTH] = ed_signing_key.to_bytes();
    let ed_public_compressed_bytes = ed_verifying_key.to_bytes();

    // Calculate expected X keys
    let hash = Sha512::digest(&ed_seed);
    let expected_x_seed_bytes: [u8; KEY_LEN] = hash[..KEY_LEN].try_into().unwrap();
    let expected_x_secret = StaticSecret::from(expected_x_seed_bytes);
    let expected_x_public = PublicKey::from(ed_verifying_key.to_montgomery().to_bytes());

    // Construct Ed DER content
    let ed_public_der_content = make_der(SPKI_ED25519_PREFIX, &ed_public_compressed_bytes);
    let ed_private_der_content = make_der(PKCS8_ED25519_PREFIX, &ed_seed);

    // Construct Ed PEM strings
    let ed_public_pem_str = make_pem(PEM_PUBLIC_KEY_TAG, &ed_public_der_content);
    let ed_private_pem_str = make_pem(PEM_PRIVATE_KEY_TAG, &ed_private_der_content);

    // Parse using our functions (should convert)
    let parsed_x_public =
      parse_public_key(ed_public_pem_str.as_bytes()).expect("Parsing Ed public PEM failed");
    let parsed_x_secret =
      parse_private_key(ed_private_pem_str.as_bytes()).expect("Parsing Ed private PEM failed");

    // Verify conversions
    assert_eq!(
      parsed_x_public.as_bytes(),
      expected_x_public.as_bytes(),
      "PEM Ed->X Public key conversion mismatch"
    );
    assert_eq!(
      parsed_x_secret.to_bytes(),
      expected_x_secret.to_bytes(),
      "PEM Ed->X Secret key conversion mismatch"
    );
  }

  #[test]
  fn parse_manually_constructed_x25519_pem() {
    let test_seed = [3u8; KEY_LEN];
    let expected_secret = StaticSecret::from(test_seed);
    let expected_public = PublicKey::from(&expected_secret);

    let public_der_content = make_der(SPKI_X25519_PREFIX, expected_public.as_bytes());
    let private_der_content = make_der(PKCS8_X25519_PREFIX, &test_seed);

    let public_pem_str = make_pem(PEM_PUBLIC_KEY_TAG, &public_der_content);
    let private_pem_str = make_pem(PEM_PRIVATE_KEY_TAG, &private_der_content);

    let parsed_public = parse_public_key(public_pem_str.as_bytes()).unwrap();
    let parsed_secret = parse_private_key(private_pem_str.as_bytes()).unwrap();

    assert_eq!(parsed_public.as_bytes(), expected_public.as_bytes());
    assert_eq!(parsed_secret.to_bytes(), expected_secret.to_bytes());
  }

  // === Error Handling Tests ===

  #[test]
  fn der_parsing_fails_on_incorrect_prefix() {
    let key_data = [4u8; KEY_LEN];
    let mut wrong_public_der = make_der(SPKI_X25519_PREFIX, &key_data);
    wrong_public_der[0] = 0x31; // Change SEQUENCE tag

    let mut wrong_private_der = make_der(PKCS8_X25519_PREFIX, &key_data);
    wrong_private_der[6] = 0x07; // Change OID tag (part of the prefix)

    // Use matches! for Result<PublicKey, ...>
    let pub_res = parse_spki_der(&wrong_public_der);
    assert!(matches!(pub_res, Err(KeyParsingError::InvalidDerPrefix)));

    // Use matches! for Result<StaticSecret, ...> and accept either error
    let priv_res = parse_pkcs8_v1_der(&wrong_private_der);
    assert!(
      matches!(
        priv_res,
        Err(KeyParsingError::InvalidDerPrefix) | Err(KeyParsingError::InvalidDerLength { .. })
      ),
      "Expected InvalidDerPrefix or InvalidDerLength for modified private key prefix"
    );
  }

  #[test]
  fn der_parsing_fails_on_incorrect_length() {
    let key_data = [5u8; KEY_LEN];
    let correct_public_der = make_der(SPKI_X25519_PREFIX, &key_data);
    let correct_private_der = make_der(PKCS8_X25519_PREFIX, &key_data);

    let short_public = &correct_public_der[..correct_public_der.len() - 1];
    let long_public = [&correct_public_der[..], &[0u8]].concat();
    let short_private = &correct_private_der[..correct_private_der.len() - 1];
    let long_private = [&correct_private_der[..], &[0u8]].concat();

    assert!(matches!(
      parse_spki_der(short_public),
      Err(KeyParsingError::InvalidDerLength { .. })
    ));
    assert!(matches!(
      parse_spki_der(&long_public),
      Err(KeyParsingError::InvalidDerLength { .. })
    ));
    assert!(matches!(
      parse_pkcs8_v1_der(short_private),
      Err(KeyParsingError::InvalidDerLength { .. })
    ));
    assert!(matches!(
      parse_pkcs8_v1_der(&long_private),
      Err(KeyParsingError::InvalidDerLength { .. })
    ));
  }

  #[test]
  fn pem_parsing_fails_on_incorrect_tag() {
    let key_data = [6u8; KEY_LEN];
    let public_der_content = make_der(SPKI_X25519_PREFIX, &key_data);
    let private_der_content = make_der(PKCS8_X25519_PREFIX, &key_data);

    let wrong_tag_pub_pem = make_pem("INVALID TAG", &public_der_content);
    let wrong_tag_priv_pem = make_pem("NOT A KEY", &private_der_content);

    let pub_res = parse_public_key(wrong_tag_pub_pem.as_bytes());
    let priv_res = parse_private_key(wrong_tag_priv_pem.as_bytes());

    assert!(matches!(
      pub_res,
      Err(KeyParsingError::InvalidPemTag { .. })
    ));
    assert!(matches!(
      priv_res,
      Err(KeyParsingError::InvalidPemTag { .. })
    ));
  }

  #[test]
  fn pem_parsing_fails_on_corrupted_base64() {
    let key_data = [7u8; KEY_LEN];
    let public_der_content = make_der(SPKI_X25519_PREFIX, &key_data);
    let correct_pem = make_pem(PEM_PUBLIC_KEY_TAG, &public_der_content);

    // Find the base64 block and corrupt it
    let start = correct_pem.find('\n').unwrap() + 1;
    let end = correct_pem.rfind('\n').unwrap();
    let mut corrupted_pem = correct_pem[..start].to_string();
    // Replace valid base64 char 'A' with invalid '!'
    corrupted_pem.push_str(&correct_pem[start..end].replace('A', "!"));
    corrupted_pem.push_str(&correct_pem[end..]);

    let res = parse_public_key(corrupted_pem.as_bytes());
    // Expecting either PemError (if pem::parse catches bad base64)
    // or InvalidDerPrefix (if pem::parse fails generically and fallback DER parse fails)
    assert!(
      matches!(
        res,
        Err(KeyParsingError::PemError(_)) | Err(KeyParsingError::InvalidDerPrefix)
      ),
      "Expected PemError or InvalidDerPrefix for corrupted base64, got {:?}",
      res
    );
  }

  #[test]
  fn pem_parsing_fails_on_corrupted_internal_der() {
    let key_data = [8u8; KEY_LEN];
    let mut public_der_content = make_der(SPKI_X25519_PREFIX, &key_data);
    public_der_content[0] = 0xFF; // Corrupt DER prefix *inside* the PEM content

    let corrupted_content_pem = make_pem(PEM_PUBLIC_KEY_TAG, &public_der_content);

    let res = parse_public_key(corrupted_content_pem.as_bytes());
    // Expecting DER prefix error from the inner parse_spki_der call
    assert_eq!(res, Err(KeyParsingError::InvalidDerPrefix));
  }

  #[test]
  fn parse_fails_gracefully_on_random_bytes() {
    let mut random_data = [0u8; 100];
    test_rng().fill_bytes(&mut random_data);

    // Try parsing as public/private key directly (should fail DER checks)
    assert!(matches!(
      parse_spki_der(&random_data),
      Err(KeyParsingError::InvalidDerPrefix) | Err(KeyParsingError::InvalidDerLength { .. })
    ));
    assert!(matches!(
      parse_pkcs8_v1_der(&random_data),
      Err(KeyParsingError::InvalidDerPrefix) | Err(KeyParsingError::InvalidDerLength { .. })
    ));

    // Try parsing via auto-detect function (should fail PEM then fail DER)
    assert!(matches!(
      parse_public_key(&random_data),
      Err(KeyParsingError::InvalidDerPrefix) | Err(KeyParsingError::InvalidDerLength { .. })
    ));
    assert!(matches!(
      parse_private_key(&random_data),
      Err(KeyParsingError::InvalidDerPrefix) | Err(KeyParsingError::InvalidDerLength { .. })
    ));
  }

  #[test]
  fn ed25519_public_key_invalid_length_in_der() { // Or similar name
      let mut invalid_der = Vec::with_capacity(SPKI_ED25519_LEN);
      invalid_der.extend_from_slice(SPKI_ED25519_PREFIX);
      // Add only 31 bytes instead of 32
      invalid_der.extend_from_slice(&[1u8; 31]);

      // This line creates a slice shorter than the expected full DER length
      let short_der_data = &invalid_der[..SPKI_ED25519_LEN - 1];
      let actual_len = short_der_data.len(); // Get the actual length

      let res = parse_spki_der(short_der_data);

      // Corrected assertion using a guard
      assert!(
          matches!(res, Err(KeyParsingError::InvalidDerLength { expected: e, actual: a })
              if e == SPKI_ED25519_LEN && a == actual_len // Use the calculated actual length
          ),
          "Expected InvalidDerLength for short DER (len {}), got {:?}",
          actual_len, res
      );
  }

  // Add a new test specifically for the length check within the Ed25519 branch
  #[test]
  fn ed25519_public_key_der_overall_length_mismatch() {
    let valid_ed_point = [2u8; 32]; // Use some non-identity value
    let correct_der = make_der(SPKI_ED25519_PREFIX, &valid_ed_point);

    // --- Test too short ---
    let short_der = &correct_der[..SPKI_ED25519_LEN - 1];
    let res_short = parse_spki_der(short_der);
    // Corrected assertion using a guard
    assert!(matches!(
        res_short,
        Err(KeyParsingError::InvalidDerLength { expected: e, actual: a })
        if e == SPKI_ED25519_LEN && a == SPKI_ED25519_LEN - 1 // Check values in the guard
    ));

    // --- Test too long ---
    let long_der = [&correct_der[..], &[0u8]].concat();
    let res_long = parse_spki_der(&long_der);
    // Corrected assertion using a guard
    assert!(matches!(
        res_long,
        Err(KeyParsingError::InvalidDerLength { expected: e, actual: a })
        if e == SPKI_ED25519_LEN && a == SPKI_ED25519_LEN + 1 // Check values in the guard
    ));
  }
}
