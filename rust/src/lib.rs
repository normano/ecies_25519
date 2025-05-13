//! Elliptic Curve Integrated Encryption Scheme using x25519
//!``

//!
//! ## Example Usage
//! ```rust
//! use rand::SeedableRng;
//! use rand_core::{OsRng, TryRngCore};
//! use ecies_25519::{EciesX25519, generate_keypair, parse_public_key, parse_private_key};
//! use rand_chacha::ChaCha8Rng;
//!
//!  let mut os_rng = rand_core::OsRng::default();
//!  let mut seed_prod = [0u8; 32];
//!  os_rng.try_fill_bytes(&mut seed_prod);
//!
//! let mut cha_rng = ChaCha8Rng::from_seed(seed_prod);
//!
//! let recv_kp = generate_keypair(&mut cha_rng);
//! let recv_pub_key = parse_public_key(&recv_kp.public_der).unwrap();
//! let recv_priv_key = parse_private_key(&recv_kp.private_der).unwrap();
//!
//! let message = "I 💖🔒";
//!
//! let ecies_inst = EciesX25519::new();
//!
//! // Encrypt the message with the public key
//! let encrypted_data = ecies_inst.encrypt(
//!    &recv_pub_key,
//!    message.as_bytes(),
//!    &mut cha_rng
//! ).unwrap();
//!
//! // Decrypt the message with the private key
//! let decrypted_data_bytes = ecies_inst.decrypt(
//!   &recv_priv_key,
//!   &encrypted_data
//! ).unwrap();
//!
//! println!("Decrypted data is {}", String::from_utf8(decrypted_data_bytes.clone()).unwrap());
//!```

mod backend;
mod parser;

pub use parser::{parse_private_key, parse_public_key, KeyPairDer, PublicKey, StaticSecret, KeyParsingError};
use rand_core::{CryptoRng, RngCore};

use backend::*;

const AES_IV_LENGTH: usize = 12;

/// The length of a `SecretKey`, in bytes.
// const SECRET_KEY_LENGTH: usize = 32;

/// The length of a `PublicKey`, in bytes.
const PUBLIC_KEY_LENGTH: usize = 32;

type AesKey = [u8; 32];

/// Generate a keypair, ready for use in ECIES
pub fn generate_keypair<T>(csprng: &mut T) -> KeyPairDer
where
  T: RngCore + CryptoRng,
{
  return parser::generate_x25519_keypair_der(csprng);
}

fn generate_shared(secret: &StaticSecret, public: &PublicKey) -> x25519_dalek::SharedSecret {
  return secret.diffie_hellman(&public);
}

fn encapsulate(sk: &StaticSecret, peer_pk: &PublicKey, hkdf_info: &[u8]) -> AesKey {
  let shared_point = generate_shared(sk, peer_pk);

  let pk = PublicKey::from(sk);

  let mut master = [0u8; 32 * 2];
  master[..32].clone_from_slice(pk.as_bytes());
  master[32..].clone_from_slice(shared_point.as_bytes());

  return hkdf_sha256(&master, hkdf_info);
}

fn decapsulate(sk: &StaticSecret, peer_pk: &PublicKey, hkdf_info: &[u8]) -> AesKey {
  let shared_point = generate_shared(sk, peer_pk);

  let mut master = [0u8; 32 * 2];
  master[..32].clone_from_slice(peer_pk.as_bytes());
  master[32..].clone_from_slice(shared_point.as_bytes());

  return hkdf_sha256(&master, hkdf_info);
}

/// Error types
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
  /// Encryption failed
  #[error("ecies-rd25519: encryption failed")]
  EncryptionFailed,

  /// Encryption failed - RNG error
  #[error("ecies-rd25519: encryption failed - RNG error")]
  EncryptionFailedRng,

  /// Decryption failed
  #[error("ecies-rd25519: decryption failed")]
  DecryptionFailed,

  /// Decryption failed - ciphertext too short
  #[error("ecies-rd25519: decryption failed - ciphertext too short")]
  DecryptionFailedCiphertextShort,

  /// Invalid public key bytes
  #[error("ecies-rd25519: invalid public key bytes")]
  InvalidPublicKeyBytes,

  /// Invalid secret key bytes
  #[error("ecies-rd25519: invalid secret key bytes")]
  InvalidSecretKeyBytes,
}

pub struct EciesX25519 {
  hkdf_info: Vec<u8>,
}

impl EciesX25519 {
  pub fn new() -> Self {
    return Self {
      hkdf_info: "ecies_x25519".as_bytes().to_vec(),
    };
  }

  /// Encrypt a message using ECIES, it can only be decrypted by the receiver's SecretKey.
  pub fn encrypt<R: CryptoRng + RngCore>(
    &self,
    receiver_pub: &PublicKey,
    msg: &[u8],
    rng: &mut R,
  ) -> Result<Vec<u8>, Error> {
    let eph_key_pair = generate_keypair(rng);
    let priv_key = parse_private_key(&eph_key_pair.private_der).unwrap();
    let aes_key = encapsulate(&priv_key, &receiver_pub, self.hkdf_info.as_slice());

    let encrypted_data = aes_encrypt(&aes_key, msg, rng)?;

    let mut packed_msg = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted_data.len());
    let eph_pub_key = parse_public_key(&eph_key_pair.public_der).unwrap();
    packed_msg.extend(eph_pub_key.to_bytes());
    packed_msg.extend(encrypted_data);

    return Ok(packed_msg);
  }

  /// Decrypt a ECIES encrypted ciphertext using the receiver's SecretKey.
  pub fn decrypt(&self, receiver_sk: &StaticSecret, packed_msg: &[u8]) -> Result<Vec<u8>, Error> {
    if packed_msg.len() <= PUBLIC_KEY_LENGTH {
      return Err(Error::DecryptionFailedCiphertextShort);
    }

    let mut eph_pk: [u8; PUBLIC_KEY_LENGTH] = Default::default();
    eph_pk.copy_from_slice(&packed_msg[..PUBLIC_KEY_LENGTH]);
    let ephemeral_pk = PublicKey::from(eph_pk);

    let aes_key = decapsulate(&receiver_sk, &ephemeral_pk, self.hkdf_info.as_slice());

    let encrypted = &packed_msg[PUBLIC_KEY_LENGTH..];
    let decrypted = aes_decrypt(&aes_key, encrypted).map_err(|_| Error::DecryptionFailed)?;

    return Ok(decrypted);
  }
}

#[cfg(test)]
pub mod tests {
  use super::*; // Import items from parent module (ecies_25519)
  use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
  use rand::SeedableRng;
  use rand_chacha::ChaCha8Rng;
  use rand_core::RngCore; // For fill_bytes

  // --- Test Constants ---
  const TEST_SEED: [u8; 32] = [42u8; 32]; // Use a fixed seed for deterministic tests
  const LONG_MESSAGE_LEN: usize = 10 * 1024; // 10 KiB

  // --- Helper Functions ---

  // Create a deterministic RNG for tests
  fn test_rng() -> ChaCha8Rng {
    ChaCha8Rng::from_seed(TEST_SEED)
  }

  // Generate and parse a keypair for tests, panicking on failure (acceptable in tests)
  fn generate_test_keys<R>(rng: &mut R) -> (StaticSecret, PublicKey)
  where
    R: RngCore + CryptoRng, // Specify bounds here
  {
    let kp_der = generate_keypair(rng); // generate_keypair likely already uses a where clause or accepts impl Trait correctly
    let sk =
      parse_private_key(&kp_der.private_der).expect("Test setup: private key parsing failed");
    let pk = parse_public_key(&kp_der.public_der).expect("Test setup: public key parsing failed");
    (sk, pk)
  }

  // --- Success Case Tests (Round Trips) ---

  #[test]
  fn test_round_trip_basic() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"This is a standard test message.";

    let encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed");

    let decrypted = ecies
      .decrypt(&receiver_sk, &encrypted)
      .expect("Decryption failed");

    assert_eq!(message, decrypted.as_slice());
  }

  #[test]
  fn test_round_trip_empty_message() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b""; // Empty message

    let encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption of empty message failed");

    let decrypted = ecies
      .decrypt(&receiver_sk, &encrypted)
      .expect("Decryption of empty message failed");

    assert!(decrypted.is_empty());
    assert_eq!(message, decrypted.as_slice());
  }

  #[test]
  fn test_round_trip_unicode_message() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    // Message from example plus more chars
    let message = "I 💖🔒 - Ελληνικά - Русский - 中文 - 😊".as_bytes();

    let encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption of unicode message failed");

    let decrypted = ecies
      .decrypt(&receiver_sk, &encrypted)
      .expect("Decryption of unicode message failed");

    assert_eq!(message, decrypted.as_slice());
    assert_eq!(
      String::from_utf8_lossy(&decrypted),
      String::from_utf8_lossy(message)
    );
  }

  #[test]
  fn test_round_trip_long_message() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let mut message = vec![0u8; LONG_MESSAGE_LEN];
    rng.fill_bytes(&mut message); // Fill with random data

    let encrypted = ecies
      .encrypt(&receiver_pk, &message, &mut rng)
      .expect("Encryption of long message failed");

    let decrypted = ecies
      .decrypt(&receiver_sk, &encrypted)
      .expect("Decryption of long message failed");

    assert_eq!(message.len(), decrypted.len());
    assert_eq!(message, decrypted);
  }

  #[test]
  fn test_round_trip_binary_data() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let mut message = [0u8; 256]; // Some arbitrary binary data length
    rng.fill_bytes(&mut message);

    let encrypted = ecies
      .encrypt(&receiver_pk, &message, &mut rng)
      .expect("Encryption of binary data failed");

    let decrypted = ecies
      .decrypt(&receiver_sk, &encrypted)
      .expect("Decryption of binary data failed");

    assert_eq!(message.as_slice(), decrypted.as_slice());
  }

  // --- Decryption Failure Tests ---

  #[test]
  fn test_decrypt_with_wrong_key() {
    let mut rng = test_rng();
    let (_receiver1_sk, receiver1_pk) = generate_test_keys(&mut rng);
    let (receiver2_sk, _receiver2_pk) = generate_test_keys(&mut rng); // Different keypair
    let ecies = EciesX25519::new();
    let message = b"Message for recipient 1";

    // Encrypt for receiver 1
    let encrypted = ecies
      .encrypt(&receiver1_pk, message, &mut rng)
      .expect("Encryption failed");

    // Attempt decrypt with receiver 2's key
    let result = ecies.decrypt(&receiver2_sk, &encrypted);

    // Expect a generic decryption failure (AEAD tag/key mismatch)
    assert!(
      matches!(result, Err(Error::DecryptionFailed)),
      "Decrypting with wrong key should fail (DecryptionFailed)"
    );
  }

  #[test]
  fn test_decrypt_ciphertext_too_short_for_pubkey() {
    let mut rng = test_rng();
    let (receiver_sk, _receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();

    // Create data shorter than the public key length
    let short_ciphertext = vec![0u8; PUBLIC_KEY_LENGTH - 5]; // Example: 5 bytes too short

    let result = ecies.decrypt(&receiver_sk, &short_ciphertext);

    // Expect specific error
    assert!(
      matches!(result, Err(Error::DecryptionFailedCiphertextShort)),
      "Decrypting ciphertext shorter than pubkey len should fail (DecryptionFailedCiphertextShort)"
    );

    // Test exactly length of pubkey (still too short for AEAD data)
    let exact_len_ciphertext = vec![0u8; PUBLIC_KEY_LENGTH];
    let result_exact = ecies.decrypt(&receiver_sk, &exact_len_ciphertext);
    assert!(
      matches!(result_exact, Err(Error::DecryptionFailedCiphertextShort)), // Boundary check
      "Decrypting ciphertext exactly pubkey len should fail (DecryptionFailedCiphertextShort)"
    );
  }

  #[test]
  fn test_decrypt_ciphertext_too_short_for_aead() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"Short AEAD test"; // Need some data to encrypt

    // Encrypt normally first to get a valid structure prefix
    let encrypted_full = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed for setup");

    // Minimum valid AEAD len = IV_LEN + TagLen (16 for GCM)
    let min_aead_len = AES_IV_LENGTH + 16;
    let required_total_len = PUBLIC_KEY_LENGTH + min_aead_len;

    // Create ciphertext just shorter than required for minimal AEAD data
    if encrypted_full.len() >= required_total_len {
      let short_ciphertext = &encrypted_full[..required_total_len - 1];
      let result = ecies.decrypt(&receiver_sk, short_ciphertext);

      // Expect generic decryption failure (underlying AEAD decrypt will fail)
      assert!(
        matches!(result, Err(Error::DecryptionFailed)),
        "Decrypting ciphertext too short for AEAD should fail (DecryptionFailed)"
      );
    } else {
      // This case shouldn't happen with AES_IV_LENGTH=12 and non-empty message, but good guard
      panic!("Generated ciphertext unexpectedly short during test setup");
    }
  }

  #[test]
  fn test_decrypt_tampered_ephemeral_key() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"Tamper ephemeral key test";

    let mut encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed");

    // Tamper: Flip a bit in the ephemeral public key part
    if encrypted.len() >= PUBLIC_KEY_LENGTH {
      encrypted[PUBLIC_KEY_LENGTH / 2] ^= 0x80; // Flip MSB of a middle byte
    } else {
      panic!("Encrypted data too short for tampering test");
    }

    let result = ecies.decrypt(&receiver_sk, &encrypted);

    // Expect generic decryption failure (derived AES key will be wrong -> AEAD fails)
    assert!(
      matches!(result, Err(Error::DecryptionFailed)),
      "Decrypting with tampered ephemeral key should fail (DecryptionFailed)"
    );
  }

  #[test]
  fn test_decrypt_tampered_nonce() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"Tamper nonce test";

    let mut encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed");

    // Tamper: Flip a bit in the nonce part
    let nonce_start_index = PUBLIC_KEY_LENGTH;
    let nonce_end_index = nonce_start_index + AES_IV_LENGTH;
    if encrypted.len() >= nonce_end_index {
      encrypted[nonce_start_index + AES_IV_LENGTH / 2] ^= 0x01; // Flip LSB of a middle byte
    } else {
      panic!("Encrypted data too short for nonce tampering test");
    }

    let result = ecies.decrypt(&receiver_sk, &encrypted);

    // Expect generic decryption failure (AEAD fails due to wrong nonce/tag check)
    assert!(
      matches!(result, Err(Error::DecryptionFailed)),
      "Decrypting with tampered nonce should fail (DecryptionFailed)"
    );
  }

  #[test]
  fn test_decrypt_tampered_ciphertext_body() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"Tamper ciphertext body test - need enough length";

    let mut encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed");

    // Tamper: Flip a bit in the actual encrypted data (after pubkey and nonce)
    let ciphertext_start_index = PUBLIC_KEY_LENGTH + AES_IV_LENGTH;
    if encrypted.len() > ciphertext_start_index + 5 {
      // Ensure there's some ciphertext body to tamper
      encrypted[ciphertext_start_index + 2] ^= 0x40; // Flip a bit somewhere in the body
    } else {
      panic!("Encrypted data too short for ciphertext body tampering test");
    }

    let result = ecies.decrypt(&receiver_sk, &encrypted);

    // Expect generic decryption failure (AEAD tag check will fail)
    assert!(
      matches!(result, Err(Error::DecryptionFailed)),
      "Decrypting with tampered ciphertext body should fail (DecryptionFailed)"
    );
  }

  #[test]
  fn test_decrypt_tampered_ciphertext_tag() {
    let mut rng = test_rng();
    let (receiver_sk, receiver_pk) = generate_test_keys(&mut rng);
    let ecies = EciesX25519::new();
    let message = b"Tamper tag test";

    let mut encrypted = ecies
      .encrypt(&receiver_pk, message, &mut rng)
      .expect("Encryption failed");

    // Tamper: Flip a bit in the likely tag region (last 16 bytes for AES-GCM)
    let len = encrypted.len();
    if len >= 16 {
      // Ensure there are at least 16 bytes for a tag
      encrypted[len - 8] ^= 0x02; // Flip a bit somewhere in the last 16 bytes
    } else {
      panic!("Encrypted data too short for tag tampering test");
    }

    let result = ecies.decrypt(&receiver_sk, &encrypted);

    // Expect generic decryption failure (AEAD tag check will fail)
    assert!(
      matches!(result, Err(Error::DecryptionFailed)),
      "Decrypting with tampered AEAD tag should fail (DecryptionFailed)"
    );
  }

  // --- Static Vector Test ---
  // (Keep the original static test for regression)
  #[test]
  fn test_decrypt_static_data_and_private_key() {
    let expected_data = "Hello World";
    let ecies_inst = EciesX25519::new();

    let recv_priv_key = StaticSecret::from([
      216, 165, 49, 19, 235, 206, 111, 153, 78, 96, 85, 233, 182, 163, 21, 167, 137, 130, 23, 76,
      112, 242, 181, 238, 63, 18, 113, 21, 239, 179, 250, 78,
    ]);

    let encrypted_data =
            "l1nwORTMVjzABXw2Ng+arfOEKhSiwAi7Z98bhTCnHgISwzes9gudq2ni9CgdfKM71wk2EfBFPaMJWHT1pBDArI7I35TQvK4=";
    // Ensure base64 is a dev-dependency
    let packed_msg = &BASE64_STANDARD.decode(encrypted_data).unwrap();

    let decrypted_data_bytes = ecies_inst
      .decrypt(&recv_priv_key, &packed_msg)
      .expect("Static vector decryption failed");

    let decrypted_data = String::from_utf8(decrypted_data_bytes.clone()).unwrap();

    assert_eq!(decrypted_data.as_str(), expected_data);
  }
}
