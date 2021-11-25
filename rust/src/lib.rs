//! Elliptic Curve Integrated Encryption Scheme using x25519
//!

//!
//! ## Example Usage
//! ```rust
//! use rand_core::{OsRng};
//! use ecies_25519::{EciesX25519, generate_keypair, parse_openssl_25519_pubkey_der, parse_openssl_25519_privkey_der};
//! 
//! let mut os_rng = OsRng::default();
//! 
//! let recv_kp = generate_keypair(&mut os_rng).unwrap();
//! let recv_pub_key = parse_openssl_25519_pubkey_der(&recv_kp.public_der).unwrap();
//! let recv_priv_key = parse_openssl_25519_privkey_der(&recv_kp.private_der).unwrap();
//! 
//! let message = "I 💖🔒";
//! 
//! let ecies_inst = EciesX25519::new();
//!
//! // Encrypt the message with the public key
//! let encrypted_data = ecies_inst.encrypt(
//!    &recv_pub_key, 
//!    message.as_bytes(), 
//!    &mut os_rng
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

mod backend {
  use aes_gcm::aead::{self, generic_array::GenericArray, Aead, NewAead};
  use aes_gcm::Aes256Gcm;
  use hkdf::Hkdf;
  use rand_core::{CryptoRng, RngCore};
  use sha2::Sha256;

  use super::AesKey;
  use super::Error;
  use super::AES_IV_LENGTH;

  pub(crate) fn hkdf_sha256(master: &[u8], hkdf_info: &[u8]) -> AesKey {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(hkdf_info, &mut out)
        .expect("ecies-ed25519: unexpected error in rust hkdf_sha256");

    out
  }

  pub(crate) fn aes_encrypt<R: CryptoRng + RngCore>(
    key: &AesKey,
    msg: &[u8],
    rng: &mut R,
  ) -> Result<Vec<u8>, Error> {
      let key = GenericArray::from_slice(key);
      let aead = Aes256Gcm::new(key);

      let mut nonce = [0u8; AES_IV_LENGTH];
      rng.try_fill_bytes(&mut nonce)
          .map_err(|_| Error::EncryptionFailedRng)?;
      let nonce = GenericArray::from_slice(&nonce);

      let ciphertext = aead
          .encrypt(nonce, msg)
          .map_err(|_| Error::EncryptionFailed)?;

      let mut output = Vec::with_capacity(AES_IV_LENGTH + ciphertext.len());
      
      output.extend(nonce);
      output.extend(ciphertext);

      Ok(output)
  }

  pub(crate) fn aes_decrypt(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, aead::Error> {
    let key = GenericArray::from_slice(key);
    let aead = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
    let encrypted = &ciphertext[AES_IV_LENGTH..];

    let decrypted = aead.decrypt(nonce, encrypted)?;

    Ok(decrypted)
  }
}

pub use curve25519_parser::{KeyPair, PublicKey, StaticSecret, parse_openssl_25519_privkey_der, parse_openssl_25519_pubkey_der};
use rand_core::{CryptoRng, RngCore};

use backend::*;

const AES_IV_LENGTH: usize = 12;

/// The length of a `SecretKey`, in bytes.
// const SECRET_KEY_LENGTH: usize = 32;

/// The length of a `PublicKey`, in bytes.
const PUBLIC_KEY_LENGTH: usize = 32;

type AesKey = [u8; 32];

/// Generate a keypair, ready for use in ECIES
pub fn generate_keypair<T>(csprng: &mut T) -> Option<KeyPair>
where
    T: RngCore + CryptoRng,
{
  return curve25519_parser::generate_keypair(csprng);
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
    }
  }

  /// Encrypt a message using ECIES, it can only be decrypted by the receiver's SecretKey.
  pub fn encrypt<R: CryptoRng + RngCore>(
    &self,
    receiver_pub: &PublicKey,
    msg: &[u8],
    rng: &mut R,
  ) -> Result<Vec<u8>, Error> {

    let eph_key_pair = generate_keypair(rng).unwrap();
    let priv_key = parse_openssl_25519_privkey_der(&eph_key_pair.private_der).unwrap();
    let aes_key = encapsulate(&priv_key, &receiver_pub, self.hkdf_info.as_slice());

    let encrypted_data = aes_encrypt(&aes_key, msg, rng)?;
    
    let mut packed_msg = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted_data.len());
    let eph_pub_key = parse_openssl_25519_pubkey_der(&eph_key_pair.public_der).unwrap();
    packed_msg.extend(eph_pub_key.to_bytes());
    packed_msg.extend(encrypted_data);
    
    return Ok(packed_msg);
  }

  /// Decrypt a ECIES encrypted ciphertext using the receiver's SecretKey.
  pub fn decrypt(
    &self,
    receiver_sk: &StaticSecret,
    packed_msg: &[u8]
  ) -> Result<Vec<u8>, Error> {

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
  use rand_core::{OsRng};

  use super::*;

  #[test]
  fn test_decrypt_static_data_and_private_key() {

    let expected_data = "Hello World";
    let ecies_inst = EciesX25519::new();

    let recv_priv_key = StaticSecret::from([216, 165, 49, 19, 235, 206, 111, 153, 78, 96, 85, 233, 182, 163, 21, 167, 137, 130, 23, 76, 112, 242, 181, 238, 63, 18, 113, 21, 239, 179, 250, 78]);
    
    let encrypted_data = "l1nwORTMVjzABXw2Ng+arfOEKhSiwAi7Z98bhTCnHgISwzes9gudq2ni9CgdfKM71wk2EfBFPaMJWHT1pBDArI7I35TQvK4=";
    let packed_msg = &base64::decode(encrypted_data).unwrap();

    let decrypted_data_bytes = ecies_inst.decrypt(
        &recv_priv_key,
    &packed_msg
    ).unwrap();

    let decrypted_data = String::from_utf8(decrypted_data_bytes.clone()).unwrap();

    assert_eq!(
      decrypted_data.as_str(),
      expected_data
    );
  }

  #[test]
  fn test_endecrypt_static_data() {
    let mut os_rng = OsRng::default();

    let recv_kp = generate_keypair(&mut os_rng).unwrap();
    let recv_pub_key = parse_openssl_25519_pubkey_der(&recv_kp.public_der).unwrap();
    let recv_priv_key = parse_openssl_25519_privkey_der(&recv_kp.private_der).unwrap();

    let expected_data = "Hello World";
    let ecies_inst = EciesX25519::new();

    let encrypted_data = ecies_inst.encrypt(
      &recv_pub_key, 
      expected_data.as_bytes(), 
      &mut os_rng
    ).unwrap();

    let decrypted_data_bytes = ecies_inst.decrypt(
        &recv_priv_key,
    &encrypted_data
    ).unwrap();

    let decrypted_data = String::from_utf8(decrypted_data_bytes.clone()).unwrap();

    assert_eq!(
      decrypted_data.as_str(),
      expected_data
    );
  }
}