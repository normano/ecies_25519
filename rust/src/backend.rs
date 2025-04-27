use rand_core::{CryptoRng, RngCore, TryRngCore};
use aes_gcm::aead::{self, generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
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
  rng
    .try_fill_bytes(&mut nonce)
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
