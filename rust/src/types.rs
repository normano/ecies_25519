use x25519_dalek::{PublicKey as X25519PublicKeyInternal, StaticSecret as X25519StaticSecretInternal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EciesPublicKey(X25519PublicKeyInternal);

impl EciesPublicKey {
  pub(crate) fn from_internal(key: X25519PublicKeyInternal) -> Self {
    EciesPublicKey(key)
  }

  pub(crate) fn as_internal(&self) -> &X25519PublicKeyInternal {
    &self.0
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    self.0.as_bytes()
  }

  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes()
  }

  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    EciesPublicKey(X25519PublicKeyInternal::from(*bytes))
  }
}

#[derive(Clone)]
pub struct EciesSecretKey(X25519StaticSecretInternal);

impl EciesSecretKey {
  pub(crate) fn from_internal(key: X25519StaticSecretInternal) -> Self {
    EciesSecretKey(key)
  }

  pub(crate) fn as_internal(&self) -> &X25519StaticSecretInternal {
    &self.0
  }

  pub fn as_bytes(&self) -> &[u8; 32] {
    self.0.as_bytes()
  }

  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes()
  }

  pub fn from_bytes(bytes: &[u8; 32]) -> Self {
    EciesSecretKey(X25519StaticSecretInternal::from(*bytes))
  }
}

pub use crate::parser::KeyPairDer;
pub use crate::parser::KeyParsingError;
