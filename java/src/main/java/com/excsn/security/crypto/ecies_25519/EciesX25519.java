package com.excsn.security.crypto.ecies_25519;

import com.excsn.security.crypto.hkdf.Hash;
import com.excsn.security.crypto.hkdf.Hkdf;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import com.google.crypto.tink.subtle.X25519;

/**
 * Elliptic Curve Integrated Encryption Scheme or ECIES
 *
 * Curve: x25519
 * Symmetric Algorithm: AES-256-GCN
 * HKDF SHA256
 *
 * Details: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme#Formal_description_of_ECIES
 *
 * Encrypted data format - ECPubKey(32) iv(12) encData(ciphertext + tag)
 */
public class EciesX25519 {

  private static final int AES_KEY_SIZE_BYTES = 32;
  private static final int DERVIED_KEY_SIZE_BYTES = 32;
  private static final int GCM_NONCE_SIZE_BYTES = 12;
  private static final int GCM_TAG_SIZE_BITS = 16 * 8;

  private final String _cipherAlgorithm = "AES_256/GCM/NoPadding";
  private final String _secretKeyAlgorithm = "AES";
  private byte[] _hkdfInfo = "ecies_x25519".getBytes(StandardCharsets.UTF_8);
  private final SecureRandom _secureRandom;
  private final Hkdf _hkdf;

  public EciesX25519() {
    _hkdf = Hkdf.usingHash(Hash.SHA256);

    try {
      _secureRandom = SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public void setHkdfInfo(byte[] hkdfInfo) {
    this._hkdfInfo = hkdfInfo;
  }

  public byte[] encrypt(byte[] recvPublicKey, byte[] dataBytes) throws GeneralSecurityException {

    var ephemeralPrivKey = X25519.generatePrivateKey();
    var ephemeralPubKey = X25519.publicFromPrivate(ephemeralPrivKey);
    var sharedSecretBytes = X25519.computeSharedSecret(ephemeralPrivKey, recvPublicKey);

    var derivedKey = _deriveKey(ephemeralPubKey, sharedSecretBytes);

    var encryptedData = _encryptAes256Gcm(derivedKey, dataBytes);

    var packedMessage = ByteBuffer.allocate(ephemeralPubKey.length + encryptedData[0].length + encryptedData[1].length);
    packedMessage.put(ephemeralPubKey);
    packedMessage.put(encryptedData[0]);
    packedMessage.put(encryptedData[1]);

    return packedMessage.array();
  }

  /**
   * @param recvPrivKeyBytes receiver's private key in byte form
   * @param packedMessage Buffer(Bytes) - ECPubKey(32) iv(12) encData(variable)
   * @return
   */
  public byte[] decrypt(byte[] recvPrivKeyBytes, byte[] packedMessage) throws GeneralSecurityException {

    var ivOffset = AES_KEY_SIZE_BYTES;
    var cipherTextOffset = AES_KEY_SIZE_BYTES + GCM_NONCE_SIZE_BYTES;

    var pubKeyBytes = Arrays.copyOfRange(packedMessage, 0, ivOffset);
    var ivBytes = Arrays.copyOfRange(packedMessage, ivOffset, cipherTextOffset);
    var cipherTextBytes = Arrays.copyOfRange(packedMessage, cipherTextOffset, packedMessage.length);

    var sharedSecretBytes = X25519.computeSharedSecret(recvPrivKeyBytes, pubKeyBytes);
    var derivedKey = _deriveKey(pubKeyBytes, sharedSecretBytes);

    return _decryptAes256Gcm(derivedKey, ivBytes, cipherTextBytes);
  }

  private SecretKey _deriveKey(byte[] peerPubKey, byte[] sharedSecretBytes) {

    var masterKey = new byte[peerPubKey.length + sharedSecretBytes.length];
    System.arraycopy(peerPubKey, 0, masterKey, 0, peerPubKey.length);
    System.arraycopy(sharedSecretBytes, 0, masterKey, peerPubKey.length, sharedSecretBytes.length);

    var secret = _hkdf.extract(null, masterKey);
    var derivedKeyBytes = _hkdf.expand(secret, _hkdfInfo, DERVIED_KEY_SIZE_BYTES);

    return new SecretKeySpec(derivedKeyBytes, _secretKeyAlgorithm);
  }

  public byte[][] _encryptAes256Gcm(SecretKey key, byte[] data) throws GeneralSecurityException {

    var ivBytes = new byte[GCM_NONCE_SIZE_BYTES];
    _secureRandom.nextBytes(ivBytes);

    var cipher = Cipher.getInstance(_cipherAlgorithm);

    var gcmParams = new GCMParameterSpec(GCM_TAG_SIZE_BITS, ivBytes);
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams);

    return new byte[][]{ivBytes, cipher.doFinal(data)};
  }

  public byte[] _decryptAes256Gcm(SecretKey key, byte[] ivBytes, byte[] cipherText) throws GeneralSecurityException {

    var cipher = Cipher.getInstance(_cipherAlgorithm);

    var gcmParams = new GCMParameterSpec(GCM_TAG_SIZE_BITS, ivBytes);
    cipher.init(Cipher.DECRYPT_MODE, key, gcmParams);

    cipher.update(cipherText);

    return cipher.doFinal();
  }
}
