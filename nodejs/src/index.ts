import * as x25519 from "@stablelib/x25519";
import { createCipheriv, createDecipheriv,randomFillSync } from "crypto";
import { hkdf } from "fast-sha256";

interface EncryptedAESGCMOutput {
  iv: Buffer;
  cipherText: Buffer;
}

const AES_KEY_SIZE_BYTES = 32;
const DERIVED_KEY_SIZE_BYTES = 32;
const GCM_NONCE_SIZE_BYTES = 12;
const GCM_TAG_SIZE_BYTES = 16;
const CIPHER_ALGORITHM = "aes-256-gcm";

function isEmptyString(value: string) {
  return value === null || value === undefined || typeof value !== "string" || value === "";
}

/**
 * Elliptic Curve Integrated Encryption Scheme or ECIES
 * Curve: x25519 
 * Symmetric algorithm: AES-256-GCM
 * KDF: HKDF-SHA256
 */
export default class EciesX25519 {
  private _hkdfInfo = new Uint8Array(Buffer.from("ecies_x25519"));

  constructor() {}

  /**
   * Info to set for the HMAC Key derivation function. Must be consistent for sender and receiver.
   */
  public setHkdfInfo(hkdfInfo: Buffer) {

    if(!Buffer.isBuffer(hkdfInfo) || hkdfInfo.length <= 0) {
      throw new Error("hkdfInfo is blank");
    }

    this._hkdfInfo = new Uint8Array(hkdfInfo);
  }

  /**
   * Encrypts data using the receiver's public key.
   * @returns packed message
   */
  public encrypt(recvPublicKey: Buffer, data: string): Buffer {

    if(!Buffer.isBuffer(recvPublicKey) || recvPublicKey.length !== 32) {
      throw new Error("recvPublicKey is invalid");
    }
    
    if(isEmptyString(data)) {
      throw new Error("data is blank");
    }

    const { publicKey: ephPubKey, secretKey: ephPrivateKey } = x25519.generateKeyPair();
    const sharedSecret = computeSharedKey(ephPrivateKey, new Uint8Array(recvPublicKey));

    if(!sharedSecret) {

      throw new Error("sharedSecret is incorrect");
    }
  
    const masterKey = Buffer.concat([ephPubKey, sharedSecret]);
    const derivedKey = hkdf(masterKey, undefined, this._hkdfInfo, DERIVED_KEY_SIZE_BYTES);
  
    const dataBuffer = Buffer.from(data);
    const encryptedData = encryptAes256Gcm(derivedKey, dataBuffer);
  
    const iv = encryptedData.iv;
    const cipherText = encryptedData.cipherText;
    const packedMessage = Buffer.concat([ephPubKey, iv, cipherText]);
  
    return packedMessage;
  }

  public decrypt(recvPrivateKey: Buffer, packedMsg: Buffer): Buffer {
  
    if(!Buffer.isBuffer(recvPrivateKey) || recvPrivateKey.length !== 32) {
      throw new Error("recvPrivateKey is invalid");
    }

    if(!Buffer.isBuffer(packedMsg) || recvPrivateKey.length !== 32) {
      throw new Error("encodedPackedMsg is blank");
    }

    if(!packedMsg || packedMsg.length <= (AES_KEY_SIZE_BYTES + GCM_NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES)) {
      throw new Error("encodedPackedMsg is in incorrect format");
    }
  
    const ivOffset = AES_KEY_SIZE_BYTES;
    const cipherTextOffset = AES_KEY_SIZE_BYTES + GCM_NONCE_SIZE_BYTES;
  
    const pubKey = packedMsg.slice(0, ivOffset);
    const iv = packedMsg.slice(ivOffset, cipherTextOffset);
    const cipherText = packedMsg.slice(cipherTextOffset);
  
    const sharedSecret = computeSharedKey(recvPrivateKey, pubKey);
    if(!sharedSecret) {

      throw new Error("sharedSecret is incorrect");
    }
    
    const masterKey = Buffer.concat([pubKey, sharedSecret]);
  
    const derivedKey = hkdf(masterKey, undefined, this._hkdfInfo, DERIVED_KEY_SIZE_BYTES);
  
    const decryptedData = decryptAes256Gcm(derivedKey, iv, cipherText);
  
    return decryptedData;
  }
}

function encryptAes256Gcm(secretKey: Uint8Array, data: Buffer): EncryptedAESGCMOutput {

  const iv = randomFillSync(Buffer.alloc(GCM_NONCE_SIZE_BYTES));

  const aes = createCipheriv(CIPHER_ALGORITHM, secretKey, iv, {
    authTagLength: GCM_TAG_SIZE_BYTES,
  });
  aes.setAutoPadding(false);
  const encData = aes.update(data);
  aes.final();
  
  const tag = aes.getAuthTag();
  const fullEncData = Buffer.concat([encData, tag]);

  return {iv, cipherText: fullEncData};
}

function decryptAes256Gcm(secretKey: Uint8Array, iv: Buffer, fullEncData: Buffer): Buffer {

  const cipherText = fullEncData.slice(0, fullEncData.length - GCM_TAG_SIZE_BYTES);
  const tag = fullEncData.slice(fullEncData.length - GCM_TAG_SIZE_BYTES);
  const aes = createDecipheriv(CIPHER_ALGORITHM, secretKey, iv, {
    authTagLength: GCM_TAG_SIZE_BYTES,
  });

  aes.setAutoPadding(false);
  aes.setAuthTag(tag);

  let data = aes.update(cipherText);
  aes.final();

  return data;
}

export function computeSharedKey(privateKey: Uint8Array, publicKey: Uint8Array) {
  return x25519.sharedKey(privateKey, publicKey);
}
