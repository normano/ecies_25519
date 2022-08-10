import * as x25519 from '@stablelib/x25519';
import test from "ava";

import EciesX25519 from "../src/index.js";

test("EciesX25519 can initialize", (t) => {

  let eciesInst = new EciesX25519();

  t.pass();
});

test("EciesX25519 Decrypt data with static private key", (t) => {

  let eciesInst = new EciesX25519();

  const expectedData = "Hello World";
  const encodedPackedMsg = "iKpx6k75mJBp0xmaW/lAlHDcbDr0GcWoY7IkrSta5WMG0n+CM4rYyJPtO3MBr+/Wyi+ma5c6cIfkwHhwPRy4ylXRC7tlgv4=";
  const recvPrivKey = Buffer.from([204,18,110,7,57,237,146,88,194,199,56,170,190,154,132,17,144,86,103,166,188,35,222,153,86,87,138,200,23,102,145,161]);


  const packedMsg = decodeB64(encodedPackedMsg);
  const staticDecryptedData = eciesInst.decrypt(recvPrivKey, packedMsg);

  t.true(expectedData === staticDecryptedData.toString("utf-8"));
});

test("EciesX25519 caan Encrypt/Decrypt", (t) => {

  let eciesInst = new EciesX25519();

  const recvKeyPair = x25519.generateKeyPair();
  const recvPubKey = Buffer.from(recvKeyPair.publicKey);
  const recvPrivKey = Buffer.from(recvKeyPair.secretKey);

  const expectedData = "Hello World";
  const encryptedData = eciesInst.encrypt(recvPubKey, expectedData);
  t.true(!!encryptedData);
  t.true(encryptedData.length > 0);

  const staticDecryptedData = eciesInst.decrypt(recvPrivKey, encryptedData);

  t.true(expectedData === staticDecryptedData.toString("utf-8"));
});

function encodeB64(data: any): string {
  return Buffer.from(data).toString("base64");
}

function decodeB64(data: string): Buffer {
  return Buffer.from(data, "base64");
}