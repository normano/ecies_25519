import * as asn from "asn1.js";
import { createPrivateKey, createPublicKey } from "crypto";

const ASN1ECPkcs8Key = asn.define("Pkcs8Key", function() {
  this.seq().obj(
    this.key("version").int(),
    this.key("algorithmIdentifier").seq().obj(
      this.key("privateKeyType").objid({
        "1 2 840 10045 3 1 7": "prime256v1",
        "1 3 101 110": "x25519",
        "1 3 101 111": "x448",
        "1 3 101 112": "ed25519",
        "1 3 101 113": "ed448",
        "1 3 132 0 10": "secp256k1",
        "1 3 132 0 34": "secp384r1",
        "1 3 132 0 35": "secp521r1",
      })
    ),
    this.key("privateKey").octstr()
  );
});

const ASN1ECSpkiKey = asn.define("SpkiKey", function() {
  this.seq().obj(
    this.key("algorithmIdentifier").seq().obj(
      this.key("parameters").objid({
        "1 2 840 10045 3 1 7": "prime256v1",
        "1 3 101 110": "x25519",
        "1 3 101 111": "x448",
        "1 3 101 112": "ed25519",
        "1 3 101 113": "ed448",
        "1 3 132 0 10": "secp256k1",
        "1 3 132 0 34": "secp384r1",
        "1 3 132 0 35": "secp521r1",
      })
    ),
    this.key("publicKey").bitstr()
  );
});

export function parsePemPrivateKey(privKeyStr: string): Buffer {

  const privateKey = createPrivateKey({
    "key": privKeyStr,
    "format": "pem"
  });

  const recvPrivKeyDer = privateKey.export({ format: "der", type: "pkcs8" });
  const recvPrivKeyDerDecoded = ASN1ECPkcs8Key.decode(recvPrivKeyDer, "der");
  const recvPrivKey = (recvPrivKeyDerDecoded.privateKey.length == 34) ? recvPrivKeyDerDecoded.privateKey.slice(2) : recvPrivKeyDerDecoded.privateKey;

  return recvPrivKey;
}

export function parsePemPublicKey(pubKeyStr: string): Buffer {

  const publicKey = createPublicKey({
    "format": "pem",
    "type": "spki",
    "key": pubKeyStr,
  });

  const recvPubKeyDer = publicKey.export({"format": "der", "type": "spki"});
  const recvPubDerDecoded = ASN1ECSpkiKey.decode(recvPubKeyDer, "der");
  const recvPubKey = recvPubDerDecoded.publicKey.data;

  return recvPubKey;
}
