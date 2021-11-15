module com.excsn.security.crypto.ecies_25519 {
  requires tink;
  requires org.bouncycastle.provider;
  requires org.bouncycastle.pkix;

  exports com.excsn.security.crypto.ecies_25519;
}