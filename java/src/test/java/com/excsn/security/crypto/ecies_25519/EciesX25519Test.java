package com.excsn.security.crypto.ecies_25519;

import com.google.crypto.tink.subtle.X25519;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EciesX25519Test {

  private byte[] _recvPrivKeyBytes;
  private byte[] _recvPubKeyBytes;
  private EciesX25519 _eciesX25519;

  @BeforeAll
  public void setup() throws Exception {

    _recvPrivKeyBytes = X25519.generatePrivateKey();
    _recvPubKeyBytes = X25519.publicFromPrivate(_recvPrivKeyBytes);
    _eciesX25519 = new EciesX25519();
  }

  @Test
  public void encryptsAndDecruptsData() throws GeneralSecurityException {

    var data = "Hello World";
    var encodedEncryptedData = _eciesX25519.encrypt(_recvPubKeyBytes, data.getBytes(StandardCharsets.UTF_8));
    Assertions.assertTrue(encodedEncryptedData != null && encodedEncryptedData.length > 0);

    var decryptedData = _eciesX25519.decrypt(_recvPrivKeyBytes, encodedEncryptedData);
    Assertions.assertArrayEquals(data.getBytes(StandardCharsets.UTF_8), decryptedData);
  }

  @Test
  public void decryptsStaticData() throws GeneralSecurityException {

    var recvPrivKeyBytes = new byte[]{-105, -78, 52, -72, 122, 50, 96, 47, -64, 82, 89, 47, -72, -53, -17, 44, 0, 91, -33, -24, -82, -70, 64, -19, 11, 37, 7, 99, -32, -61, -35, -85};
    var expectedData = "Hello World";
    var encodedPackedMsg = "itnwVyRGl7GNW6FMRCy6tao9kx+jOSRMZ2l4mBJlbWASmybkTYjXz9k2p3GVCUFGwR+Kwmd5xBQELMpIJNiipbCFeRqmwd4=";
    var packedMessage = Base64.getDecoder().decode(encodedPackedMsg);
    var decryptedData = _eciesX25519.decrypt(recvPrivKeyBytes, packedMessage);

    Assertions.assertArrayEquals(expectedData.getBytes(StandardCharsets.UTF_8), decryptedData);
  }
}
