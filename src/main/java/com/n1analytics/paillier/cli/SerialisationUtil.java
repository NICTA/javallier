package com.n1analytics.paillier.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.util.Map;

/**
 * Class for common serialisation utils used in the CLI.
 * */
public class SerialisationUtil {

  public static PaillierPublicKey unserialise_public(Map data) {
    // decode the modulus
    BigInteger n = new BigInteger(Base64.decodeBase64((String) data.get("n")));

    return new PaillierPublicKey(n);
  }

  public static PaillierPrivateKey unserialise_private(Map data) {

    // First step is to unserialise the Public key
    PaillierPublicKey pub = unserialise_public((Map) data.get("pub"));

    BigInteger lambda = new BigInteger(Base64.decodeBase64((String) data.get("lambda")));
    BigInteger mu = new BigInteger(Base64.decodeBase64((String) data.get("mu")));

    return new PaillierPrivateKey(pub, lambda);
  }

  public static ObjectNode serialise_encrypted(EncryptedNumber enc) {
    ObjectNode data;
    ObjectMapper mapper = new ObjectMapper();
    data = mapper.createObjectNode();

    data.put("v", enc.calculateCiphertext().toString());
    data.put("e", enc.getExponent());

    return data;
  }

  public static EncryptedNumber unserialise_encrypted(Map data, PaillierPublicKey pub) {
    BigInteger ciphertext = new BigInteger(data.get("v").toString());
    int exponent = Integer.parseInt(data.get("e").toString());
    PaillierContext context = pub.createSignedContext(32);
    return new EncryptedNumber(context, ciphertext, exponent);
  }

}
