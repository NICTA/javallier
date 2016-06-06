package com.n1analytics.paillier.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;
import com.n1analytics.paillier.util.BigIntegerUtil;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;


public class PrivateKeyJsonSerialiser implements PaillierPrivateKey.Serializer {
  ObjectNode data;
  ObjectMapper mapper;
  String comment;

  public PrivateKeyJsonSerialiser(String comment) {
    mapper = new ObjectMapper();
    mapper.enable(SerializationFeature.INDENT_OUTPUT);
    this.comment = comment;
  }

  @Override
  public String toString() {
    return data.toString();
  }

  @Override
  public void serialize(PaillierPublicKey publickey, BigInteger p, BigInteger q) {
    data = mapper.createObjectNode();
    data.put("kty", "DAJ");
    ArrayNode an = data.putArray("key_ops");
    an.add("decrypt");

    PublicKeyJsonSerialiser serialisedPublicKey = new PublicKeyJsonSerialiser(comment);
    publickey.serialize(serialisedPublicKey);
    data.set("pub", serialisedPublicKey.getNode());


    data.put("kid", comment);

    BigInteger lambda = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
    String encodedLambda = new String(Base64.encodeBase64(lambda.toByteArray()));
    data.put("lambda", encodedLambda);

    BigInteger mu = BigIntegerUtil.invert(lambda, publickey.getModulus());
    String encodedMu = new String(Base64.encodeBase64(mu.toByteArray()));
    data.put("mu", encodedMu);
  }

}
