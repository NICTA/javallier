package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class RawPaillierTest {

  static PaillierPrivateKey privateKey;
  static PaillierPublicKey publicKey;
  
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    privateKey = PaillierPrivateKey.create(2048);
    publicKey = privateKey.getPublicKey();
  }
  
  @Test
  public void testEncryptionDecryption(){
    BigInteger plaintext = new BigInteger("42");
    BigInteger ciphertext = publicKey.raw_encrypt(plaintext);
    assertNotEquals(plaintext, ciphertext);
    assertEquals(plaintext, privateKey.raw_decrypt(ciphertext));
  }
  
  @Test
  public void testAdd(){
    BigInteger a = new BigInteger("123");
    BigInteger b = new BigInteger("7654");
    BigInteger ciphertext = publicKey.raw_add(publicKey.raw_encrypt(a), publicKey.raw_encrypt(b));
    assertEquals(privateKey.raw_decrypt(ciphertext), a.add(b));
    //test overflow
    a = publicKey.modulus;
    b = BigInteger.ONE;
    ciphertext = publicKey.raw_add(publicKey.raw_encrypt(a), publicKey.raw_encrypt(b));
    assertEquals(privateKey.raw_decrypt(ciphertext), BigInteger.ONE);
  }
  
  @Test
  public void testMul(){
    BigInteger a = new BigInteger("95831");
    BigInteger k = BigInteger.ONE;
    BigInteger ciphertext = publicKey.raw_multiply(publicKey.raw_encrypt(a), k);
    assertEquals(privateKey.raw_decrypt(ciphertext), a);
    k = new BigInteger("842");
    ciphertext = publicKey.raw_multiply(publicKey.raw_encrypt(a), k);
    assertEquals(privateKey.raw_decrypt(ciphertext), a.multiply(k));
    a = publicKey.modulus.subtract(BigInteger.ONE);
    k = new BigInteger("42");
    ciphertext = publicKey.raw_multiply(publicKey.raw_encrypt(a), k);
    assertEquals(privateKey.raw_decrypt(ciphertext), a.multiply(k).mod(publicKey.modulus));
  }
  
  @Test
  public void testObfuscate(){
    BigInteger a = new BigInteger("123456789");
    BigInteger ciphertext = publicKey.raw_encrypt(a);
    BigInteger obuscatedCiphertext = publicKey.raw_obfuscate(ciphertext);
    assertNotEquals(ciphertext, obuscatedCiphertext);
    assertEquals(privateKey.raw_decrypt(obuscatedCiphertext), a);
  }
  
}
