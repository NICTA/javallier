package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class MockPaillierContextTest {

  static PaillierPrivateKey key;
  static PaillierPublicKey publicKey;
  static MockPaillierContext mockContext;
  
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    key = PaillierPrivateKey.create(2048);
    publicKey = key.getPublicKey();
    mockContext = publicKey.createMockSignedContext();
  }

  @Test
  public void testConstructor() throws Exception {
    PaillierContext context = null;

    try {
      context = new MockPaillierContext(null, false, 10);
      fail("Successfully created a context with null public key");
    } catch (NullPointerException e) {
    }
    assertNull(context);

    try {
      context = new MockPaillierContext(publicKey, false, 0);
      fail("Successfully created a context with precision less than one");
    } catch (IllegalArgumentException e) {
    }
    assertNull(context);

    try {
      context = new MockPaillierContext(publicKey, true, 1);
      fail("Successfully created a context with precision less than one when signed is true");
    } catch (IllegalArgumentException e) {
    }
    assertNull(context);

    try {
      context = new MockPaillierContext(publicKey, true, 2080);
      fail("Successfully created a context with precision greater than the public key's modulus bit length");
    } catch (IllegalArgumentException e) {
    }
    assertNull(context);

    context = new MockPaillierContext(publicKey, true, 2048);
    assertNotNull(context);
    // Check public key
    assertNotNull(context.getPublicKey());
    assertEquals(publicKey, context.getPublicKey());
    // Check signed
    assertTrue(context.isSigned());
    // Check precision
    assertNotNull(context.getPrecision());
    assertEquals(2048, context.getPrecision());
  }
  
  @Test
  public void testObfuscate(){
    EncryptedNumber n = new EncryptedNumber(mockContext, BigInteger.ONE, 0);
    EncryptedNumber m = mockContext.obfuscate(n);
    assertEquals(n.ciphertext, m.ciphertext);
    assertEquals(n.exponent, m.exponent);
    assertEquals(n.context, m.context);
    assertEquals(n.isSafe, m.isSafe);
  }
  
  @Test
  public void testEncrypt(){
    EncodedNumber n = mockContext.encode(42.42);
    EncryptedNumber m = mockContext.encrypt(n);
    assertEquals(n.value, m.ciphertext);
    assertEquals(n.exponent,m.exponent);
  }
  
  @Test
  public void testAdd(){
    EncodedNumber n = mockContext.encode(42.42e-120);
    EncodedNumber m = mockContext.encode(123);
    EncryptedNumber nplusm = mockContext.encrypt(n).add(mockContext.encrypt(m));
    EncodedNumber nplusm_e = n.add(m);
    assertEquals(nplusm.calculateCiphertext(), nplusm_e.value);
    assertEquals(nplusm.exponent, nplusm_e.exponent);

    EncodedNumber n2 = mockContext.encode(123);
    EncodedNumber m2 = mockContext.encode(42.42e-120);
    EncryptedNumber nplusm2 = mockContext.encrypt(n2).add(mockContext.encrypt(m2));
    EncodedNumber nplusm_e2 = n2.add(m2);
    assertEquals(nplusm2.calculateCiphertext(), nplusm_e2.value);
    assertEquals(nplusm2.exponent, nplusm_e2.exponent);
  }
  
  @Test
  public void testAdditiveInverse(){
    EncodedNumber n = mockContext.encode(123.456);
    EncodedNumber minusN = mockContext.additiveInverse(n);
    assertEquals(minusN.decodeDouble(), n.decodeDouble()*-1, 1e-100);
    EncryptedNumber en = mockContext.encrypt(n);
    EncryptedNumber minusEN = mockContext.additiveInverse(en);
    assertEquals(key.decrypt(en.add(minusEN)).decodeDouble(), 0.0, 1e-100);
    EncodedNumber zero = mockContext.encode(0);
    EncodedNumber minusZero = mockContext.additiveInverse(zero);
    assertEquals(zero, minusZero);
    assertEquals(0, zero.decodeLong());
  }
  
  @Test
  public void testMultiply(){
    EncodedNumber n = mockContext.encode(-987.654321);
    EncodedNumber m = mockContext.encode(462435.80712);
    EncryptedNumber nm = mockContext.encrypt(n).multiply(m);
    assertEquals(key.decrypt(nm), n.multiply(m));
  }

  @Test
  public void testEquals() {
    MockPaillierContext context1 = publicKey.createMockSignedContext();
    MockPaillierContext context2 = null;
    MockPaillierContext context3, context4;

    assertTrue(context1.equals(context1)); // Compare to itself
    assertFalse(context1.equals(publicKey)); // Compare to other object
    assertFalse(context1.equals(null)); // Compare to null

    assertFalse(context1.equals(context2)); // Compare to uninitialised mock Paillier context
    context2 = publicKey.createMockUnsignedContext();
    assertFalse(context1.equals(context2)); // Compare to a different context

    context3 = publicKey.createMockSignedContext(1000);
    context4 = publicKey.createMockUnsignedContext(1000);
    assertFalse(context1.equals(context3));
    assertFalse(context1.equals(context4));
  }
}
