/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PaillierPublicKeyTest {

  private static PaillierPrivateKey defPrivateKey;
  private static PaillierPublicKey defPublicKey;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    defPrivateKey = PaillierPrivateKey.create(2048);
    defPublicKey = defPrivateKey.getPublicKey();
  }

  @Test
  public void testConstructor() throws Exception {
    PaillierPublicKey publicKey = null;

    try {
      publicKey = new PaillierPublicKey(null);
      fail("Succesfully created a public key with a null modulus");
    } catch (NullPointerException e) {
    }
    assertNull(publicKey);

    BigInteger modulus = new BigInteger("17").multiply(new BigInteger("19"));
    publicKey = new PaillierPublicKey(modulus);
    assertNotNull(publicKey);
    // Check modulus
    assertNotNull(publicKey.getModulus());
    assertEquals(modulus, publicKey.getModulus());
    // Check modulus squared
    assertNotNull(publicKey.getModulusSquared());
    assertEquals(modulus.multiply(modulus), publicKey.getModulusSquared());
    // Check generator
    assertNotNull(publicKey.getGenerator());
    assertEquals(modulus.add(BigInteger.ONE), publicKey.getGenerator());
  }

  @Test
  public void testCreateSignedFullContext() throws Exception {
    PaillierContext context = defPublicKey.createSignedContext();
    assertNotNull(context);
    assertEquals(true, context.isSigned());
    assertEquals(true, context.isFullPrecision());
  }

  @Test
  public void testCreateUnsignedFullContext() throws Exception {
    PaillierContext context = defPublicKey.createUnsignedContext();
    assertNotNull(context);
    assertEquals(false, context.isSigned());
    assertEquals(true, context.isFullPrecision());
  }

  @Test
  public void testCreateSignedPartialContext() throws Exception {
    PaillierContext context = defPublicKey.createSignedContext(2044);
    assertNotNull(context);
    assertEquals(true, context.isSigned());
    assertEquals(false, context.isFullPrecision());

    context = defPublicKey.createSignedContext(2048);
    assertNotNull(context);
    assertEquals(true, context.isSigned());
    assertEquals(true, context.isFullPrecision());
  }

  @Test
  public void testCreateUnsignedPartialContext() throws Exception {
    PaillierContext context = defPublicKey.createUnsignedContext(2044);
    assertNotNull(context);
    assertEquals(false, context.isSigned());
    assertEquals(false, context.isFullPrecision());

    context = defPublicKey.createUnsignedContext(2048);
    assertNotNull(context);
    assertEquals(false, context.isSigned());
    assertEquals(true, context.isFullPrecision());
  }

//  @Test
//  public void testCreateDoubleContext() {
//    PaillierContext context = CONFIGURATION_DOUBLE.context();
//
//    // Test that the extreme floating point values are encodable
//    PaillierContextTest.testEncodable(context, Double.MAX_VALUE);
//    PaillierContextTest.testEncodable(context, Double.MIN_VALUE);
//    PaillierContextTest.testEncodable(context, -Double.MAX_VALUE);
//    PaillierContextTest.testEncodable(context, -Double.MIN_VALUE);
//
//    // Test that the extreme floating point values (with extended precision)
//    // are encodable
//    final Number MAX_NUMBER = new Number(
//            BigInteger.ONE.shiftLeft(Number.DOUBLE_MAX_PRECISION).subtract(
//                    BigInteger.ONE), Number.DOUBLE_MIN_VALUE_EXPONENT);
//    PaillierContextTest.testEncodable(context, MAX_NUMBER);
//    PaillierContextTest.testEncodable(context, MAX_NUMBER.negate());
//
//    // Test that the number after MAX_NUMBER is not encodable
//    final Number INVALID_NUMBER = new Number(
//            BigInteger.ONE.shiftLeft(Number.DOUBLE_MAX_PRECISION),
//            Number.DOUBLE_MIN_VALUE_EXPONENT);
//    PaillierContextTest.testUnencodable(context, INVALID_NUMBER);
//    PaillierContextTest.testUnencodable(context, INVALID_NUMBER.negate());
//  }

  @Test
  public void testEquals() throws Exception {
    assertTrue(defPublicKey.equals(defPublicKey)); // Compare to itself
    assertFalse(defPublicKey.equals(defPrivateKey)); // Compare to other object
    assertFalse(defPublicKey.equals(null)); // Compare to null

    PaillierPublicKey otherPublicKey = null;
    assertFalse(defPublicKey.equals(otherPublicKey)); // Compare to an uninitialised public key

    BigInteger modulus = new BigInteger("17").multiply(new BigInteger("19"));
    otherPublicKey = new PaillierPublicKey(modulus);
    assertFalse(defPublicKey.equals(otherPublicKey)); // Compare to another public key with the same modulus

    BigInteger differentModulus = new BigInteger("19").multiply(new BigInteger("23"));
    otherPublicKey = new PaillierPublicKey(differentModulus);
    assertFalse(defPublicKey.equals(otherPublicKey)); // Compare to another public key with different modulus

  }
}
