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

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;
import java.util.HashSet;

import static org.junit.Assert.*;

public class PaillierPrivateKeyTest {

  @Category(SlowTests.class)
  @Test
  public void testCreateKeypairs() throws Exception {
    int[] keyLength = {8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};

    for (int i = 0; i < keyLength.length; i++) {
      PaillierPrivateKey privateKey = PaillierPrivateKey.create(keyLength[i]);

      // Check if the private key exist
      assertNotNull(privateKey);
      // Check if the public key associated with this private key exist
      assertNotNull(privateKey.getPublicKey());
      // Check if p exist
      assertNotNull(privateKey.p);
      // Check if q exist
      assertNotNull(privateKey.q);
      // Check if pSquared exist
      assertNotNull(privateKey.pSquared);
      // Check if qSquared exist
      assertNotNull(privateKey.qSquared);
      // Check if hp exist
      assertNotNull(privateKey.hp);
      // Check if hq exist
      assertNotNull(privateKey.hq);
      // Check if pInverse exist
      assertNotNull(privateKey.pInverse);

      PaillierPublicKey publicKey = privateKey.getPublicKey();
      // Check if the public key exist
      assertNotNull(publicKey);
      // Check if n exist
      assertNotNull(publicKey.getModulus());
      // Check if n^2 exist
      assertNotNull(publicKey.getModulusSquared());
      // Check if g exist
      assertNotNull(publicKey.getGenerator());
    }
  }

  @Test
  public void testIllegalKeyLength() throws Exception {
    PaillierPrivateKey privateKey = null;

    int keysizeSmallerThanEight = 4;
    try {
      privateKey = PaillierPrivateKey.create(keysizeSmallerThanEight);
      fail("Successfuly create a private key which key size is smaller than eight.");
    } catch (IllegalArgumentException e) {
    }

    int keysizeNotMultipleOfEight = 1023;
    try {
      privateKey = PaillierPrivateKey.create(keysizeNotMultipleOfEight);
      fail("Successfuly create a private key which key size is not a multiple of eight.");
    } catch (IllegalArgumentException e) {
    }
  }

  @Test
  public void testConstructor() throws Exception {
    PaillierPrivateKey privateKey = null;

    BigInteger modulus = new BigInteger("17").multiply(new BigInteger("19"));
    PaillierPublicKey publicKey = new PaillierPublicKey(modulus);

    // Check if exception is thrown when the public key is null
    try {
      privateKey = new PaillierPrivateKey(null, new BigInteger("288"));
      fail("Succefully created a private key with a null public key");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

    // Check if exception is thrown when the totient is null
    try {
      privateKey = new PaillierPrivateKey(publicKey, null);
      fail("Succefully created a private key with a null totient");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

    // Check if exception is thrown when the totient is negative
    try {
      privateKey = new PaillierPrivateKey(publicKey, BigInteger.ONE.negate());
      fail("Succefully created a private key with a negative totient");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

    // Check if exception is thrown when the totient is equal to modulus
    try {
      privateKey = new PaillierPrivateKey(publicKey, modulus);
      fail("Succefully created a private key with a totient value equals to the public key's modulus");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

    BigInteger totient = new BigInteger("288");
    privateKey = new PaillierPrivateKey(publicKey, totient);
    assertNotNull(privateKey);
    // Check public key
    assertNotNull(privateKey.getPublicKey());
    assertEquals(publicKey, privateKey.getPublicKey());
    // Check p
    assertNotNull(privateKey.p);
    assertEquals(BigInteger.valueOf(19), privateKey.p);
    // Check q
    assertNotNull(privateKey.q);
    assertEquals(BigInteger.valueOf(17), privateKey.q);

    privateKey = null;
    BigInteger p = BigInteger.valueOf(19);
    try {
      privateKey = new PaillierPrivateKey(null, p, p);
      fail("Succefully created a private key with a null public key");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

    try {
      privateKey = new PaillierPrivateKey(publicKey, p, p);
      fail("Succefully created a private key which modulus does not match the prime numbers");
    } catch (IllegalArgumentException e) {
    }
    assertNull(privateKey);

  }

  @Test
  public void testEquals() throws Exception {
    BigInteger modulus = new BigInteger("17").multiply(new BigInteger("19"));
    BigInteger totient = new BigInteger("288");
    PaillierPublicKey publicKey = new PaillierPublicKey(modulus);
    PaillierPrivateKey privateKey = new PaillierPrivateKey(publicKey, totient);

    assertTrue(privateKey.equals(privateKey)); // Compare to itself
    assertFalse(privateKey.equals(publicKey)); // Compare to other object
    assertFalse(privateKey.equals(null)); // Compare to null

    PaillierPrivateKey otherPrivateKey = null;
    assertFalse(privateKey.equals(otherPrivateKey)); // Compare to an uninitialised private key

    BigInteger otherModulus = new BigInteger("13")
        .multiply(new BigInteger("17"));
    BigInteger otherTotient = new BigInteger("192");
    otherPrivateKey = new PaillierPrivateKey(new PaillierPublicKey(otherModulus), otherTotient);
    assertFalse(privateKey.equals(otherPrivateKey)); // Compare to a private key with different public key and totient
  }

  // Key uniqueness tests for key of size 512 bits, 1024 bits and 2104 bits.
  // The selected key sizes correspond to the key size likely used in a real life scenario.
  // The number of repeats correspond to the number of unique keys need to be generated.

  @Category(SlowTests.class)
  @Test
  public void testKeyUniqueness512() throws Exception {
    int repeats = 100;
    HashSet<PaillierPrivateKey> keypairs = new HashSet<PaillierPrivateKey>();
    while (keypairs.size() < repeats) {
      PaillierPrivateKey privateKey = PaillierPrivateKey.create(512);
      if (keypairs.contains(privateKey)) {
        fail("Non unique keypair.");
      }
      keypairs.add(privateKey);
    }
  }

  @Category(SlowTests.class)
  @Test
  public void testKeyUniqueness1024() throws Exception {
    int repeats = 100;
    HashSet<PaillierPrivateKey> keypairs = new HashSet<PaillierPrivateKey>();
    while (keypairs.size() < repeats) {
      PaillierPrivateKey privateKey = PaillierPrivateKey.create(1024);
      if (keypairs.contains(privateKey)) {
        fail("Non unique keypair.");
      }
      keypairs.add(privateKey);
    }
  }

  @Category(SlowTests.class)
  @Test
  public void testKeyUniqueness2048() throws Exception {
    int repeats = 100;
    HashSet<PaillierPrivateKey> keypairs = new HashSet<PaillierPrivateKey>();
    while (keypairs.size() < repeats) {
      PaillierPrivateKey privateKey = PaillierPrivateKey.create(2048);
      if (keypairs.contains(privateKey)) {
        fail("Non unique keypair.");
      }
      keypairs.add(privateKey);
    }
  }
}
