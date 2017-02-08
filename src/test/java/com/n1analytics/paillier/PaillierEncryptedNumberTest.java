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
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

import static com.n1analytics.paillier.TestConfiguration.*;
import static com.n1analytics.paillier.TestUtil.EPSILON;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MAX_VALUE;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MIN_VALUE;
import static org.junit.Assert.*;

@RunWith(Enclosed.class)
public class PaillierEncryptedNumberTest {
  static final Random random = new Random();

  @RunWith(Parameterized.class)
  public static class EncryptedNumberParamTest {
    private PaillierContext context;
    private PaillierPrivateKey privateKey;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Parameterized.Parameters
    public static Collection<Object[]> configurations() {
      Collection<Object[]> configurationParams = new ArrayList<>();

      for(TestConfiguration[] confs : CONFIGURATIONS) {
        for(TestConfiguration conf : confs) {
          configurationParams.add(new Object[]{conf});
        }
      }
      return configurationParams;
    }

    public EncryptedNumberParamTest(TestConfiguration conf) {
      this.context = conf.context();
      this.privateKey = conf.privateKey();
    }

    @Test
    public void testAutomaticPrecision0() throws Exception {
      double eps = Math.ulp(1.0d);
      double onePlusEps = 1.0d + eps;
      assert onePlusEps > 1;

      EncryptedNumber ciphertext1 = context.encrypt(onePlusEps);
      double decryption1 = privateKey.decrypt(ciphertext1).decodeDouble();
      assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption1));

      EncryptedNumber ciphertext2 = ciphertext1.add(eps);
      double decryption2 = privateKey.decrypt(ciphertext2).decodeDouble();
      assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption2));

      EncryptedNumber ciphertext3 = ciphertext1.add(eps / 5.0d);
      double decryption3 = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption3));

      EncryptedNumber ciphertext4 = ciphertext3.add(eps * 4.0d / 5.0d);
      double decryption4 = privateKey.decrypt(ciphertext4).decodeDouble();
      assertNotEquals(onePlusEps, decryption4, 0.0d);
      assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption4));
    }

    @Test
    public void testMulZero() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(3.0);
      EncryptedNumber ciphertext2 = ciphertext1.multiply(0);
      assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    @Test
    public void testMulZeroRight() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(3.0);
      EncryptedNumber ciphertext2 = context.encode(0).multiply(ciphertext1);
      assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    public void testEncryptDecryptLong(long value) {
      try {
        EncryptedNumber ciphertext = context.encrypt(value);
        if(value < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
        }
        assertEquals(value, ciphertext.decrypt(privateKey).decodeLong());
      } catch (EncodeException e) {
      }
    }

    @Test
    public void testLongConstants() throws Exception {
      testEncryptDecryptLong(Long.MAX_VALUE);
      testEncryptDecryptLong(Long.MIN_VALUE);
    }

    @Test
    public void testLongRandom() throws Exception {
      for(int i = 0; i < 100; ++i) {
        testEncryptDecryptLong(random.nextLong());
      }
    }

    public void testEncryptDecryptDouble(double value) {
      try {
        EncryptedNumber ciphertext = context.encrypt(value);
        if(value < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
        }

        double tolerance = EPSILON;
        double result = ciphertext.decrypt(privateKey).decodeDouble();
        double absValue = Math.abs(value);
        if(absValue == 0.0 || absValue > 1.0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(value));
        }

        assertEquals(value, result, tolerance);
      } catch (EncodeException e) {
      }
    }

    @Test
    public void testDoubleConstants() throws Exception {
      testEncryptDecryptDouble(Double.MAX_VALUE);
      testEncryptDecryptDouble(Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
      testEncryptDecryptDouble(1.0);
      testEncryptDecryptDouble(Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
      testEncryptDecryptDouble(Double.MIN_NORMAL);
      testEncryptDecryptDouble(Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
      testEncryptDecryptDouble(Double.MIN_VALUE);
      testEncryptDecryptDouble(0.0);
      testEncryptDecryptDouble(-0.0);
      testEncryptDecryptDouble(-Double.MIN_VALUE);
      testEncryptDecryptDouble(-Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
      testEncryptDecryptDouble(-Double.MIN_NORMAL);
      testEncryptDecryptDouble(-Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
      testEncryptDecryptDouble(-1.0);
      testEncryptDecryptDouble(-Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
      testEncryptDecryptDouble(-Double.MAX_VALUE);
    }

    @Test
    public void testDoubleRandom() throws Exception {
      for(int i = 0; i < 100; ++i) {
        testEncryptDecryptDouble(randomFiniteDouble());
      }
    }

    public BigInteger generateRandomBigInteger(Random random, int bitLength) {
      BigInteger value = new BigInteger(bitLength, random);

      int i = random.nextInt(2);
      if(i % 2 == 0) {
        return value;
      } else {
        return value.negate();
      }
    }

    public void testEncryptDecryptBigInteger(BigInteger value) {
      try {
        EncryptedNumber ciphertext = context.encrypt(value);
        if (value.compareTo(BigInteger.ZERO) < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
        }
        assertEquals(value, ciphertext.decrypt(privateKey).decodeBigInteger());
      } catch (EncodeException e) {

      }
    }

    @Test
    public void testBigIntegerConstants() throws Exception {
      if(context.isSigned())
        testEncryptDecryptBigInteger(context.getMaxEncoded().negate());
      else
        testEncryptDecryptBigInteger(context.getMinEncoded());
      testEncryptDecryptBigInteger(LONG_MIN_VALUE);
      testEncryptDecryptBigInteger(LONG_MIN_VALUE.add(BigInteger.ONE));
      testEncryptDecryptBigInteger(BigInteger.TEN.negate());
      testEncryptDecryptBigInteger(BigInteger.ONE.negate());
      testEncryptDecryptBigInteger(BigInteger.ZERO);
      testEncryptDecryptBigInteger(BigInteger.ONE);
      testEncryptDecryptBigInteger(BigInteger.TEN);
      testEncryptDecryptBigInteger(LONG_MAX_VALUE.subtract(BigInteger.ONE));
      testEncryptDecryptBigInteger(LONG_MAX_VALUE);
      testEncryptDecryptBigInteger(context.getMaxEncoded());
    }

    @Test
    public void testBigIntegerRandom() throws Exception {
      int[] bitLengths = {16, 32, 64, 128, 256};

      for(int i = 0; i < bitLengths.length; ++i) {
        for(int j = 0; j < 20; ++j) {
          testEncryptDecryptBigInteger(generateRandomBigInteger(random, bitLengths[i]));
        }
      }
    }

    @Test
    public void testSubWithDifferentPrecisionFloat0() throws Exception {
      EncodedNumber number1 = context.encode(0.1, 1e-3);
      EncodedNumber number2 = context.encode(0.2, 1e-20);

      EncryptedNumber ciphertext1 = context.encrypt(number1);
      EncryptedNumber ciphertext2 = context.encrypt(number2);

      assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());

      if(context.isSigned()) {
        EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);
        assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-0.1, decryption, 1e-3);
      }
    }

    @Test
    public void testEncryptedNegativeLongWithEncryptedLong() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-15);
        EncryptedNumber ciphertext2 = context.encrypt(1);

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        long additionResult = privateKey.decrypt(ciphertext3).decodeLong();

        assertEquals(-14, additionResult);
      }
    }

    @Test
    public void testAddEncryptedLongs() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(15);
      EncryptedNumber ciphertext2 = context.encrypt(1);

      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

      long additionResult = privateKey.decrypt(ciphertext3).decodeLong();

      assertEquals(16, additionResult);
    }

    @Test
    public void testAddWithEncryptedNegativeLongWithEncryptedNegativeLong() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-15);
        EncryptedNumber ciphertext2 = context.encrypt(-1);

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        long additionResult = privateKey.decrypt(ciphertext3).decodeLong();

        assertEquals(-16, additionResult);
      }
    }

    @Test
    public void testSubtractEncryptedLongWithEncryptedLong() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(15);
      EncryptedNumber ciphertext2 = context.encrypt(1);

      EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);

      long decryption = privateKey.decrypt(ciphertext3).decodeLong();

      assertEquals(14, decryption);
    }

    @Test
    public void testAddEncryptedNegativeDoubleWithEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-15.0);
        EncryptedNumber ciphertext2 = context.encrypt(1.0);
        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-14.0, decryption, EPSILON);
      }
    }

    @Test
    public void testAddEncryptedDoubleWithEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-15.0);
        EncryptedNumber ciphertext2 = context.encrypt(1.0);
        EncryptedNumber ciphertext3 = ciphertext2.add(ciphertext1);

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-14.0, decryption, EPSILON);
      }
    }

    @Test
    public void testAddEncryptedDoubles() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(15.0);
      EncryptedNumber ciphertext2 = context.encrypt(1.0);
      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

      double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(16.0, decryption, EPSILON);
    }

    @Test
    public void testAddEncryptedNegativeDoubleWithEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-15.0);
        EncryptedNumber ciphertext2 = context.encrypt(-1.0);
        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-16.0, decryption, EPSILON);
      }
    }

    @Test
    public void testAddEncryptedDoubleWithEncryptedNegativeDouble2() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(1.3842);
        EncryptedNumber ciphertext2 = context.encrypt(-0.4);
        EncryptedNumber ciphertext3 = ciphertext2.add(ciphertext1);

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(0.9842, decryption, EPSILON);
      }
    }

    @Test
    public void testAddEncryptedDoublesDiffPrec() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(0.1, 1e-3));
      EncryptedNumber ciphertext2 = context.encrypt(context.encode(0.2, 1e-20));
      assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());

      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
      assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());

      double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(0.3, decryption, EPSILON);
    }

    @Test
    public void testSubtractEncryptedDoubleFromEncryptedDoubleDiffPrec() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(context.encode(0.1, 1e-3));
        EncryptedNumber ciphertext2 = context.encrypt(context.encode(0.2, 1e-20));
        assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());

        EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);
        assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-0.1, decryption, EPSILON);
      }
    }

    @Test
    public void testAddLongToEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.add(4);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testAddDoubleToEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.add(4.0);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testAddBigIntegerToEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.add(new BigInteger("4"));
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testAddDoubleWithEncryptedDouble() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(1.98);
      EncryptedNumber ciphertext2 = ciphertext1.add(4.3);
      assertEquals(6.28, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
    }

    @Test
    public void testAddNegativeDoubleWithEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(240.9);
        EncryptedNumber ciphertext2 = ciphertext1.add(-40.8);
        assertEquals(200.1, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
      }
    }

    @Test
    public void testAddLongWithEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(3.9);
        EncryptedNumber ciphertext2 = ciphertext1.add(-40);
        assertEquals(-36.1, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testSubtractLongFromEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testSubtractDoubleFromEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4.0);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testSubtractBigIntegerFromEncryptedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(new BigInteger("-4"));
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testSubtractEncryptedDoubleFromEncodedLong() throws Exception {
      // Right-operation: 4 - encrypt(1.98)
      EncryptedNumber ciphertext1 = context.encrypt(1.98);
      EncryptedNumber ciphertext2 = context.encode(4).subtract(ciphertext1);
      assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    @Test
    public void testSubtractEncryptedDoubleFromEncodedDouble() throws Exception {
      // Right-operation: 4 - encrypt(1.98)
      EncryptedNumber ciphertext1 = context.encrypt(1.98);
      EncryptedNumber ciphertext2 = context.encode(4.0).subtract(ciphertext1);
      assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    @Test
    public void testSubtractEncryptedDoubleFromEncodedBigInteger() throws Exception {
      // Right-operation: 4 - encrypt(1.98)
      EncryptedNumber ciphertext1 = context.encrypt(1.98);
      EncryptedNumber ciphertext2 = context.encode(new BigInteger("4")).subtract(ciphertext1);
      assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    @Test
    public void testSubtractNegativeDoubleWithEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4.3);
        assertEquals(6.28, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
      }
    }

    @Test
    public void testSubDoubleFromEncodedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = context.encode(4.3).subtract(ciphertext1);
        assertEquals(6.28, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
      }
    }

    @Test
    public void testSubtractDoubleFromEncryptedDouble() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(240.9);
      EncryptedNumber ciphertext2 = ciphertext1.subtract(40.8);
      assertEquals(200.1, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
    }

    @Test
    public void testSubtractLongFromEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(3.9);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(40);
        assertEquals(-36.1, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testMultiplyLongByEncryptedNumber() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(4);
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testMultiplyDoubleByEncryptedDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(4.0);
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testMultiplyBigIntegerByEncryptedNumber() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(new BigInteger("4"));
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testMultiplyEncryptedNegativeDoubleWithOne() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.3);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(1);
        double decryption = privateKey.decrypt(ciphertext2).decodeDouble();

        assertEquals(ciphertext1.getExponent(), ciphertext2.getExponent());
        assertEquals(-1.3, decryption, 0.0);
      }
    }

    @Test
    public void testMultiplyEncryptedDoubleWithTwo() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(2.3);
      EncodedNumber two = context.encode(2);
      EncryptedNumber ciphertext2 = ciphertext1.multiply(two);
      double decryption = privateKey.decrypt(ciphertext2).decodeDouble();

      assertEquals(ciphertext1.getExponent() + two.getExponent(), ciphertext2.getExponent());
      assertEquals(4.6, decryption, 0.0);
    }

    @Test
    public void testMultiplicationResultExponent() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(31.4);

        assertEquals(-3.14, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
        assertNotEquals(ciphertext2.getExponent(), ciphertext1.getExponent());

        int expOf314 = context.encode(-31.4).getExponent();

        assertEquals(ciphertext2.getExponent(), ciphertext1.getExponent() + expOf314);
      }
    }

    @Test
    public void testMultiplyEncodedDoubleWithEncryptedNumber() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(1.2345678e-12, 1e-14));
      EncodedNumber encoded1 = context.encode(1.38734864, 1e-2);
      EncryptedNumber ciphertext2 = ciphertext1.multiply(encoded1);
      assertEquals(1.71e-12, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
    }

    @Test
    public void testMultiplyEncryptedNegativeDoubleWithNegativeOne() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.3);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(-1);
        double decryption = privateKey.decrypt(ciphertext2).decodeDouble();

        assertEquals(ciphertext1.getExponent(), ciphertext2.getExponent());
        assertEquals(1.3, decryption, 0.0);
      }
    }

    @Test
    public void testMultiplyEncryptedDoubleWithNegativeTwo() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(2.3);
        EncodedNumber minusTwo = context.encode(-2);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(minusTwo);
        double decryption = privateKey.decrypt(ciphertext2).decodeDouble();

        assertEquals(ciphertext1.getExponent() + minusTwo.getExponent(), ciphertext2.getExponent());
        assertEquals(-4.6, decryption, 0.0);
      }
    }

    @Test
    public void testMultiplicationResultExponent2() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(-31.4);

        assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
        assertNotEquals(ciphertext2.getExponent(), ciphertext1.getExponent());

        int expOf314 = context.encode(-31.4).getExponent();

        assertEquals(ciphertext2.getExponent(), ciphertext1.getExponent() + expOf314);
      }
    }

    @Test
    public void testMultiplyEncodedNegativeDoubleWithEncryptedDouble() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(1.2345678e-12, 1e-14));
      EncodedNumber encoded1 = context.encode(1.38734864, 1e-2);
      EncryptedNumber ciphertext2 = ciphertext1.multiply(encoded1);
      assertEquals(-1.71e-12, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
    }

    @Test
    public void testDivideLongByEncryptedNumber() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.divide(4);
        assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testMultiplyRight() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(0.1);
      EncryptedNumber ciphertext2 = ciphertext1.multiply(31.4);
      EncryptedNumber ciphertext3 = (context.encode(31.4)).multiply(ciphertext1);

      assertEquals(privateKey.decrypt(ciphertext3).decodeDouble(), privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
    }

    @Test
    public void testDivideEncryptedNegativeDoubleByDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.divide(4.0);
        assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
      }
    }

    @Test
    public void testDivideEncryptedDoubleWithLong() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(6.28);
      EncryptedNumber ciphertext2 = ciphertext1.divide(2);
      assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);

      EncryptedNumber ciphertext3 = ciphertext1.divide(3.14);
      assertEquals(2.0, privateKey.decrypt(ciphertext3).decodeDouble(), 0.0);
    }

    @Test
    public void testAdditiveInverse() throws Exception {
      if(context.isSigned()) {
        double number = 1.98;
        EncryptedNumber ciphertext = context.encrypt(number);

        EncryptedNumber negativeCiphertext = ciphertext.additiveInverse();
        assertEquals(ciphertext.multiply(-1), negativeCiphertext);

        double decryptedNegativeNumber = negativeCiphertext.decrypt(privateKey).decodeDouble();
        assertEquals(-number, decryptedNegativeNumber, EPSILON);

        double number2 = -number;
        EncryptedNumber ciphertext2 = context.encrypt(number2);

        EncryptedNumber negativeCiphertext2 = ciphertext2.additiveInverse();
        assertEquals(ciphertext2.multiply(-1), negativeCiphertext2);

        double decryptedNegativeNumber2 = negativeCiphertext2.decrypt(privateKey).decodeDouble();
        assertEquals(number, decryptedNegativeNumber2, EPSILON);
      }
    }

    @Test
    public void testAddEncryptedDoubleWithEncodedDouble() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(0.1, 1e-3));
      EncodedNumber encoded1 = context.encode(0.2, 1e-20);
      assertNotEquals(ciphertext1.getExponent(), encoded1.getExponent());

      EncryptedNumber ciphertext3 = ciphertext1.add(encoded1);
      assertEquals(encoded1.getExponent(), ciphertext3.getExponent());

      double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(0.3, decryption, 1e-3);
    }

    @Test
    public void testMultiplyEncryptedNegativeDoubleWithEncodedNegativeDouble() throws Exception {
      if(context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
        EncodedNumber encoded1 = context.encode(-31.4);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(encoded1);

        assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
        assertNotEquals(ciphertext2.getExponent(), ciphertext1.getExponent());

        int expOf314 = context.encode(-31.4).getExponent();
        assertEquals(ciphertext2.getExponent(), ciphertext1.getExponent() + expOf314);
      }
    }

    @Test
    public void testEncryptIntPositiveOverflowAdd() throws Exception {
      if(!context.isFullPrecision()) {
        EncryptedNumber ciphertext1 = context.encrypt(
                context.getMaxSignificand());
        EncryptedNumber ciphertext2 = context.encrypt(BigInteger.ONE);

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        exception.expect(DecodeException.class);
        BigInteger result = privateKey.decrypt(ciphertext3).decodeBigInteger();
      }
    }

    @Test
    public void testEncryptIntNegativeOverflowAdd() throws Exception {
      if(!context.isFullPrecision() && context.isSigned()) {
        EncryptedNumber ciphertext1 = context.encrypt(
                context.getMinSignificand());
        EncryptedNumber ciphertext2 = context.encrypt(BigInteger.ONE.negate());

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        exception.expect(DecodeException.class);
        BigInteger result = privateKey.decrypt(ciphertext3).decodeBigInteger();
      }
    }

    @Test
    public void testAddWithEncryptedIntAndEncodedNumberDiffExp0() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(15);
      EncodedNumber encoded2 = context.encode(1.0, 50);
      assert encoded2.getExponent() > 200;
      assert ciphertext1.getExponent() > 200;

      EncodedNumber encoded3 = context.encode(1.0, 200);
      EncryptedNumber ciphertext3 = ciphertext1.add(encoded3);
      double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(16, (long) decryption);
    }

    @Test
    public void testAddWithEncryptedIntAndEncodedNumberDiffExp1() throws Exception {
      EncodedNumber encoded1 = context.encode(1.0, 10);
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(15.0, 100));
      assert encoded1.getExponent() == 10;
      assert ciphertext1.getExponent() == 100;

      EncryptedNumber ciphertext2 = ciphertext1.add(encoded1);
      assertEquals(16.0, privateKey.decrypt(ciphertext2).decodeDouble(), EPSILON);
    }

    @Test
    public void testAddWithDifferentPrecisionFloat4() throws Exception {
      EncodedNumber number1 = context.encode(0.1, 1e-3);
      EncodedNumber number2 = context.encode(0.2, 1e-20);

      EncryptedNumber ciphertext1 = context.encrypt(number1);
      EncryptedNumber ciphertext2 = context.encrypt(number2);

      assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());
      int oldExponent = ciphertext1.getExponent();

      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
      assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());
      assertEquals(oldExponent, ciphertext1.getExponent());

      double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
      assertEquals(0.3, decryption, 1e-3);
    }

    @Test
    public void testDecreaseExponentTo() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(context.encode(1.01, Math.pow(1.0, -8)));
      assert -30 < ciphertext1.getExponent();
      EncryptedNumber ciphertext2 = ciphertext1.decreaseExponentTo(-30);

      assert -30 < ciphertext1.getExponent();
      assertEquals(-30, ciphertext2.getExponent());
      assertEquals(1.01, privateKey.decrypt(ciphertext2).decodeDouble(), Math.pow(1.0, -8));
    }
  }

  public static class EncryptedNumberTest {
    private static PaillierPrivateKey privateKey;
    private static PaillierContext context;

    private static PaillierContext partialContext;

    private static PaillierPrivateKey otherPrivateKey;
    private static PaillierContext otherContext;

    private static BigInteger plaintextList[];
    private static EncryptedNumber encryptionList[];

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
      context = SIGNED_FULL_PRECISION.context();
      privateKey = SIGNED_FULL_PRECISION.privateKey();

      partialContext = SIGNED_PARTIAL_PRECISION.context();

      otherPrivateKey = PaillierPrivateKey.create(DEFAULT_KEY_SIZE);
      otherContext = createSignedFullPrecision(otherPrivateKey).context();

      plaintextList = new BigInteger[]{new BigInteger("123456789"), new BigInteger(
              "314159265359"), new BigInteger("271828182846"), new BigInteger(
              "-987654321"), new BigInteger("-161803398874"), new BigInteger(
              "1414213562373095")};

      encryptionList = new EncryptedNumber[plaintextList.length];

      for(int i = 0; i < plaintextList.length; i++) {
        encryptionList[i] = context.encrypt(plaintextList[i]);
      }
    }

    @Test
    public void testConstructor() throws Exception {
      EncryptedNumber encryptedNumber = null;

      try {
        encryptedNumber = new EncryptedNumber(null, BigInteger.ONE, 0);
        fail("Successfully created an encrypted number with null context");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encryptedNumber);

      try {
        encryptedNumber = new EncryptedNumber(context, null, 0);
        fail("Successfully created an encrypted number with null ciphertext");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encryptedNumber);

      try {
        encryptedNumber = new EncryptedNumber(context, BigInteger.ONE.negate(), 0);
        fail("Successfully created an encrypted number with negative ciphertext");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encryptedNumber);

      try {
        encryptedNumber = new EncryptedNumber(context,
                context.getPublicKey().getModulusSquared().add(
                        BigInteger.ONE), 0);
        fail("Successfully created an encrypted number with ciphertext greater than modulus squared");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encryptedNumber);
    }

    @Test
    public void testCantEncryptDecryptIntWithDifferentKey() throws Exception {
      long data = 1564;
      EncryptedNumber ciphertext = context.encrypt(data);

      exception.expect(PaillierKeyMismatchException.class);
      otherPrivateKey.decrypt(ciphertext).decodeLong();
    }

    @Test
    public void testCantEncryptDecryptIntWithDifferentSizeKey() throws Exception {
      PaillierPrivateKey aPrivateKey = PaillierPrivateKey.create(128);
      PaillierPublicKey aPublicKey = aPrivateKey.getPublicKey();
      PaillierContext aContext = aPublicKey.createSignedContext();

      long data = 1564;
      EncryptedNumber ciphertext = aContext.encrypt(data);

      exception.expect(PaillierKeyMismatchException.class);
      privateKey.decrypt(ciphertext).decodeLong();
    }

    @Test
    public void testCantAddWithDifferentKey() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(-15);
      EncryptedNumber ciphertext2 = otherContext.encrypt(1);

      exception.expect(PaillierContextMismatchException.class);
      EncryptedNumber result = ciphertext1.add(ciphertext2);
    }

    @Test
    public void testCantAddEncodedWithDifferentKey() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(-15);
      EncodedNumber ciphertext2 = new EncodedNumber(otherContext, BigInteger.ONE,
              ciphertext1.getExponent());

      exception.expect(PaillierContextMismatchException.class);
      EncryptedNumber result = ciphertext1.add(ciphertext2);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt0() throws Exception {
      EncryptedNumber ciphertext = (encryptionList[0].add(encryptionList[1])).add(
              encryptionList[2]);
      BigInteger decryption = privateKey.decrypt(ciphertext).decodeBigInteger();

      BigInteger expectedResult = (plaintextList[0].add(plaintextList[1])).add(
              plaintextList[2]);
      assertEquals(expectedResult, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt1() throws Exception {
      EncryptedNumber ciphertext = (encryptionList[3].add(encryptionList[4])).add(
              encryptionList[5]);
      BigInteger decryption = privateKey.decrypt(ciphertext).decodeBigInteger();

      BigInteger expectedResult = (plaintextList[3].add(plaintextList[4])).add(
              plaintextList[5]);
      assertEquals(expectedResult, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt2() throws Exception {
      EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(
              encryptionList[2]);
      EncryptedNumber ciphertext2 = encryptionList[3].add(encryptionList[4]);
      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
      BigInteger decryption = privateKey.decrypt(ciphertext3).decodeBigInteger();

      BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(
              plaintextList[2]);
      BigInteger expectedResult2 = plaintextList[3].add(plaintextList[4]);
      BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

      assertEquals(expectedResult3, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt3() throws Exception {
      EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(
              encryptionList[2]);
      EncryptedNumber ciphertext2 = (encryptionList[3].add(encryptionList[4])).add(
              encryptionList[5]);
      EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
      BigInteger decryption = privateKey.decrypt(ciphertext3).decodeBigInteger();

      BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(
              plaintextList[2]);
      BigInteger expectedResult2 = (plaintextList[3].add(plaintextList[4])).add(
              plaintextList[5]);
      BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

      assertEquals(expectedResult3, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptIntLimits() throws Exception {
      BigInteger sum3Pos2Neg1 = (plaintextList[0].add(plaintextList[1])).add(
              plaintextList[2]);
      BigInteger sum3Pos2Neg2 = plaintextList[3].add(plaintextList[4]);
      BigInteger sum3Pos2Neg3 = sum3Pos2Neg1.add(sum3Pos2Neg2);

      BigInteger sum3Pos3Neg1 = (plaintextList[0].add(plaintextList[1])).add(
              plaintextList[2]);
      BigInteger sum3Pos3Neg2 = (plaintextList[3].add(plaintextList[4])).add(
              plaintextList[5]);
      BigInteger sum3Pos3Neg3 = sum3Pos3Neg1.add(sum3Pos3Neg2);

      EncryptedNumber ciphertextSum3Pos2Neg1 = (encryptionList[0].add(
              encryptionList[1])).add(encryptionList[2]);
      EncryptedNumber ciphertextSum3Pos2Neg2 = encryptionList[3].add(encryptionList[4]);
      EncryptedNumber ciphertextSum3Pos2Neg3 = ciphertextSum3Pos2Neg1.add(
              ciphertextSum3Pos2Neg2);


      EncryptedNumber ciphertextSum3Pos3Neg1 = (encryptionList[0].add(
              encryptionList[1])).add(encryptionList[2]);
      EncryptedNumber ciphertextSum3Pos3Neg2 = (encryptionList[3].add(
              encryptionList[4])).add(encryptionList[5]);
      EncryptedNumber ciphertextSum3Pos3Neg3 = ciphertextSum3Pos3Neg1.add(
              ciphertextSum3Pos3Neg2);

//        Add many positive and negative numbers to reach maxInt.
      EncryptedNumber ciphertext1 = context.encrypt(
              context.getMaxSignificand().subtract(sum3Pos2Neg3));
      EncryptedNumber ciphertext2 = ciphertextSum3Pos2Neg3.add(ciphertext1);
      BigInteger decryption = privateKey.decrypt(ciphertext2).decodeBigInteger();
      assertEquals(context.getMaxSignificand(), decryption);

//        Add many positive and negative numbers to reach -maxInt.
      EncryptedNumber ciphertext3 = context.encrypt(
              (context.getMinSignificand()).add(sum3Pos3Neg3));
      EncryptedNumber ciphertext4 = ciphertext3.subtract(ciphertextSum3Pos3Neg3);
      BigInteger decryption2 = privateKey.decrypt(
              ciphertext4).decodeBigInteger();
      assertEquals(context.getMinSignificand(), decryption2);
    }

    @Test
    public void testCalculateCiphertext() throws Exception {
      EncryptedNumber encryptedNumber = context.encrypt(3.14);

      BigInteger unsafeCiphertext = encryptedNumber.ciphertext;
      BigInteger safeCiphertext = encryptedNumber.calculateCiphertext();

      assertNotNull(safeCiphertext);
      assertNotEquals(unsafeCiphertext, safeCiphertext);
    }

    @Test
    public void testCiphertextObfuscation() throws Exception {
      EncryptedNumber encryptedNumber = context.encrypt(3.14);
      BigInteger ciphertext = encryptedNumber.ciphertext;
      assertEquals(encryptedNumber.isSafe, false);

      EncryptedNumber obfuscatedEncryptedNumber = encryptedNumber.obfuscate();
      BigInteger obfuscatedCiphertext = obfuscatedEncryptedNumber.calculateCiphertext();

      assertNotNull(obfuscatedEncryptedNumber);
      assertEquals(obfuscatedEncryptedNumber.isSafe, true);
      assertNotEquals(encryptedNumber, obfuscatedEncryptedNumber);
      assertNotEquals(ciphertext, obfuscatedCiphertext);
    }

    @Test
    public void testNotObfuscated() throws Exception {
      EncryptedNumber encryptedNumber = context.encrypt(context.encode(3.14, 103));
      assertEquals(encryptedNumber.isSafe, false);
      BigInteger ciphertext1 = encryptedNumber.ciphertext;

      EncryptedNumber encryptedNumber2 = encryptedNumber.obfuscate();
      BigInteger ciphertext2 = encryptedNumber2.ciphertext;
      assertEquals(encryptedNumber2.isSafe, true);

      EncryptedNumber encryptedNumber3 = encryptedNumber2.obfuscate();
      BigInteger ciphertext3 = encryptedNumber3.ciphertext;
      assertEquals(encryptedNumber3.isSafe, true);

      BigInteger ciphertext4 = encryptedNumber2.calculateCiphertext();

      assertNotEquals(ciphertext1, ciphertext2);
      assertNotEquals(ciphertext2, ciphertext3);
      assertEquals(ciphertext2, ciphertext4);
      assertNotEquals(ciphertext3, ciphertext4);

      double decryptedNumber = privateKey.decrypt(encryptedNumber).decodeDouble();
      assertEquals(3.14, decryptedNumber, 0.0);
    }

    @Test
    public void testAddObfuscated() throws Exception {
      EncryptedNumber encryptedNumber1 = context.encrypt(94.5);
      EncryptedNumber encryptedNumber2 = context.encrypt(107.3);
      assertEquals(encryptedNumber1.isSafe, false);
      assertEquals(encryptedNumber2.isSafe, false);
      EncryptedNumber encryptedNumber3 = encryptedNumber1.add(encryptedNumber2);
      assertEquals(encryptedNumber3.isSafe, false);
      EncryptedNumber encryptedNumber4 = encryptedNumber3.obfuscate();
      assertEquals(encryptedNumber4.isSafe, true);
    }

    @Test
    public void testCheckSameContextEncryptedNumber() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(1.0);
      EncryptedNumber ciphertext2 = context.encrypt(2.0);
      EncryptedNumber ciphertext3 = otherContext.encrypt(2.0);

      EncryptedNumber check = ciphertext1.checkSameContext(ciphertext2);

      try {
        check = ciphertext1.checkSameContext(ciphertext3);
        fail("ciphertext1 and ciphertext3 have different context");
      } catch (PaillierContextMismatchException e) {
      }
    }

    @Test
    public void testCheckSameContextEncodedNumber() throws Exception {
      EncryptedNumber ciphertext1 = context.encrypt(1.0);
      EncodedNumber encodedNumber2 = context.encode(2.0);
      EncodedNumber encodedNumber3 = otherContext.encode(2.0);

      EncodedNumber check = ciphertext1.checkSameContext(encodedNumber2);

      try {
        check = ciphertext1.checkSameContext(encodedNumber3);
        fail("encodedNumber1 and encodedNumber3 have different context");
      } catch (PaillierContextMismatchException e) {
      }
    }

    @Test
    public void testEquals() throws Exception {
      EncryptedNumber encrypted = context.encrypt(17);
      EncryptedNumber partialEncrypted = partialContext.encrypt(17);

      assertTrue(encrypted.equals(encrypted)); // Compare to itself
      assertFalse(encrypted.equals(context)); // Compare to other object
      assertFalse(encrypted.equals(null)); // Compare to null

      EncryptedNumber encrypted2 = null;
      assertFalse(encrypted.equals(encrypted2)); // Compare to uninitialised encrypted number

      encrypted2 = context.encrypt(3.14);
      assertFalse(encrypted.equals(encrypted2)); // Compare to an encrypted number with different value

      assertFalse(encrypted.equals(partialEncrypted)); // Compare to an encrypted number with different context
    }

    @Test
    public void testDecreaseInvalidExponent() throws Exception {
      EncryptedNumber ciphertext = context.encrypt(context.encode(1.01, 1e-8));
      assert ciphertext.getExponent() < 20;

      exception.expect(IllegalArgumentException.class);
      ciphertext.decreaseExponentTo(20);
    }
    
    @Test
    public void testGetThisThingInSafe() {
        EncryptedNumber unSafeEN = context.encrypt(context.encode(1.01, 1e-8));
        assertFalse(unSafeEN.isSafe);
        EncryptedNumber safeEN = unSafeEN.getSafeEncryptedNumber();
        assertTrue(safeEN.isSafe);
        assertNotEquals(unSafeEN.ciphertext, safeEN.ciphertext);
        assertTrue(safeEN.getSafeEncryptedNumber().isSafe);
        assertEquals(safeEN.ciphertext, safeEN.getSafeEncryptedNumber().ciphertext);
    }
  }

}