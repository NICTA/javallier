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

import com.n1analytics.paillier.util.BigIntegerUtil;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

import static com.n1analytics.paillier.PaillierContextTest.testEncodable;
import static com.n1analytics.paillier.PaillierContextTest.testUnencodable;
import static com.n1analytics.paillier.TestConfiguration.*;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.*;

@RunWith(Enclosed.class)
public class PaillierEncodedNumberTest {

  @RunWith(Parameterized.class)
  public static class EncodedNumberParamTest {
    public static final Random random = new Random();

    private TestConfiguration conf;
    private PaillierContext context;
    private PaillierPrivateKey privateKey;

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

    public EncodedNumberParamTest(TestConfiguration conf) {
      this.conf = conf;
      context = conf.context();
      privateKey = conf.privateKey();
    }

    public void testLong(long value) {
      BigInteger valueBig = BigInteger.valueOf(value);
      double valueDouble = (double) value;

      try {
        EncodedNumber encoded = context.encode(value);
        if(value < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encoded negative integer with unsigned encoding");
        }
        assertEquals(context, encoded.getContext());
        BigInteger expected = valueBig;
        
        if(!expected.equals(BigInteger.ZERO)) {
          while (expected.mod(BigInteger.valueOf(context.getBase())).compareTo(BigInteger.ZERO) == 0) {
            expected = expected.divide(BigInteger.valueOf(context.getBase()));
          }
        }
        if(value < 0) {
          expected = context.getPublicKey().getModulus().add(expected);
        }
        assertEquals(expected, encoded.getValue());
        assertEquals(value, encoded.decodeLong());
        assertEquals(valueBig, encoded.decodeBigInteger());

        assertEquals(valueDouble, encoded.decodeDouble(), EPSILON);
      } catch (EncodeException e) {
        if(value >= 0 || context.isSigned()) {
          throw e;
        }
      }
    }

    @Test
    public void testLongSmall() {
      for(long i = -1024; i <= 1024; ++i) {
        testLong(i);
      }
    }

    @Test
    public void testLongLarge() {
      testLong(Long.MAX_VALUE);
      testLong(Long.MIN_VALUE);
    }

    @Test
    public void testLongRandom() {
      for(int i = 0; i < 100000; ++i) {
        testLong(random.nextLong());
      }
    }

    public void testDouble(double value) {
      try {
        EncodedNumber encoded = context.encode(value);
        if(value < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encoded negative double with unsigned encoding");
        }
        double tolerance = EPSILON;
        double decodedResult = encoded.decodeDouble();
        double absValue = Math.abs(value);
        if(absValue == 0.0 || absValue > 1.0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(value));
        }
        assertEquals(value, decodedResult, tolerance);
      } catch (EncodeException e) {
      }
    }
    
    @Test
    public void testZeroDouble() {
      EncodedNumber zero = context.encode(0.0);
      assertTrue(zero.exponent==0);
    }

    @Test
    public void testDoubleConstants() {
      testDouble(Double.MAX_VALUE);
      testDouble(Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
      testDouble(1.0);
      testDouble(Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
      testDouble(Double.MIN_NORMAL);
      testDouble(Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
      testDouble(Double.MIN_VALUE);
      testDouble(0.0);
      testDouble(-0.0);
      testDouble(-Double.MIN_VALUE);
      testDouble(-Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
      testDouble(-Double.MIN_NORMAL);
      testDouble(-Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
      testDouble(-1.0);
      testDouble(-Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
      testDouble(-Double.MAX_VALUE);
    }

    @Test
    public void testDoubleRandom() {
      for(int i = 0; i < 100000; ++i) {
        testDouble(randomFiniteDouble());
      }
    }

    @Test
    public void testDoubleNonFinite() {
      // Test constants
      double[] nonFinite = {Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, Double.NaN};
      for(double value : nonFinite) {
        try {
          context.encode(value);
          fail("ERROR: Successfully encoded non-finite double");
        } catch (EncodeException e) {
        }
      }

      // Test random NaNs
      for(int i = 0; i < 1000; ++i) {
        try {
          context.encode(randomNaNDouble());
          fail("ERROR: Successfully encoded non-finite double");
        } catch (EncodeException e) {
        }
      }
    }
    
    public void testBigDecimal(BigDecimal value) {
      try {
        EncodedNumber encoded = context.encode(value);
        if(value.compareTo(BigDecimal.ZERO) < 0 && context.isUnsigned()) {
          fail("ERROR: Successfully encoded negative BigDecimal with unsigned encoding");
        }
        BigDecimal decodedResult = encoded.decodeBigDecimal();
        BigDecimal EPSILON = new BigDecimal(BigInteger.ONE, StandardEncodingScheme.BIG_DECIMAL_ENCODING_PRECISION);
        BigDecimal relError = value.compareTo(BigDecimal.ZERO) == 0 ? decodedResult : value.subtract(decodedResult).divide(value, new MathContext(StandardEncodingScheme.BIG_DECIMAL_ENCODING_PRECISION + 1)).abs();
        assertTrue(relError.compareTo(EPSILON) <= 0);
      } catch (EncodeException e) {
      }
    }
    
    @Test
    public void testBigDecimalConstants() {
      testBigDecimal(BigDecimal.ZERO);
      testBigDecimal(BigDecimal.ONE);
      testBigDecimal(BigDecimal.ONE.negate());
      testBigDecimal(new BigDecimal(context.getMaxSignificand()));
      testBigDecimal(new BigDecimal(context.getMinSignificand()));
    }
    
    @Test
    public void testBigDecimalRandom() {
      int numBits = context.getPrecision()/2;
      for(int i = 0; i < 100000; ++i) {        
        testBigDecimal(new BigDecimal(new BigInteger(numBits, random), random.nextInt(60)-30));
      }
    }

    public void testRange(TestConfiguration configuration) {
      BigInteger ZERO = BigInteger.ZERO;
      BigInteger ONE = BigInteger.ONE;
      BigInteger modulus = configuration.modulus();
      int exponent = 0;
      int precision = configuration.precision();
      if(configuration.unsignedFullPrecision()) {
        BigInteger max = modulus.subtract(ONE);

        assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
        assertEquals(ZERO, context.getMinSignificand());

        long maxLong = max.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        long actualMaxLong = context.getMaxSignificand().compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        assertEquals(maxLong, actualMaxLong);
        assertEquals(ZERO.longValue(), context.getMinSignificand().longValue());

        assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                EPSILON * context.getMaxSignificand().doubleValue());
        assertEquals(ZERO.doubleValue(), context.getMinSignificand().doubleValue(), 0.0);

        // TODO Issue #15: encode/decode

      } else if(configuration.unsignedPartialPrecision()) {
        BigInteger max = ONE.shiftLeft(precision).subtract(ONE);

        assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
        assertEquals(ZERO, context.getMinSignificand());

        long maxLong = max.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        long actualMaxLong = context.getMaxSignificand().compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        assertEquals(maxLong, actualMaxLong);
        assertEquals(ZERO.longValue(), context.getMinSignificand().longValue());

        assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                EPSILON * context.getMaxSignificand().doubleValue());
        assertEquals(ZERO.doubleValue(), context.getMinSignificand().doubleValue(), 0.0);
      } else if(configuration.signedFullPrecision()) {
        BigInteger max = context.getPublicKey().getModulus().shiftRight(1);
        BigInteger min = max.negate();

        assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
        assertEquals(min.shiftLeft(exponent), context.getMinSignificand());

        long maxLong = max.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        long actualMaxLong = context.getMaxSignificand().compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        assertEquals(maxLong, actualMaxLong);
        long minLong = min.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
                exponent).longValue();
        long actualMinLong = context.getMinSignificand().compareTo(
                BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
                exponent).longValue();
        assertEquals(minLong, actualMinLong);

        assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                EPSILON * context.getMaxSignificand().doubleValue());
        assertEquals(min.doubleValue(), context.getMinSignificand().doubleValue(),
                EPSILON * Math.abs(context.getMinSignificand().doubleValue()));
      } else if(configuration.signedPartialPrecision()) {
        BigInteger max = ONE.shiftLeft(precision - 1).subtract(ONE);
        BigInteger min = max.negate();

        assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
        assertEquals(min.shiftLeft(exponent), context.getMinSignificand());

        long maxLong = max.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        long actualMaxLong = context.getMaxSignificand().compareTo(
                BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
                exponent).longValue();
        assertEquals(maxLong, actualMaxLong);
        long minLong = min.shiftLeft(exponent).compareTo(
                BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
                exponent).longValue();
        long actualMinLong = context.getMinSignificand().compareTo(
                BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
                exponent).longValue();
        assertEquals(minLong, actualMinLong);

        assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                EPSILON * context.getMaxSignificand().doubleValue());
        assertEquals(min.doubleValue(), context.getMinSignificand().doubleValue(),
                EPSILON * Math.abs(context.getMinSignificand().doubleValue()));
      } else {
        fail("Invalid defConfig!");
      }
    }

    @Test
    public void testRange() {
      testRange(conf);
    }
    
    @Test
    public void testSignum() throws Exception {
      BigInteger[] testNumbers = new BigInteger[] { BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.negate(),
          conf.maxSignificand(), conf.minSignificand() };
      for (BigInteger n : testNumbers) {
        try {
          EncodedNumber en = conf.context().encode(n);
          if (en.isValid()) {
            assertEquals(en.signum(), n.signum());
          }
        } catch (Exception e) {
          if (!e.getClass().equals(EncodeException.class)) {
            fail("unexpected Exception");
          }
        }
      }
    }

    @Test
    public void testMaxEncodableNumber() throws Exception {
      EncodedNumber maxNumber = context.encode(context.getMaxSignificand());
      testEncodable(context, maxNumber);
    }

    @Test
    public void testMinEncodableNumber() throws Exception {
      EncodedNumber minNumber = context.encode(context.getMinSignificand());
      testEncodable(context, minNumber);
    }

    @Test
    public void testInvalidLargeMaxNumber() throws Exception {
      BigInteger humongous = context.getMaxSignificand().nextProbablePrime(); //so base won't divide significant
      testUnencodable(context, humongous);
    }

    @Test
    public void testInvalidLargeMinNumber() throws Exception {
      BigInteger negHumongous = context.getMinSignificand().subtract(BigInteger.ONE);
      while(!negHumongous.isProbablePrime(20)){
        negHumongous = negHumongous.subtract(BigInteger.ONE);
      }
      testUnencodable(context, negHumongous);
    }

    public void testUndecodable(EncodedNumber encodedNumber) throws Exception {
      try {
        double decodedNumber = encodedNumber.decodeDouble();
        fail("Error: successfully decode invalid number.");
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }

    // NOTE: decodeException only applies to partial precision
    @Test
    public void testDecodeInvalidPositiveNumbers() throws Exception {
      if(conf.signedPartialPrecision()) {
        EncodedNumber encodedNumber = new EncodedNumber(context, context.getMaxEncoded().add(BigInteger.ONE), 0);
        testUndecodable(encodedNumber);
      }
    }

    @Test
    public void testDecodeInvalidNegativeNumbers() throws Exception {
      if(conf.signedPartialPrecision()) {
        EncodedNumber encodedNumber = new EncodedNumber(context, context.getMinEncoded().subtract(BigInteger.ONE), 0);
        testUndecodable(encodedNumber);
      }
    }

    @Test
    public void testEncrypt() throws Exception {
      EncodedNumber encodedNumber = context.encode(1.0);
      EncryptedNumber encryptedNumber = encodedNumber.encrypt();

      EncryptedNumber contextEncryptedNumber = context.encrypt(1.0);

      assertTrue(encryptedNumber.equals(contextEncryptedNumber));
    }

    @Test
    public void testAddLongToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(2);
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testAddDoubleToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(2.0);
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testAddBigIntegerToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(new BigInteger("2"));
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testSubtractLongToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(2);
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testSubtractDoubleToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(2.0);
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testSubtractBigIntegerToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(new BigInteger("2"));
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testMultiplyLongToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(2);
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testMultiplyDoubleToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(2.0);
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testMultiplyBigIntegerToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(new BigInteger("2"));
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testDivideLongToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.divide(2);
      assertEquals(0.85, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testDivideDoubleToEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = context.encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.divide(2.0);
      assertEquals(0.85, encodedNumber2.decodeDouble(), EPSILON);
    }

    @Test
    public void testPositiveEncodedDecreaseExponentTo() throws Exception {
      EncodedNumber number1 = context.encode(3.14);
      int originalExp = number1.getExponent();
      int newExp = originalExp - 20;
      EncodedNumber number2 = number1.decreaseExponentTo(newExp);

      if(originalExp < number2.getExponent()) {
        fail("Fail to decrease the encoded number's exponent");
      }
      assertEquals(newExp, number2.getExponent());
      double decodedNumber = number2.decodeDouble();
      assertEquals(3.14, decodedNumber, EPSILON);
    }

    @Test
    public void testNegativeEncodedDecreaseExponentTo() throws Exception {
      if(conf.signed()) {
        EncodedNumber number1 = context.encode(-3.14);
        int originalExp = number1.getExponent();
        int newExp = originalExp - 20;
        EncodedNumber number2 = number1.decreaseExponentTo(newExp);

        if(originalExp < number2.getExponent()) {
          fail("Fail to decrease the encoded number's exponent");
        }
        assertEquals(newExp, number2.getExponent());
        double decodedNumber = number2.decodeDouble();
        assertEquals(-3.14, decodedNumber, EPSILON);
      }
    }

    @Test
    public void testManualPrecisionPositiveDouble() throws Exception {
      double originalNumber = 3.171234e-7;
      double precision = 1e-8;

      EncodedNumber number = context.encode(originalNumber, precision);
      double decodedNumber = number.decodeDouble();
      if(decodedNumber < originalNumber - precision || decodedNumber > originalNumber + precision) {
        fail("decodedNumber: " + decodedNumber + " is not in the correct range.");
      }

      EncodedNumber number2 = conf.context().encode(decodedNumber + 0.500001 * precision, precision);
      double decodedNumber2 = number2.decodeDouble();
      if(decodedNumber == decodedNumber2)
        fail("decodedNumber: " + decodedNumber + " should not be the same as decodedNumber2: " + decodedNumber2);

      if(decodedNumber2 < originalNumber - precision / 2 || decodedNumber2 > originalNumber + precision * 1.5001)
        fail("decodedNumber2: " + decodedNumber2 + "is not in the correct range.");

      double value = decodedNumber + precision / 16;
      EncodedNumber number3 = context.encode(value, precision);
      double decodedNumber3 = number3.decodeDouble();
      assertEquals(decodedNumber, decodedNumber3, EPSILON);
    }

    @Test
    public void testManualPrecisionNegativeDouble() throws Exception {
      if(conf.signed()) {
        double originalNumber = -3.171234e-7;
        double precision = 1e-8;

        EncodedNumber number = context.encode(originalNumber, precision);
        double decodedNumber = number.decodeDouble();
        if(decodedNumber < originalNumber - precision || decodedNumber > originalNumber + precision) {
          fail("decodedNumber: " + decodedNumber + " is not in the correct range.");
        }

        EncodedNumber number2 = context.encode(decodedNumber + 0.500001 * precision, precision);
        double decodedNumber2 = number2.decodeDouble();
        if(decodedNumber == decodedNumber2)
          fail("decodedNumber: " + decodedNumber + " should not be the same as decodedNumber2: " + decodedNumber2);

        if(decodedNumber2 < originalNumber - precision / 2 || decodedNumber2 > originalNumber + precision * 1.5001)
          fail("decodedNumber2: " + decodedNumber2 + "is not in the correct range.");

        double value = decodedNumber + precision / 16;
        EncodedNumber number3 = context.encode(value, precision);
        double decodedNumber3 = number3.decodeDouble();
        assertEquals(decodedNumber, decodedNumber3, EPSILON);
      }
    }

    @Test
    public void testEncodedDecreaseExponentTo0() throws Exception {
      EncodedNumber number1 = context.encode(1.01, Math.pow(1.0, -8));
      assertTrue(-30 < number1.getExponent());
      EncodedNumber number2 = number1.decreaseExponentTo(-30);

      if(number1.getExponent() < -30){
        fail("-30 < number1.getExponent()");
      }
      assertEquals(-30, number2.getExponent());
      double decodedNumber = number2.decodeDouble();
      assertEquals(1.01, decodedNumber, Math.pow(1.0, -8));
    }

    @Test
    public void testEncodedDecreaseExponentTo1() throws Exception {
      if(conf.signed()) {
        EncodedNumber number1 = context.encode(-1.01, Math.pow(1.0, -8));
        assertTrue(-30 < number1.getExponent());
        EncodedNumber number2 = number1.decreaseExponentTo(-30);

        if(number1.getExponent() < -30){
          fail("-30 < number1.getExponent()");
        }
        assertEquals(-30, number2.getExponent());
        double decodedNumber = number2.decodeDouble();
        assertEquals(-1.01, decodedNumber, Math.pow(1.0, -8));
      }
    }
  }

  public static class EncodedNumberTest {
    private static final PaillierContext defaultSignedContext = SIGNED_FULL_PRECISION.context();
    private static final PaillierContext defaultUnsignedContext = UNSIGNED_FULL_PRECISION.context();
    private static final PaillierContext defaultPartialSignedContext = SIGNED_PARTIAL_PRECISION.context();

    @Test
    public void testConstructor() throws Exception {
      EncodedNumber encodedNumber = null;

      try {
        encodedNumber = new EncodedNumber(null, BigInteger.ONE, 0);
        fail("Successfully create an encoded number with null context");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encodedNumber);

      try {
        encodedNumber = new EncodedNumber(defaultSignedContext, null, 0);
        fail("Successfully create an encoded number with null value");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encodedNumber);

      try {
        encodedNumber = new EncodedNumber(defaultSignedContext, BigInteger.ONE.negate(), 0);
        fail("Successfully create an encoded number with negative value");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encodedNumber);

      try {
        encodedNumber = new EncodedNumber(defaultSignedContext,
                defaultSignedContext.getPublicKey().getModulus(), 0);
        fail("Successfully create an encoded number with value equal to modulus");
      } catch (IllegalArgumentException e) {
      }
      assertNull(encodedNumber);

      encodedNumber = new EncodedNumber(defaultSignedContext, BigInteger.ONE, 0);
      assertNotNull(encodedNumber);
      assertEquals(BigInteger.ONE, encodedNumber.getValue());
      assertEquals(0, encodedNumber.getExponent());
    }

    @Test
    public void testCheckSameContextEncryptedNumber() throws Exception {
      EncodedNumber encodedNumber1 = defaultSignedContext.encode(1.0);
      EncryptedNumber ciphertext2 = defaultSignedContext.encrypt(2.0);
      EncryptedNumber ciphertext3 = defaultPartialSignedContext.encrypt(2.0);

      EncryptedNumber check = encodedNumber1.checkSameContext(ciphertext2);
      try {
        check = encodedNumber1.checkSameContext(ciphertext3);
        fail("ciphertext1 and ciphertext3 have different context");
      } catch (PaillierContextMismatchException e) {
      }
    }

    @Test
    public void testCheckSameContextEncodedNumber() throws Exception {
      EncodedNumber encodedNumber1 = defaultSignedContext.encode(1.0);
      EncodedNumber encodedNumber2 = defaultSignedContext.encode(2.0);
      EncodedNumber encodedNumber3 = defaultUnsignedContext.encode(2.0);

      EncodedNumber check = encodedNumber1.checkSameContext(encodedNumber2);
      try {
        check = encodedNumber1.checkSameContext(encodedNumber3);
        fail("encodedNumber1 and encodedNumber3 have different context");
      } catch (PaillierContextMismatchException e) {
      }
    }

    @Test
    public void testIsEncodedNumberValid() throws Exception {
      EncodedNumber encodedNumber1 = new EncodedNumber(defaultPartialSignedContext,
              defaultPartialSignedContext.getMaxEncoded(), 0);
      EncodedNumber encodedNumber2 = new EncodedNumber(defaultPartialSignedContext,
              defaultPartialSignedContext.getMinEncoded(), 0);
      EncodedNumber encodedNumber3 = new EncodedNumber(defaultPartialSignedContext,
              defaultPartialSignedContext.getMaxEncoded().add(BigInteger.ONE), 0);

      assertEquals(true, encodedNumber1.isValid());
      assertEquals(true, encodedNumber2.isValid());
      assertEquals(false, encodedNumber3.isValid());
    }

    @Test
    public void testEquals() throws Exception {
      EncodedNumber encodedNumber = defaultSignedContext.encode(17);

      assertTrue(encodedNumber.equals(encodedNumber)); // Compare to itself
      assertFalse(encodedNumber.equals(defaultSignedContext)); // Compare to other object
      assertFalse(encodedNumber.equals(null)); // Compare to null

      EncodedNumber otherEncodedNumber = null;
      assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an uninitialised encoded number
      otherEncodedNumber = defaultSignedContext.encode(3);
      assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an encoded number with different value

      otherEncodedNumber = defaultPartialSignedContext.encode(17);
      assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an encoded number with different context
    }

    @Test
    public void testEncodedDecreaseInvalidExponent() throws Exception {
      EncodedNumber enc1 = defaultSignedContext.encode(3.14);
      assertTrue(enc1.getExponent() < -10);

      try {
        enc1.decreaseExponentTo(-10);
      } catch (IllegalArgumentException e) {
      }
    }

    @Test
    public void testInvalidNumber() throws Exception {
      try {
        defaultSignedContext.encode(Double.NaN);
        fail("Successfully encode a NaN");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.POSITIVE_INFINITY);
        fail("Successfully encode positive infinity");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.NEGATIVE_INFINITY);
        fail("Successfully encode negative infinity");
      } catch (EncodeException e) {
      }

      try {
        defaultUnsignedContext.encode(-1.0);
        fail("Successfully encode a negative number using an unsigned Paillier context");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.NaN, 1);
        fail("Successfully encode a NaN with a specific exponent");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.POSITIVE_INFINITY, 1);
        fail("Successfully encode positive infinity with a specific exponent");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.NEGATIVE_INFINITY, 1);
        fail("Successfully encode negative infinity with a specific exponent");
      } catch (EncodeException e) {
      }

      try {
        defaultUnsignedContext.encode(-1.0, 1);
        fail("Successfully encode a negative number with a specific exponent using an unsigned Paillier context");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.NaN, 1e-3);
        fail("Successfully encode a NaN with a specific precision");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.POSITIVE_INFINITY, 1e-3);
        fail("Successfully encode positive infinity with a specific precision");
      } catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(Double.NEGATIVE_INFINITY, 1e-3);
        fail("Successfully encode negative infinity with a specific precision");
      }catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(-1.0, -1e-3);
        fail("Successfully encode a number with invalid precision");
      }catch (EncodeException e) {
      }

      try {
        defaultSignedContext.encode(-1.0, 1e3);
        fail("Successfully encode a number with invalid precision");
      }catch (EncodeException e) {
      }

      try {
        defaultUnsignedContext.encode(-1.0, 1e-3);
        fail("Successfully encode a negative number using an unsigned Paillier context");
      }catch (EncodeException e) {
      }
    }

    @Test
    public void testAutomaticPrecisionAgreesWithEpsilon() throws Exception {
      double eps = Math.ulp(1.0);

      double floorHappy = Math.ceil(Math.log((double) PaillierContext.DEFAULT_BASE)/ Math.log(2.0)) * 2;

      for(double i = -floorHappy; i <= floorHappy; i++){
        EncodedNumber enc1 = defaultSignedContext.encode(Math.pow(2.0, i));
        EncodedNumber enc2 = defaultSignedContext.encode(Math.pow(2.0, i), (eps * Math.pow(2.0, i)));
        assertEquals(String.valueOf(i), enc1.getExponent(), enc2.getExponent());

        double realEps = eps * Math.pow(2.0, (i - 1));
        double val = Math.pow(2.0, i) - realEps;
        assertTrue(val != Math.pow(2.0, i));

        EncodedNumber enc3 = defaultSignedContext.encode(val);
        EncodedNumber enc4 = defaultSignedContext.encode(val, realEps);
        assertEquals(String.valueOf(i), enc3.getExponent(), enc4.getExponent());
      }
    }

  }

}

