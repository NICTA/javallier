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
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

import static com.n1analytics.paillier.TestConfiguration.CONFIGURATIONS;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
@Category(SlowTests.class)
public class AdditionTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  static private int maxIteration = 100;

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

  public AdditionTest(TestConfiguration conf) {
    context = conf.context();
    privateKey = conf.privateKey();
  }

  interface BinaryAdder1
          extends TwoInputsFunction<EncryptedNumber, EncryptedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2);
  }

  interface BinaryAdder2
          extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
  }

  interface BinaryAdder4
          extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {

    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  BinaryAdder1 binaryAdders1[] = new BinaryAdder1[]{new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  BinaryAdder2 binaryAdders2[] = new BinaryAdder2[]{new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  BinaryAdder4 binaryAdders4[] = new BinaryAdder4[]{new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  void testDoubleAddition(BinaryAdder1 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      // Check if B and A are "close enough", otherwise there will be an undetected overflow
      double minB = a - (a * EPSILON), maxB = a + (a * EPSILON);
      if(b > maxB || b < minB)
        continue;

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeDouble();

        double absValue = Math.abs(plainResult);
        if (absValue == 0.0 || absValue > 1.0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
        } else {
          tolerance = EPSILON;
        }

        assertEquals(plainResult, decodedResult, tolerance);
      } catch (DecodeException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder1 adder) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder1 adder) {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = new BigInteger(context.getPrecision(), random);
      b = new BigInteger(context.getPrecision(), random);

      if(BigIntegerUtil.greater(a, context.getMaxSignificand()) || BigIntegerUtil.less(a, context.getMinSignificand()))
        continue;

      if(BigIntegerUtil.greater(b, context.getMaxSignificand()) || BigIntegerUtil.less(b, context.getMinSignificand()))
        continue;

      // The random generator above only generates positive BigIntegers, the following code
      // negates some inputs.
      if(context.isSigned()) {
        if(i % 4 == 1) {
          b = b.negate();
        } else if(i % 4 == 2) {
          a = a.negate();
        } else if(i % 4 == 3) {
          a = a.negate();
          b = b.negate();
        }
      }

      plainResult = a.add(b);
      if(!isValid(context, plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleAddition(BinaryAdder2 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      // Check if B and A are "close enough", otherwise there will be an undetected overflow
      double minB = a - (a * EPSILON), maxB = a + (a * EPSILON);
      if(b > maxB || b < minB)
        continue;

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeDouble();

        double absValue = Math.abs(plainResult);
        if (absValue == 0.0 || absValue > 1.0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
        } else {
          tolerance = EPSILON;
        }

        assertEquals(plainResult, decodedResult, tolerance);
      } catch (DecodeException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder2 adder) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder2 adder) {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = new BigInteger(context.getPrecision(), random);
      b = new BigInteger(context.getPrecision(), random);

      // The random generator above only generates positive BigIntegers, the following code
      // negates some inputs.
      if(context.isSigned()) {
        if(i % 4 == 1) {
          b = b.negate();
        } else if(i % 4 == 2) {
          a = a.negate();
        } else if(i % 4 == 3) {
          a = a.negate();
          b = b.negate();
        }
      }

      plainResult = a.add(b);

      if(!isValid(context, a) || !isValid(context, b) || !isValid(context, plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleAddition(BinaryAdder4 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncodedNumber encodedA, encodedB, encodedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      // Check if B and A are "close enough", otherwise there will be an undetected overflow
      double minB = a - (a * EPSILON), maxB = a + (a * EPSILON);
      if(b > maxB || b < minB)
        continue;

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeDouble();

        if(Math.getExponent(plainResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
        } else {
          tolerance = EPSILON;
        }

        assertEquals(plainResult, decodedResult, tolerance);
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder4 adder) {
    long a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        continue;
      }

      plainResult = a + b;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder4 adder) {
    BigInteger a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = new BigInteger(context.getPrecision(), random);
      b = new BigInteger(context.getPrecision(), random);

      // The random generator above only generates positive BigIntegers, the following code
      // negates some inputs.
      if(context.isSigned()) {
        if (i % 4 == 1) {
          b = b.negate();
        } else if (i % 4 == 2) {
          a = a.negate();
        } else if (i % 4 == 3) {
          a = a.negate();
          b = b.negate();
        }
      }

      plainResult = a.add(b);
      if(!isValid(context, a) || !isValid(context, b) || !isValid(context, plainResult))
        continue;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testAdditionEncryptedNumbers1() throws Exception {
    for(BinaryAdder1 adder : binaryAdders1) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

  @Test
  public void testAdditionEncryptedNumbers2() throws Exception {
    for(BinaryAdder2 adder : binaryAdders2) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

  @Test
  public void testAdditionEncodedNumbers1() throws Exception {
    for(BinaryAdder4 adder : binaryAdders4) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

}
