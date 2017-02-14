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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.n1analytics.paillier.util.BigIntegerUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

import static com.n1analytics.paillier.TestConfiguration.CONFIGURATIONS;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
@Category(SlowTests.class)
public class MultiplicationTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  final static private int MAX_ITERATIONS = TestConfiguration.MAX_ITERATIONS;

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

  public MultiplicationTest(TestConfiguration conf) {
    context = conf.context();
    privateKey = conf.privateKey();
  }

  interface EncryptedToEncodedMultiplier {

    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg1_obf, EncodedNumber arg2);
  }

  interface EncodedToEncodedMultiplier {

    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  EncryptedToEncodedMultiplier encryptedToEncodedMultipliers[] = new EncryptedToEncodedMultiplier[]{new EncryptedToEncodedMultiplier() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg1_obf, EncodedNumber arg2) {
      return arg1.multiply(arg2);
    }
  }, new EncryptedToEncodedMultiplier() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg1_obf, EncodedNumber arg2) {
      return arg2.multiply(arg1);
    }
  }, new EncryptedToEncodedMultiplier() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg1_obf, EncodedNumber arg2) {
      return context.multiply(arg1, arg2);
    }
  }, new EncryptedToEncodedMultiplier() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg1_obf, EncodedNumber arg2) {
      return context.multiply(arg2, arg1);
    }
  }};

  EncodedToEncodedMultiplier encodedToEncodedMultipliers[] = new EncodedToEncodedMultiplier[]{new EncodedToEncodedMultiplier() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.multiply(arg2);
    }
  }, new EncodedToEncodedMultiplier() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.multiply(arg1);
    }
  }, new EncodedToEncodedMultiplier() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg1, arg2);
    }
  }, new EncodedToEncodedMultiplier() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg2, arg1);
    }
  }};

  @Test
  public void testDoubleMultiplication() {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, cipherTextA_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, decryptedResult;

    for(int i = 0; i < MAX_ITERATIONS; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      if(context.isUnsigned()) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
        }
      }

      plainResult = a * b;

      cipherTextA = context.encrypt(a);
      cipherTextA_obf = cipherTextA.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

      for (EncryptedToEncodedMultiplier multiplier : encryptedToEncodedMultipliers) {
        encryptedResult = multiplier.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();

          double absValue = Math.abs(plainResult);
          if(absValue == 0.0 || absValue > 1.0) {
            tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
          } else {
            tolerance = EPSILON;
          }
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      
      for (EncodedToEncodedMultiplier multiplier : encodedToEncodedMultipliers) {
        decryptedResult = multiplier.eval(encodedA, encodedB);
        try {
          decodedResult = decryptedResult.decodeDouble();

          double absValue = Math.abs(plainResult);
          if(absValue == 0.0 || absValue > 1.0) {
            tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
          } else {
            tolerance = EPSILON;
          }
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }

  @Test
  public void testLongMultiplication() {
    long a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextA_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, decryptedResult;

    for(int i = 0; i < MAX_ITERATIONS; i++) {
      a = random.nextLong();
      b = random.nextLong();

      if(context.isUnsigned()) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
        }
      }

      plainResult = a * b;

      cipherTextA = context.encrypt(a);
      cipherTextA_obf = cipherTextA.obfuscate();
      encodedB = context.encode(b);
      encodedA = context.encode(a);

      for (EncryptedToEncodedMultiplier multiplier : encryptedToEncodedMultipliers) {
        encryptedResult = multiplier.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncodedToEncodedMultiplier multiplier : encodedToEncodedMultipliers) {
        decryptedResult = multiplier.eval(encodedA, encodedB);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }

  @Test
  public void testBigIntegerMultiplication() {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextA_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, decryptedResult;

    for(int i = 0; i < MAX_ITERATIONS; i++) {
      do {
        a = new BigInteger(context.getPrecision(), random);
      } while(BigIntegerUtil.greater(a, context.getMaxSignificand()) || BigIntegerUtil.less(a, context.getMinSignificand()));
      do {
        b = new BigInteger(context.getPrecision(), random);
      } while(BigIntegerUtil.greater(b, context.getMaxSignificand()) || BigIntegerUtil.less(b, context.getMinSignificand()));


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

      plainResult = a.multiply(b);
      while(!isValid(context, plainResult)) {
        b = b.shiftRight(1);
        plainResult = a.multiply(b);
      }

      cipherTextA = context.encrypt(a);
      cipherTextA_obf = cipherTextA.obfuscate();
      encodedB = context.encode(b);
      encodedA = context.encode(a);

      for (EncryptedToEncodedMultiplier multiplier : encryptedToEncodedMultipliers) {
        encryptedResult = multiplier.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncodedToEncodedMultiplier multiplier : encodedToEncodedMultipliers) {
        decryptedResult = multiplier.eval(encodedA, encodedB);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }

}
