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
import java.util.Random;

import static com.n1analytics.paillier.TestConfiguration.CONFIGURATIONS;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
@Category(SlowTests.class)
public class SubtractionTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  static final private int MAX_ITERATIONS = TestConfiguration.MAX_ITERATIONS;

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

  public SubtractionTest(TestConfiguration conf) {
    context = conf.context();
    privateKey = conf.privateKey();
  }

  interface EncryptedToEncryptedSubtractor {
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated);
  }

  interface EncryptedToEncodedSubtractor {
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2);
  }

  interface EncodedToEncodedSubtractor {
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  /**
   * Subtracting encrypted number from another encrypted number, possible combinations
   * (using subtraction in API and context):
   *  - Non-obfuscated / non-obfuscated
   *  - Obfuscated / obfuscated
   *  - Non-obfuscated / obfuscated
   *  - Obfuscated / non-obfuscated
   */
  EncryptedToEncryptedSubtractor encryptedToEncryptedSubtractors[] = new EncryptedToEncryptedSubtractor[]{
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return arg1_nonObfuscated.subtract(arg2_nonObfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return context.subtract(arg1_nonObfuscated, arg2_nonObfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return arg1_obfuscated.subtract(arg2_obfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return context.subtract(arg1_obfuscated, arg2_obfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return arg1_nonObfuscated.subtract(arg2_obfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return context.subtract(arg1_nonObfuscated, arg2_obfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return arg1_obfuscated.subtract(arg2_nonObfuscated);
            }
          },
          new EncryptedToEncryptedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
              return context.subtract(arg1_obfuscated, arg2_nonObfuscated);
            }
          }
  };

  /**
   * Subtracting encoded number from encrypted number, possible combinations
   * (using subtraction in API and context):
   *  - Non-obfuscated encrypted / encoded
   *  - Obfuscated / encoded
   */
  EncryptedToEncodedSubtractor encryptedToEncodedSubtractors[] = new EncryptedToEncodedSubtractor[]{
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return arg1_nonObfuscated.subtract(arg2);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return context.subtract(arg1_nonObfuscated, arg2);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return arg1_obfuscated.subtract(arg2);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return context.subtract(arg1_obfuscated, arg2);
            }
          }
  };

  /**
   * Subtracting encoded number from encrypted number, possible combinations
   * (using subtraction in API and context):
   *  - Encoded / non-obfuscated
   *  - Encoded / obfuscated
   */
  EncryptedToEncodedSubtractor encodedToEncryptedSubtractors[] = new EncryptedToEncodedSubtractor[] {
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return arg2.subtract(arg1_nonObfuscated);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return context.subtract(arg2, arg1_nonObfuscated);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return arg2.subtract(arg1_obfuscated);
            }
          },
          new EncryptedToEncodedSubtractor() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated,
                                        EncodedNumber arg2) {
              return context.subtract(arg2, arg1_obfuscated);
            }
          }
  };

  /**
   * Subtracting encoded number from another encoded number.
   */
  EncodedToEncodedSubtractor encodedToEncodedSubtractors[] = new EncodedToEncodedSubtractor[]{
          new EncodedToEncodedSubtractor() {
            @Override
            public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
              return arg1.subtract(arg2);
            }
          },
          new EncodedToEncodedSubtractor() {
            @Override
            public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
              return context.subtract(arg1, arg2);
            }
          }
  };

  @Test
  public void testDoubleSubtraction() {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, encodedResult, decryptedResult;
    Random rnd = new Random();
    int maxExponentDiff = (int)(0.5 * context.getMaxEncoded().bitLength() / (Math.log(context.getBase()) / Math.log(2)) - (Math.ceil(Math.log(1<<53) / Math.log(context.getBase()))));
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
        if (a < b) {
          double tmp = a;
          a = b;
          b = tmp;
        }
      }
      encodedA = context.encode(a);
      encodedB = context.encode(b);
      //check for overflows
      if (Math.abs(encodedA.exponent - encodedB.exponent) > maxExponentDiff) {
        int newExp = encodedA.exponent - (int)Math.round((rnd.nextDouble()) * maxExponentDiff);
        encodedB = new EncodedNumber(context, encodedB.value, newExp);
      }
      b = encodedB.decodeDouble();
      if(context.isUnsigned()) { //now that we changed b, we have to check again if a < b
        if (a < b) {
          double tmp = a;
          a = b;
          b = tmp;
          encodedA = context.encode(a);
        }
      }
      encodedB = context.encode(b);
      
      plainResult = a - b;
      
      cipherTextA = context.encrypt(a);
      cipherTextB = context.encrypt(b);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB_obf = cipherTextB.obfuscate();
      double absValue = Math.abs(plainResult);
      if (absValue == 0.0 || absValue > 1.0) {
        tolerance = EPSILON * Math.pow(2.0, Math.getExponent(plainResult));
      } else {
        tolerance = EPSILON;
      }

      for (EncryptedToEncryptedSubtractor subtractor : encryptedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor : encryptedToEncodedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor: encodedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextB, cipherTextB_obf, encodedA);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }

      for (EncodedToEncodedSubtractor subtractor : encodedToEncodedSubtractors) {
        encodedResult = subtractor.eval(encodedA, encodedB);
        try {
          decodedResult = encodedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }

  @Test
  public void testLongSubtraction() {
    long a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, encodedResult, decryptedResult;

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
        if (a < b) {
          long tmp = a;
          a = b;
          b = tmp;
        }
      }

      plainResult = a - b;

      cipherTextA = context.encrypt(a);
      cipherTextB = context.encrypt(b);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB_obf = cipherTextB.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

      for (EncryptedToEncryptedSubtractor subtractor : encryptedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor : encryptedToEncodedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor: encodedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextB, cipherTextB_obf, encodedA);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncodedToEncodedSubtractor subtractor : encodedToEncodedSubtractors) {
        encodedResult = subtractor.eval(encodedA, encodedB);
        try {
          decodedResult = encodedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }
    }
  }

  @Test
  public void testBigIntegerSubtraction() {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, encodedResult, decryptedResult;
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
      } else {
        if (a.compareTo(b) == -1) {
          BigInteger tmp = a;
          a = b;
          b = tmp;
        }
      }

      plainResult = a.subtract(b);
      while (!isValid(context, plainResult)) {
        b = b.shiftRight(1);
        plainResult = a.subtract(b);
      }

      cipherTextA = context.encrypt(a);
      cipherTextB = context.encrypt(b);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB_obf = cipherTextB.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

      for (EncryptedToEncryptedSubtractor subtractor : encryptedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor : encryptedToEncodedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncryptedToEncodedSubtractor subtractor: encodedToEncryptedSubtractors) {
        encryptedResult = subtractor.eval(cipherTextB, cipherTextB_obf, encodedA);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }

      for (EncodedToEncodedSubtractor subtractor : encodedToEncodedSubtractors) {
        encodedResult = subtractor.eval(encodedA, encodedB);
        try {
          decodedResult = encodedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (DecodeException e) {
        }
      }
    }
  }
}
