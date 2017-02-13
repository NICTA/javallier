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
public class SubtractionTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  static private int maxIteration = TestConfiguration.MAX_ITERATIONS;

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

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      // Check if B and A are "close enough", otherwise there will be an undetected overflow
      double minB = a - (a * EPSILON), maxB = a + (a * EPSILON);
      if(b > maxB || b < minB) {
        continue;
      }

      plainResult = a - b;

      if(context.isUnsigned() && (a < 0 || b < 0 || plainResult < 0)) {
        continue;
      }

      cipherTextA = context.encrypt(a);
      cipherTextB = context.encrypt(b);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB_obf = cipherTextB.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

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
          System.out.println("DecodeException thrown");
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

    for(int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
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

      plainResult = a.subtract(b);
      if(!isValid(context, plainResult))
        continue;

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
