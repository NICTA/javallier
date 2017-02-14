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
public class AdditionTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  static private int MAX_ITERATIONS = TestConfiguration.MAX_ITERATIONS;

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

  interface EncryptedToEncryptedAdder {
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated);
  }

  interface EncryptedToEncodedAdder {
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2);
  }

  interface EncodedToEncodedAdder {
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  /**
   * Combinations of adding Encrypted number to test:
   *  - adding using Object api
   *  - adding using context
   *  - with arguments reversed
   *  - adding obfuscated numbers
   *  - adding non-obfuscated with obfuscated
   * */
  EncryptedToEncryptedAdder encryptedToEncryptedAdders[] = new EncryptedToEncryptedAdder[]{new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg1_nonObfuscated.add(arg2_nonObfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg2_nonObfuscated.add(arg1_nonObfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg1_nonObfuscated, arg2_nonObfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg2_nonObfuscated, arg1_nonObfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg1_obfuscated.add(arg2_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg2_obfuscated.add(arg1_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg1_obfuscated, arg2_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg2_obfuscated, arg1_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg1_nonObfuscated.add(arg2_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return arg1_obfuscated.add(arg2_nonObfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg1_nonObfuscated, arg2_obfuscated);
    }
  }, new EncryptedToEncryptedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, 
        EncryptedNumber arg2_nonObfuscated, EncryptedNumber arg2_obfuscated) {
      return context.add(arg1_obfuscated, arg2_nonObfuscated);
    }
  }
  };

  EncryptedToEncodedAdder encryptedToEncodedAdders[] = new EncryptedToEncodedAdder[]{new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return arg1_nonObfuscated.add(arg2);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return arg1_obfuscated.add(arg2);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return arg2.add(arg1_nonObfuscated);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return arg2.add(arg1_obfuscated);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return context.add(arg1_nonObfuscated, arg2);
    }
  },  new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return context.add(arg1_obfuscated, arg2);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return context.add(arg2, arg1_nonObfuscated);
    }
  }, new EncryptedToEncodedAdder() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1_nonObfuscated, EncryptedNumber arg1_obfuscated, EncodedNumber arg2) {
      return context.add(arg2, arg1_obfuscated);
    }
  }};

  EncodedToEncodedAdder encodedToEncodedAdders[] = new EncodedToEncodedAdder[]{new EncodedToEncodedAdder() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new EncodedToEncodedAdder() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new EncodedToEncodedAdder() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new EncodedToEncodedAdder() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  @Test
  public void testDoubleAddition() {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, encodedResult, decryptedResult;
    Random rnd = new Random();
    int maxExponentDiff = (int)(0.5 * context.getPublicKey().getModulus().bitLength() / (Math.log(context.getBase()) / Math.log(2)));

    for(int i = 0; i < MAX_ITERATIONS; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      if(context.isUnsigned() && (a < 0 || b < 0)) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
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
      encodedB = context.encode(b);

      plainResult = a + b;

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

      for (EncryptedToEncryptedAdder adder : encryptedToEncryptedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncryptedToEncodedAdder adder : encryptedToEncodedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeDouble();
          assertEquals(plainResult, decodedResult, tolerance);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncodedToEncodedAdder adder : encodedToEncodedAdders) {
        encodedResult = adder.eval(encodedA, encodedB);
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
  public void testLongAddition() {
    long a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf, encryptedResult;
    EncodedNumber encodedA, encodedB, encodedResult, decryptedResult;

    for(int i = 0; i < MAX_ITERATIONS; i++) {
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

      plainResult = a + b;

      cipherTextA = context.encrypt(a);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB = context.encrypt(b);
      cipherTextB_obf = cipherTextB.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

      for (EncryptedToEncryptedAdder adder : encryptedToEncryptedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncryptedToEncodedAdder adder : encryptedToEncodedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncodedToEncodedAdder adder : encodedToEncodedAdders) {
        encodedResult = adder.eval(encodedA, encodedB);
        try {
          decodedResult = encodedResult.decodeLong();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }
  
  @Test
  public void testBigIntegerAddition() {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber cipherTextA, cipherTextB, cipherTextA_obf, cipherTextB_obf, encryptedResult;
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
      }

      plainResult = a.add(b);
      while(!isValid(context, plainResult)) {
        b = b.shiftRight(1);
        plainResult = a.add(b);
      }

      cipherTextA = context.encrypt(a);
      cipherTextB = context.encrypt(b);
      cipherTextA_obf = cipherTextA.obfuscate();
      cipherTextB_obf = cipherTextB.obfuscate();
      encodedA = context.encode(a);
      encodedB = context.encode(b);

      for (EncryptedToEncryptedAdder adder : encryptedToEncryptedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, cipherTextB, cipherTextB_obf);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncryptedToEncodedAdder adder : encryptedToEncodedAdders) {
        encryptedResult = adder.eval(cipherTextA, cipherTextA_obf, encodedB);
        decryptedResult = encryptedResult.decrypt(privateKey);
        try {
          decodedResult = decryptedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
      for (EncodedToEncodedAdder adder : encodedToEncodedAdders) {
        encodedResult = adder.eval(encodedA, encodedB);
        try {
          decodedResult = encodedResult.decodeBigInteger();
          assertEquals(plainResult, decodedResult);
        } catch (ArithmeticException e) {
        } catch (DecodeException e) {
        }
      }
    }
  }

}
