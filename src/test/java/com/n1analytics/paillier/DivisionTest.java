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
import org.junit.runners.Parameterized.Parameters;

import java.util.ArrayList;
import java.util.Collection;

import static com.n1analytics.paillier.TestConfiguration.CONFIGURATIONS;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
@Category(SlowTests.class)
public class DivisionTest {
  private PaillierContext context;
  private PaillierPrivateKey privateKey;

  static private int maxIteration = TestConfiguration.MAX_ITERATIONS;

  @Parameters
  public static Collection<Object[]> configurations() {
    Collection<Object[]> configurationParams = new ArrayList<>();

    for(TestConfiguration[] confs : CONFIGURATIONS) {
      for(TestConfiguration conf : confs) {
        configurationParams.add(new Object[]{conf});
      }
    }
    return configurationParams;
  }

  public DivisionTest(TestConfiguration conf) {
    context = conf.context();
    privateKey = conf.privateKey();
  }

  @Test
  public void testDivideEncryptedNumber1() throws Exception {
    double a, b, invertedB, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, encryptedResult;

    for(int i = 0; i < maxIteration; i++) {
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

      invertedB = 1 / b;
      if (Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / b;

      cipherTextA = context.encrypt(a);

      encryptedResult = cipherTextA.divide(b);

      try {
        decodedResult = encryptedResult.decrypt(privateKey).decodeDouble();

        double absValue = Math.abs(plainResult);
        if(absValue == 0.0 || absValue > 1.0) {
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

  @Test
  public void testDivideEncryptedNumber2() throws Exception {
    long b;
    double a, invertedB, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, encryptedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = random.nextLong();

      if(context.isUnsigned()) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
        }
       }

      invertedB = 1 / (double) b;
      if(Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / (double) b;

      cipherTextA = context.encrypt(a);

      encryptedResult = cipherTextA.divide(b);

      try {
        decodedResult = encryptedResult.decrypt(privateKey).decodeDouble();

        double absValue = Math.abs(plainResult);
        if(absValue == 0.0 || absValue > 1.0) {
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

  @Test
  public void testDivideEncodedNumber1() throws Exception {
    double a, b, invertedB, plainResult, decodedResult, tolerance;
    EncodedNumber encodedNumberA, encodedResult;

    for(int i = 0; i < maxIteration; i++) {
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

      invertedB = 1 / b;
      if(Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / b;

      encodedNumberA = context.encode(a);

      encodedResult = encodedNumberA.divide(b);

      try {
        decodedResult = encodedResult.decodeDouble();

        double absValue = Math.abs(plainResult);
        if(absValue == 0.0 || absValue > 1.0) {
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

  @Test
  public void testDivideEncodedNumber2() throws Exception {
    long b;
    double a, invertedB, plainResult, decodedResult, tolerance;
    EncodedNumber encodedNumberA, encodedResult;

    for(int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = random.nextLong();

      if(context.isUnsigned()) {
        if (a < 0) {
          a = -a;
        }
        if (b < 0) {
          b = -b;
        }
       }

      invertedB = 1 / (double) b;
      if(Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / (double) b;

      encodedNumberA = context.encode(a);

      encodedResult = encodedNumberA.divide(b);

      try {
        decodedResult = encodedResult.decodeDouble();

        double absValue = Math.abs(plainResult);
        if(absValue == 0.0 || absValue > 1.0) {
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
}
