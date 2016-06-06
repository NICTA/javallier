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

import java.math.BigInteger;
import java.util.Random;

public class TestUtil {

  public static final double EPSILON = 1e-3;

  public static final Random random = new Random();

  public static double randomDouble() {
	  return Double.longBitsToDouble(random.nextLong());
  }

  public static double randomFiniteDouble() {
    for (; ; ) {
      double value = randomDouble();
		if (!(Double.isInfinite(value) || Double.isNaN(value))) {
			return value;
		}
    }
  }

  public static double randomNaNDouble() {
    for (; ; ) {
      // Generate a random NaN/infinity
      double value = Double.longBitsToDouble(0x7FF000000000000L | random.nextLong());
		if (Double.isNaN(value)) {
			return value;
		}
    }
  }

  public static double randomNormalDouble() {
    for (; ; ) {
      double value = randomFiniteDouble();
		if (value >= Double.MIN_NORMAL) {
			return value;
		}
    }
  }

  public static double randomSubnormalDouble() {
    return Double.longBitsToDouble(0x800FFFFFFFFFFFFL & random.nextLong());
  }

  public static boolean isValid(PaillierContext context, BigInteger number) {
    if (BigIntegerUtil.greater(number, context.getMaxSignificand()) ||
            BigIntegerUtil.less(number, context.getMinSignificand()))
      return false;
    return true;
  }
}
