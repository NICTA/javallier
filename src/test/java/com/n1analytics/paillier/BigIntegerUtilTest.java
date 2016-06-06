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

import java.math.BigInteger;
import java.util.HashSet;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.*;

public class BigIntegerUtilTest {

  final private BigInteger BigOne = BigInteger.ONE;
  final private BigInteger BigZero = BigInteger.ZERO;
  final private BigInteger BigNegativeOne = BigInteger.ONE.negate();

  @Test
  public void testRandomPositiveNumberInvalidParameters() {
    int[] invalidParameters = new int[]{-1, 0, 1};
    for (int i : invalidParameters) {
      try {
        BigIntegerUtil.randomPositiveNumber(BigInteger.valueOf(i));
        fail("Expected IllegalArgumentException");
      } catch (IllegalArgumentException e) {
      }
    }
  }

  @Test
  public void testRandomPositiveNumberSmallRanges() {
    for (int i = 2; i < 32; ++i) {
      HashSet<Integer> sampled = new HashSet<Integer>();
      for (int j = 0; j < 1000 * i; ++j) {
        int k = BigIntegerUtil.randomPositiveNumber(BigInteger.valueOf(i)).intValue();
        assertTrue(1 <= k && k < i);
        sampled.add(k);
      }
      assertTrue("Missing samples (NON-DETERMINISTIC TEST)", sampled.size() == i - 1);
    }
  }

  @Test
  public void testBigIntegerSignum() throws Exception {
    assertTrue(BigIntegerUtil.positive(BigOne));
    assertTrue(BigIntegerUtil.nonNegative(BigOne));
    assertFalse(BigIntegerUtil.negative(BigOne));
    assertFalse(BigIntegerUtil.nonPositive(BigOne));

    assertTrue(BigIntegerUtil.nonNegative(BigZero));
    assertTrue(BigIntegerUtil.nonPositive(BigZero));

    assertTrue(BigIntegerUtil.negative(BigNegativeOne));
    assertTrue(BigIntegerUtil.nonPositive(BigNegativeOne));
    assertFalse(BigIntegerUtil.positive(BigNegativeOne));
    assertFalse(BigIntegerUtil.nonNegative(BigNegativeOne));
  }

  @Test
  public void testComparison() throws Exception {
    assertTrue(BigIntegerUtil.greater(BigOne, BigNegativeOne));
    assertTrue(BigIntegerUtil.greaterOrEqual(BigOne, BigNegativeOne));
    assertTrue(BigIntegerUtil.greaterOrEqual(BigOne, BigOne));

    assertTrue(BigIntegerUtil.less(BigNegativeOne, BigOne));
    assertTrue(BigIntegerUtil.lessOrEqual(BigNegativeOne, BigOne));
    assertTrue(BigIntegerUtil.lessOrEqual(BigNegativeOne, BigNegativeOne));

    assertFalse(BigIntegerUtil.greater(BigNegativeOne, BigOne));
    assertFalse(BigIntegerUtil.greaterOrEqual(BigNegativeOne, BigOne));

    assertFalse(BigIntegerUtil.less(BigOne, BigNegativeOne));
    assertFalse(BigIntegerUtil.lessOrEqual(BigOne, BigNegativeOne));
  }

  @Test
  public void testSqrt() throws Exception {
    BigInteger n = BigIntegerUtil.randomPositiveNumber(BigInteger.ONE
        .shiftLeft(512));
    BigInteger nSquared = n.multiply(n);
    assertEquals(BigIntegerUtil.sqrt(nSquared), n);
  }
}
