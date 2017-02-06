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
package com.n1analytics.paillier.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.squareup.jnagmp.Gmp;

/**
 * A class containing the common methods for {@code BigInteger} manipulation, including:
 * <ul>
 *     <li>The {@code BigInteger} representation of the minimum and maximum {@code long} values</li>
 *     <li>The methods to check the property of a {@code BigInteger}, i.e., {@code positive}, {@code negative}, etc</li>
 *     <li>The methods comparing two {@code BigInteger}, i.e., {@code greaterThan}, {@code lessThan}, etc</li>
 *     <li>The method to generate strictly random positive number</li>
 *     <li>The method to determine the bit length of an absolute value of a {@code BigInteger}</li>
 *     <li>The method to convert a {@code BigInteger} to an exact {@code long} representation</li>
 *     <li>The method to compute square root</li>
 * </ul>
 */
public class BigIntegerUtil {
  
  private static Logger logger = Logger.getLogger("com.n1analytics.paillier");

  /**
   * Minimum {@code long} value as a {@code BigInteger}.
   */
  public static final BigInteger LONG_MIN_VALUE = BigInteger.valueOf(Long.MIN_VALUE);

  /**
   * Maximum {@code long} value as a {@code BigInteger}.
   */
  public static final BigInteger LONG_MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);

 
  public static final SecureRandom random = new SecureRandom();
  
  /**
   * will be set to 'true' if the gmp library is available.
   */
  public static final boolean USE_GMP;
 
 
  static{
    //check if GMP is available
    USE_GMP = canLoadGmp();
  }
  
  private static boolean canLoadGmp(){
    try{
      Gmp.checkLoaded();
      return true;
    }catch(Error e){
      logger.log(Level.WARNING, "can't load Gmp library. Falling back to native Java for modPow. Unfortunately, that's a 'lot' slower.", e);
      return  false;
    }
  }
  
  /**
   * computes a modular exponentiation. It will call the GMP library, if available on this system.
   * This leads to a significant speed-up.
   * @param base of the modular exponentiation
   * @param exponent of the exponentiation
   * @param modulus
   * @return (base ^ exponent) mod modulus
   */
  public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
    if (USE_GMP) {
      return exponent.signum() < 0 //Gmp library can't handle negative exponents
          ? modInverse(Gmp.modPowSecure(base, exponent.negate(), modulus), modulus)
          : Gmp.modPowSecure(base, exponent, modulus);
    } else {
      return base.modPow(exponent, modulus);
    }
  }

  /**
   * Computes the multiplicitive inverse of `a` in the integers, modulo `b`.
   *
   * @param a the number to invert
   * @param b the modulus
   * @throws ArithmeticException if the inverse doesn't exist
   * @return x, where a * x == 1 mod b
   */
  public static BigInteger modInverse(BigInteger a, BigInteger b) throws ArithmeticException {
    if(USE_GMP){
      return Gmp.modInverse(a, b);
    } else {
      return a.modInverse(b);
    }
  }

  /**
   * Checks whether {@code n} is positive.
   *
   * @param n number to check.
   * @return true if {@code n} is positive, false otherwise.
   */
  public static boolean positive(BigInteger n) {
    return n.signum() > 0;
  }

  /**
   * Checks whether {@code n} is non-negative.
   *
   * @param n number to check.
   * @return true if {@code n} is positive or {@code n} is equal to 0, false otherwise.
   */
  public static boolean nonNegative(BigInteger n) {
    return n.signum() >= 0;
  }

  /**
   * Checks whether {@code n} is negative.
   *
   * @param n number to check.
   * @return true if {@code n} is negative, false otherwise.
   */
  public static boolean negative(BigInteger n) {
    return n.signum() < 0;
  }

  /**
   * Checks whether {@code n} is non-positive.
   *
   * @param n number to check.
   * @return true if {@code n} is negative or {@code n} is equal to 0, false otherwise.
   */
  public static boolean nonPositive(BigInteger n) {
    return n.signum() <= 0;
  }

  /**
   * Checks whether {@code a} is greater than {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is greater than {@code b}, false otherwise.
   */
  public static boolean greater(BigInteger a, BigInteger b) {
    return a.compareTo(b) > 0;
  }

  /**
   * Checks whether {@code a} is greater than or equal to {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is greater than or equal to {@code b}, false otherwise.
   */
  public static boolean greaterOrEqual(BigInteger a, BigInteger b) {
    return a.compareTo(b) >= 0;
  }

  /**
   * Checks whether {@code a} is less than {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if a is less than {@code b}, false otherwise.
   */
  public static boolean less(BigInteger a, BigInteger b) {
    return a.compareTo(b) < 0;
  }

  /**
   * Checks whether {@code a} is less than or equal to {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is less than or equal to {@code b}, false otherwise.
   */
  public static boolean lessOrEqual(BigInteger a, BigInteger b) {
    return a.compareTo(b) <= 0;
  }

  /**
   * Returns a random strictly positive number less than {@code n}.
   *
   * @param n upper bound.
   * @return a random number less than {@code n}.
   */
  public static BigInteger randomPositiveNumber(final BigInteger n) {
    if (lessOrEqual(n, BigInteger.ONE)) {
      throw new IllegalArgumentException("n must be strictly greater than one");
    }

    int bits = n.bitLength();
    for (; ; ) {
      BigInteger r = new BigInteger(bits, random);
      if (less(r, BigInteger.ONE) || greaterOrEqual(r, n)) {
        continue;
      }
      return r;
    }
  }

  /**
   * Computes the Integer part of the square root of {@code BigInteger} {@code n}.
   * This code is adapted from Faruk Akgul's code found at:
   * http://faruk.akgul.org/blog/javas-missing-algorithm-biginteger-sqrt/
   *
   * @param n number to square root.
   * @return the integer part of the square root of {@code n}.
   */
  public static BigInteger sqrt(BigInteger n) {
    BigInteger a = BigInteger.ONE;
    BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
    while (b.compareTo(a) >= 0) {
      BigInteger mid = a.add(b).shiftRight(1);
      if (mid.multiply(mid).compareTo(n) > 0)
        b = mid.subtract(BigInteger.ONE);
      else
        a = mid.add(BigInteger.ONE);
    }
    return a.subtract(BigInteger.ONE);
  }
  
}
