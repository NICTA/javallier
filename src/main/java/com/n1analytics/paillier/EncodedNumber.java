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

import java.math.BigDecimal;
import java.math.BigInteger;

import com.n1analytics.paillier.util.HashChain;

/**
 * Represents encoded numbers, enabling Paillier encrypted operations on
 * signed integers and signed floating point numbers.
 *
 * This class defines public methods:
 * <ul>
 *     <li>To check whether another EncodedNumber or an EncryptedNumber has the same PaillierContext</li>
 *     <li>To decode exactly and approximately to a BigInteger, long, double and Number</li>
 *     <li>To perform arithmetic operations; addition, subtraction, limited multiplication and limited division.</li>
 * </ul>
 */
public final class EncodedNumber {

  /**
   * The Paillier context used to encode this number.
   */
  protected final PaillierContext context;

  /**
   * The value of the encoded number. Must be a non-negative integer less than <code>context.getModulus()</code>
   */
  protected final BigInteger value;

  /**
   * The exponent of the encoded number.
   */
  protected final int exponent;

  /**
   * Constructs an encoded number given an encoding and an encoded value. The
   * encoded value must be a non-negative integer less than
   * {@code context.getModulus()}.
   *
   * @param context used to encode value.
   * @param value of the encoded number must be a non-negative integer less than {@code context.getModulus()}.
   * @param exponent of the encoded number.
   */
  protected EncodedNumber(PaillierContext context, BigInteger value, int exponent) {
    if (context == null) {
      throw new IllegalArgumentException("context must not be null");
    }
    if (value == null) {
      throw new IllegalArgumentException("value must not be null");
    }
    if (value.signum() < 0) {
      throw new IllegalArgumentException("value must be non-negative");
    }
    if (value.compareTo(context.getPublicKey().getModulus()) >= 0) {
      throw new IllegalArgumentException("value must be less than modulus");
    }
    this.context = context;
    this.value = value;
    this.exponent = exponent;
  }

  /**
   * @return the {@code context} with which this number is encoded.
   */
  public PaillierContext getContext() {
    return context;
  }

  /**
   * @return the encoded {@code value}.
   */
  public BigInteger getValue() {
    return value;
  }

  /**
   * @return {@code exponent}.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Checks whether this encoded number is valid in the current context.
   *
   * @return true if encoded number is valid, false otherwise.
   */
  public boolean isValid() {
    return context.isValid(this);
  }
  
  /**
   * Returns the signum function of this EncodedNumber.
   * @return -1, 0 or 1 as the value of this EncodedNumber is negative, zero or positive.
   */
  public int signum(){
    return context.signum(this);
  }

  /**
   * Checks whether an {@code EncryptedNumber} has the same context as this {@code EncodedNumber}.
   *
   * @param other {@code EncryptedNumber} to compare to.
   * @return {@code other} provided the contexts match, else PaillierContextMismatchException is thrown.
   * @throws PaillierContextMismatchException if the contexts are different.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    return context.checkSameContext(other);
  }

  /**
   * Checks whether another {@code EncodedNumber} has the same context as this {@code EncodedNumber}.
   *
   * @param other {@code EncodedNumber} to compare to.
   * @return {@code other} provided the contexts match, else PaillierContextMismatchException is thrown.
   * @throws PaillierContextMismatchException if the context are different.
   */
  public EncodedNumber checkSameContext(EncodedNumber other)
          throws PaillierContextMismatchException {
    return context.checkSameContext(other);
  }

  /**
   * Decodes to a {@code BigInteger} representation. See
   * {@link com.n1analytics.paillier.PaillierContext#decodeBigInteger(EncodedNumber)} for details.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this {@code EncodedNumber} cannot be represented as a {@code BigInteger}.
   */
  public BigInteger decodeBigInteger() throws ArithmeticException {
    return context.decodeBigInteger(this);
  }

  /**
   * Decodes this {@code EncodedNumber} to a {@code double} representation. See
   * {@link com.n1analytics.paillier.PaillierContext#decodeDouble(EncodedNumber)} for details.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this {@code EncodedNumber} cannot be represented as a valid {@code double}.
   */
  public double decodeDouble() throws ArithmeticException {
    return context.decodeDouble(this);
  }

  /**
   * Decodes this {@code EncodedNumber} to a {@code long} representation. See
   * {@link com.n1analytics.paillier.PaillierContext#decodeLong(EncodedNumber)} for details.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this cannot be represented as a valid {@code long}.
   */
  public long decodeLong() throws ArithmeticException {
    return context.decodeLong(this);
  }
  
  public BigDecimal decodeBigDecimal() throws ArithmeticException {
    return context.decodeBigDecimal(this);
  }

  /**
   * Decreases the exponent of this {@code EncodedNumber} to {@code newExp}, if {@code newExp} is less than
   * the current {@code exponent}.
   * See {@link com.n1analytics.paillier.PaillierContext#decreaseExponentTo(EncodedNumber, int)} for details.
   *
   * @param newExp the new exponent for the {@code EncodedNumber}, must be less than the current exponent.
   * @return an {@code EncodedNumber} which exponent is equal to {@code newExp}.
   */
  public EncodedNumber decreaseExponentTo(int newExp) {
    return context.decreaseExponentTo(this, newExp);
  }

  /**
   * Encrypts this {@code EncodedNumber}. See
   * {@link com.n1analytics.paillier.PaillierContext#encrypt(EncodedNumber)} for details.
   *
   * @return the encrypted number.
   */
  public EncryptedNumber encrypt() {
    return context.encrypt(this);
  }

  /**
   * Adds an {@code EncryptedNumber} to this {@code EncodedNumber}. See
   * {@link com.n1analytics.paillier.PaillierContext#add(EncodedNumber, EncryptedNumber)} for details.
   *
   * @param other {@code EncryptedNumber} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds another {@code EncodedNumber} to this {@code EncodedNumber}. See
   * {@link com.n1analytics.paillier.PaillierContext#add(EncodedNumber, EncodedNumber)} for details.
   *
   * @param other {@code EncodedNumber} to be added.
   * @return the addition result.
   */
  public EncodedNumber add(EncodedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds a {@code BigInteger} to this {@code EncodedNumber}.
   *
   * @param other {@code EncodedNumber} to be added.
   * @return the addition result.
   */
  public EncodedNumber add(BigInteger other) {
    return add(context.encode(other));
  }

  /**
   * Adds a {@code double} to this {@code EncodedNumber}.
   *
   * @param other {@code double} to be added.
   * @return the addition result.
   */
  public EncodedNumber add(double other) {
    return add(context.encode(other));
  }

  /**
   * Adds a {@code long} to this {@code EncodedNumber}.
   *
   * @param other {@code long} to be added.
   * @return the addition result.
   */
  public EncodedNumber add(long other) {
    return add(context.encode(other));
  }

  /**
   * @return additive inverse of this {@code EncodedNumber}.
   */
  public EncodedNumber additiveInverse() {
    return context.additiveInverse(this);
  }

  /**
   * Subtracts an {@code EncryptedNumber} from this {@code EncodedNumber}.
   *
   * @param other {@code EncryptedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts another {@code EncodedNumber} from this {@code EncodedNumber}.
   *
   * @param other {@code EncodedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(EncodedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts a {@code BigInteger} from this {@code EncodedNumber}.
   *
   * @param other {@code BigInteger} to be subtracted from this {@code EncodedNumber}.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(BigInteger other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a {@code double} from this {@code EncodedNumber}.
   *
   * @param other {@code double} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(double other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a {@code long} from this {@code EncodedNumber}.
   *
   * @param other {@code long} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(long other) {
    // NOTE it would be nice to do add(context.encode(-other)) however this
    //      would fail if other == Long.MIN_VALUE since it has no
    //      corresponding positive value.
    return subtract(context.encode(other));
  }

  /**
   * Multiplies an {@code EncryptedNumber} with this {@code EncodedNumber}.
   *
   * @param other {@code EncryptedNumber} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncryptedNumber other) {
    return context.multiply(this, other);
  }

  /**
   * Multiplies another {@code EncodedNumber} with this {@code EncodedNumber}.
   *
   * @param other {@code EncodedNumber} to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(EncodedNumber other) {
    return context.multiply(this, other);
  }

  /**
   * Multiplies a {@code BigInteger} with this {@code EncodedNumber}.
   *
   * @param other {@code BigInteger} to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(BigInteger other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a {@code double} with this {@code EncodedNumber}.
   *
   * @param other {@code double} to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(double other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a {@code long} with this {@code EncodedNumber}.
   *
   * @param other {@code long} to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(long other) {
    return multiply(context.encode(other));
  }

  // TODO Issue #10
    /*
    public EncodedNumber multiplicativeInverse() {
    	return context.multiplicativeInverse(this);
    }

    public EncodedNumber divide(EncodedNumber other) {
    	return context.divide(this, other);
    }

    public EncodedNumber divide(Number other) {
    	return divide(context.encode(other));
    }

    public EncodedNumber divide(BigInteger other) {
    	return divide(context.encode(other));
    }
    */

  /**
   * Divides this {@code EncodedNumber} with a {@code double}.
   *
   * @param other {@code double} to divide this with.
   * @return the division result.
   */
  public EncodedNumber divide(double other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this {@code EncodedNumber} with a {@code long}.
   *
   * @param other {@code long} to divide this with.
   * @return the division result.
   */
  public EncodedNumber divide(long other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  @Override
  public int hashCode() {
    return new HashChain().chain(context).chain(value).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != EncodedNumber.class) {
      return false;
    }
    EncodedNumber number = (EncodedNumber) o;
    return context.equals(number.context) && value.equals(number.value);
  }

  public boolean equals(EncodedNumber o) {
    return o == this || (o != null &&
            context.equals(o.context) &&
            value.equals(o.value));
  }
}
