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

import com.n1analytics.paillier.util.BigIntegerUtil;
import com.n1analytics.paillier.util.HashChain;

/**
 * The PaillierContext combines an encoding scheme and a public key.
 * 
 * The encoding scheme used to convert numbers into unsigned 
 * integers for use in the Paillier cryptosystem.
 * 
 * There are several attributes that define an encoding scheme:
 * <ul>
 *   <li>
 *     A <code>PaillierPublicKey</code> used to generate this PaillierContext.
 *   </li>
 *   <li>
 *     A boolean <code>signed</code> that denotes whether the numbers
 *     represented are signed or unsigned.
 *   </li>
 *   <li>
 *     An integer <code>precision</code> that denotes the number of bits
 *     used to represent valid numbers that can be encrypted using
 *     the associated <code>PaillierPublicKey</code>. Setting this equal to the number
 *     of bits in the modulus results in the entire range of encoded numbers
 *     being valid, while setting it less than this results in a range of
 *     <code>(2<sup>precision</sup> + 1)</code> valid encoded numbers and
 *     <code>(modulus - 2<sup>precision</sup>)</code> invalid encoded numbers
 *     than can be used to (non-deterministically) detect overflows.
 *   </li>
 * </ul>
 *
 * PaillierContext defines methods:
 * <ul>
 *     <li>To check whether a BigInteger, long, double, Number or EncodedNumber is valid</li>
 *     <li>To encode a BigInteger, long, double and Number to an EncodedNumber</li>
 *     <li>To decode an EncodedNumber to a Number, BigInteger, long or double</li>
 *     <li>To encrypt a BigInteger, long, double, Number and EncodedNumber</li>
 *     <li>To perform arithmetic computation (support addition, subtraction,
 *     limited multiplication and limited division)</li>
 *     <li>To check whether another PaillierContext is the same as this PaillierContext</li>
 * </ul>
 *
 * Note you can create a PaillierContext directly from the create methods
 * on a PaillierPublicKey e.g., {@link PaillierPublicKey#createSignedContext()}.
 */
public class PaillierContext {

  /**
   * The default base value.
   */
  protected static final int DEFAULT_BASE = 16;

  /**
   * The public key associated with this PaillierContext.
   */
  private final PaillierPublicKey publicKey;

  /**
   * The encoding scheme associated with this PaillierContext.
   */
  private final EncodingScheme encoding;

  
  /**
   * Constructs a Paillier context using the  {@code DEFAULT_BASE}.
   *
   * @param publicKey associated with this PaillierContext.
   * @param signed to denote whether this PaillierContext supports signed or unsigned numbers.
   * @param precision to denote the number of bits used to represent valid numbers.
   */
  public PaillierContext(PaillierPublicKey publicKey, boolean signed, int precision) {
    this(publicKey, signed, precision, DEFAULT_BASE);
  }
  
  /**
   * Constructs a Paillier context
   *
   * The method also derives the minimum/maximum {@code value} of {@code EncodedNumber} and
   * the minimum/maximum values that can be encoded and encrypted using the {@code PaillierPublicKey}.
   *
   * @param publicKey associated with this PaillierContext.
   * @param signed to denote whether this PaillierContext supports signed or unsigned numbers.
   * @param precision to denote the number of bits used to represent valid numbers.
   * @param base to denote the selected base used for encoding, the value must be greater than or equal to 2.
   */
  public PaillierContext(PaillierPublicKey publicKey, boolean signed, int precision, int base) {
    if (publicKey == null) {
      throw new NullPointerException("publicKey must not be null");
    }
    this.publicKey = publicKey;
    this.encoding = new StandardEncodingScheme(this, signed, precision, base);
  }
  
  
  public PaillierContext(PaillierPublicKey publicKey, EncodingScheme encoding) {
    if (publicKey == null) {
      throw new NullPointerException("publicKey must not be null");
    }
    this.publicKey = publicKey;
    this.encoding = encoding;
  }

  /**
   * @return public key of this PaillierContext.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }
  
  /**
   * @return the encoding scheme of this PaillierContext
   */
  public EncodingScheme getEncodingScheme() {
    return encoding;
  }

  /**
   * @return encoding base used in this PaillierContext.
   */
  public int getBase() { return encoding.getBase(); }

  /**
   * Checks whether this PaillierContext supports signed numbers.
   *
   * @return true if this PaillierContext support signed numbers, false otherwise.
   */
  public boolean isSigned() {
    
    return encoding.isSigned();
  }

  /**
   * Checks whether this PaillierContext supports unsigned numbers.
   *
   * @return true if this PaillierContext support unsigned numbers, false otherwise.
   */
  public boolean isUnsigned() {
    return !isSigned();
  }

  /**
   * @return the precision of this PaillierContext.
   */
  public int getPrecision() {
    return encoding.getPrecision();
  }

  /**
   * Checks whether this PaillierContext has full precision.
   *
   * @return true if this PaillierContext has full precision, false otherwise.
   */
  public boolean isFullPrecision() {
    return getPrecision() == publicKey.getModulus().bitLength();
  }

  /**
   * @return the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMaxEncoded() {
    return encoding.getMaxEncoded();
  }

  /**
   * @return the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMinEncoded() {
    return encoding.getMinEncoded();
  }

  /**
   * @return the maximum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMaxSignificand() {
    return encoding.getMaxSignificand();
  }

  /**
   * @return the minimum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMinSignificand() {
    return encoding.getMinSignificand();
  }

  /**
   * Checks whether another {@code PaillierContext} is the same as this {@code PaillierContext}.
   *
   * @param context the {@code PaillierContext} to be compared to.
   * @throws PaillierContextMismatchException if the other {@code context} is not the same
   * as this {@code PaillierContext}.
   */
  public void checkSameContext(PaillierContext context)
          throws PaillierContextMismatchException {
    if (this == context) {
      return;
    }
    if (!publicKey.equals(context.publicKey)) {
      throw new PaillierContextMismatchException("These PaillierContexts have diffenent public keys");
    }
    if (!encoding.equals(context.encoding)) {
      throw new PaillierContextMismatchException("These PaillierContexts have diffenent encoding schemes");
    }
  }

  /**
   * Checks whether an {@code EncryptedNumber} has the same context as this {@code PaillierContext}.
   * Returns the unmodified {@code EncryptedNumber} so that it can be called inline.
   *
   * @param other the {@code EncryptedNumber} to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException If {@code other} has a
   * different context to this {@code PaillierContext}.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    checkSameContext(other.getContext());
    return other;
  }

  /**
   * Checks whether an {@code EncodedNumber} has the same context as this {@code PaillierContext}.
   * Returns the unmodified {@code EncodedNumber} so that it can be called inline.
   *
   * @param encoded the {@code EncodedNumber} to compare to.
   * @return {@code encoded}
   * @throws PaillierContextMismatchException If{@code encoded} has a
   * different context to this {@code PaillierContext}.
   */
  public EncodedNumber checkSameContext(EncodedNumber encoded)
          throws PaillierContextMismatchException {
    checkSameContext(encoded.getContext());
    return encoded;
  }

  /**
   * Checks whether an {@code EncodedNumber}'s {@code value} is valid, that is the {@code value}
   * can be encrypted using the associated {@code publicKey}. 
   * 
   * For an unsigned {@code PaillierContext}, a valid {@code value} is less than or equal 
   * to {@code maxEncoded}. While for a signed {@code PaillierContext}, a valid {@code value} 
   * is less than or equal to {@code maxEncoded} (for positive numbers) or is greater than or 
   * equal to {@code minEncoded} (for negative numbers).
   *
   * @param encoded the {@code EncodedNumber} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(EncodedNumber encoded) {
    return encoding.isValid(encoded);
  }

  /**
   * Encodes a {@code BigInteger} using this {@code PaillierContext}. Throws EncodeException if the input
   * value is greater than {@code maxSignificand} or is less than {@code minSignificand}.
   *
   * @param value the {@code BigInteger} to be encoded.
   * @return the encoding result - {@code EncodedNumber}
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigInteger value) throws EncodeException {
    return encoding.encode(value);
  }

  /**
   * Encodes a {@code double} using this {@code PaillierContext}. If the input value is not valid (that is
   * if {@code value} is infinite, is a NaN, or is negative when this context is unsigned) then throw
   * EncodeException.
   *
   * @param value the {@code double} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(double value) throws EncodeException {
    return encoding.encode(value);
  }

  /**
   * Encodes a {@code double} given a {@code maxExponent} using this {@code PaillierContext}.
   *
   * @param value the {@code double} to be encoded.
   * @param maxExponent the maximum exponent to encode the {@code value} with. The exponent of
   *                    the resulting {@code EncodedNumber} will be at most equal to {@code maxExponent}.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, int maxExponent) throws EncodeException {
    return encoding.encode(value, maxExponent);
  }

  /**
   * Encodes a {@code double} given a {@code precision} using this {@code PaillierContext}.
   *
   * @param value the {@code double} to be encoded.
   * @param precision denotes how different is the {@code value} from 0,
   *                  {@code precision}'s value is between 0 and 1.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, double precision) throws EncodeException{
    return encoding.encode(value, precision);
  }

  /**
   * Encodes a {@code long} using this {@code PaillierContext}.
   *
   * @param value the {@code long} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(long value) throws EncodeException {
    return encode(BigInteger.valueOf(value));
  }
  
  public EncodedNumber encode(BigDecimal value) throws EncodeException {
    return encoding.encode(value);
  }

  /**
   * Returns the signum function of this EncodedNumber.
   * @return -1, 0 or 1 as the value of this EncodedNumber is negative, zero or positive.
   */
  public int signum(EncodedNumber number){
    return encoding.signum(number);
  }

  

  /**
   * Returns the rescaling factor to re-encode an {@code EncodedNumber} using the same {@code base}
   * but with a different {@code exponent}. The rescaling factor is computed as <code>base</code><sup>expDiff</sup>.
   *
   * @param expDiff the exponent to for the new rescaling factor.
   * @return the rescaling factor.
   */
  public BigInteger getRescalingFactor(int expDiff) {
    return encoding.getRescalingFactor(expDiff);
  }

  /**
   * Decreases the exponent of an {@code EncodedNumber} to {@code newExp}. If {@code newExp} is greater than
   * the {@code EncodedNumber}'s current {@code exponent}, throws an IllegalArgumentException.
   *
   * @param encodedNumber the {@code EncodedNumber} which {@code exponent} will be reduced.
   * @param newExp the new {@code exponent}, must be less than the current {@code exponent}.
   * @return an {@code EncodedNumber} representing the same value with {@code exponent} equals to {@code newExp}.
   */
  public EncodedNumber decreaseExponentTo(EncodedNumber encodedNumber, int newExp) {
    BigInteger significand = encodedNumber.getValue();
    int exponent = encodedNumber.getExponent();
    if(newExp > exponent){
      throw new IllegalArgumentException("New exponent: "+ newExp +
              "should be more negative than old exponent: " + exponent + ".");
    }

    int expDiff = exponent - newExp;
    BigInteger bigFactor = getRescalingFactor(expDiff);
    BigInteger newEnc = significand.multiply(bigFactor).mod(publicKey.getModulus());
    return new EncodedNumber(this, newEnc, newExp);
  }

  /**
   * Decreases the exponent of an {@code EncryptedNumber} to {@code newExp}. If {@code newExp} is greater than
   * the {@code EncryptedNumber}'s current {@code exponent}, throws an IllegalArgumentException.
   *
   * @param encryptedNumber the {@code EncryptedNumber} which {@code exponent} will be reduced.
   * @param newExp the new {@code exponent}, must be less than the current {@code exponent}.
   * @return an {@code EncryptedNumber} representing the same value with {@code exponent} equals to {@code newExp}.
   */
  public EncryptedNumber decreaseExponentTo(EncryptedNumber encryptedNumber, int newExp) {
    int exponent = encryptedNumber.getExponent();
    if(newExp > exponent){
      throw new IllegalArgumentException("New exponent: "+ newExp +
              "should be more negative than old exponent: " + exponent + ".");
    }

    int expDiff = exponent - newExp;
    BigInteger bigFactor = getRescalingFactor(expDiff);
    BigInteger newEnc = publicKey.raw_multiply(encryptedNumber.ciphertext, bigFactor);
    return new EncryptedNumber(this, newEnc, newExp, encryptedNumber.isSafe);
  }


  /**
   * Decodes to the exact {@code BigInteger} representation.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
    return encoding.decodeBigInteger(encoded);
  }

  /**
   * Decodes to the exact {@code double} representation. Throws DecodeException if the decoded result
   * is {@link java.lang.Double#POSITIVE_INFINITY}, {@link java.lang.Double#NEGATIVE_INFINITY} or
   * {@link java.lang.Double#NaN}.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public double decodeDouble(EncodedNumber encoded) throws DecodeException {
    return encoding.decodeDouble(encoded);
  }

  /**
   * Decodes to the exact {@code long} representation. Throws DecodeException if the decoded result
   * is greater than {@link java.lang.Long#MAX_VALUE} or less than {@link java.lang.Long#MIN_VALUE}.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public long decodeLong(EncodedNumber encoded) throws DecodeException {
    return encoding.decodeLong(encoded);
  }
  
  public BigDecimal decodeBigDecimal(EncodedNumber encoded) throws DecodeException {
    return encoding.decodeBigDecimal(encoded);
  }

  /**
   * Obfuscates an {@code EncryptedNumber}.
   *
   * @param encrypted the {@code EncryptedNumber} to be obfuscated.
   * @return the obfuscated {@code EncryptedNumber}.
   */
  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    checkSameContext(encrypted);
    
    final BigInteger obfuscated = publicKey.raw_obfuscate(encrypted.ciphertext);
    return new EncryptedNumber(this, obfuscated, encrypted.getExponent(), true);
  }

  /**
   * Encrypts an {@code EncodedNumber}.
   *
   * Checks whether the {@code EncodedNumber} to be encrypted has the same context as this {@code PaillierContext}.
   * Encrypts the {@code EncodedNumber}'s {@code value}. Note that the {@code exponent} is not encrypted and
   * the result {@code EncryptedNumber} is not obfuscated.
   *
   * @param encoded the {@code EncodedNumber} to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(EncodedNumber encoded) {
    checkSameContext(encoded);
    final BigInteger value = encoded.getValue();
    final BigInteger ciphertext = publicKey.raw_encrypt_without_obfuscation(value);
    return new EncryptedNumber(this, ciphertext, encoded.getExponent(), false);
  }

  /**
   * Encrypts a {@code BigInteger}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(BigInteger value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a {@code double}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(double value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a {@code long}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(long value) {
    return encrypt(encode(value));
  }

  /**
   * Adds two EncryptedNumbers. Checks whether the {@code PaillierContext} of {@code operand1}
   * and {@code operand2} are the same as this {@code PaillierContext}. If the operands' exponents
   * are not the same, reduce the higher exponent to match with the lower exponent.
   *
   * @param operand1 first {@code EncryptedNumber}.
   * @param operand2 second {@code EncryptedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.ciphertext;
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = publicKey.raw_multiply(value1, getRescalingFactor(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = publicKey.raw_multiply(value2, getRescalingFactor(exponent2 - exponent1));
    } // else do nothing
    final BigInteger result = publicKey.raw_add(value1, value2);
    return new EncryptedNumber(this, result, exponent1, operand1.isSafe && operand2.isSafe);
  }

  /**
   * Adds an {@code EncryptedNumber} and an {@code EncodedNumber}. Encrypts the {@code EncodedNumber}
   * before adding them together.
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    //addition only works if both numbers have the same exponent. Adjusting the exponent of an 
    //encrypted number can only be done with an encrypted multiplication (internally, this is
    //done with a modular exponentiation). 
    //It is going to be computationally much cheaper to adjust the encoded number before the 
    //encryption as we only need to do a modular multiplication.
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    BigInteger value2 = operand2.value;
    if(exponent1 < exponent2){
      value2 = value2.multiply(getRescalingFactor(exponent2-exponent1)).mod(publicKey.getModulus());
      return add(operand1, encrypt(new EncodedNumber(this, value2, exponent1)));
    }
    if(exponent1 > exponent2 && operand2.signum() == 1){
      //test if we can shift value2 to the right without loosing information
      //Note, this only works for positive values.
      boolean canShift = value2.mod(getRescalingFactor(exponent1-exponent2)).equals(BigInteger.ZERO);
      if(canShift){
        value2 = value2.divide(getRescalingFactor(exponent1-exponent2));
        return add(operand1, encrypt(new EncodedNumber(this, value2, exponent1)));
      }
    }
    return add(operand1, encrypt(operand2));
  }

  /**
   * Adds an {@code EncodedNumber} and an {@code EncryptedNumber}. Encrypts the {@code EncodedNumber}
   * before adding them together.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand2, operand1);
  }

  /**
   * Adds two {@code EncodedNumber}s. Checks whether the {@code PaillierContext} of {@code operand1}
   * and {@code operand2} are the same as this {@code PaillierContext}. If the operands' exponents
   * are not the same, reduce the higher exponent to match with the lower exponent.
   *
   * @param operand1 first {@code EncodedNumber}.
   * @param operand2 second {@code EncodedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this{@code PaillierContext}.
   */
  public EncodedNumber add(EncodedNumber operand1, EncodedNumber operand2)
  throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = publicKey.getModulus();
    BigInteger value1 = operand1.getValue();
    BigInteger value2 = operand2.getValue();
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = value1.multiply(getRescalingFactor(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.multiply(getRescalingFactor(exponent2 - exponent1));
    }
    final BigInteger result = value1.add(value2).mod(modulus);
    return new EncodedNumber(this, result, exponent1);
  }

  /**
   * Returns the additive inverse of {@code EncryptedNumber}.
   *
   * @param operand1 input.
   * @return the additive inverse result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of {@code operand1}
   * is not the same as this {@code PaillierContext}.
   */
  public EncryptedNumber additiveInverse(EncryptedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(), BigIntegerUtil.modInverse(operand1.ciphertext,
            operand1.getContext().getPublicKey().getModulusSquared()),
                               operand1.getExponent(), operand1.isSafe);
  }

  /**
   * Returns the additive inverse of an {@code EncodedNumber}.
   *
   * @param operand1 input.
   * @return the additive inverse.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of {@code operand1}
   * is not the same as this {@code PaillierContext}.
   */
  public EncodedNumber additiveInverse(EncodedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    if (operand1.getValue().signum() == 0) {
      return operand1;
    }
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger result = modulus.subtract(value1);
    return new EncodedNumber(this, result, operand1.getExponent());
  }

  /**
   * Subtracts an {@code EncryptedNumber} ({@code operand2}) from another {@code EncryptedNumber} ({@code operand1}).
   *
   * @param operand1 first {@code EncryptedNumber}.
   * @param operand2 second {@code EncryptedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    // TODO Issue #9: optimise
    checkSameContext(operand1);
    checkSameContext(operand2);
    return add(operand1, additiveInverse(operand2));
  }

  /**
   * Subtracts an {@code EncodedNumber} ({@code operand2}) from an {@code EncryptedNumber} ({@code operand1}).
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2.additiveInverse()));
  }

  /**
   * Subtracts an {@code EncryptedNumber} ({@code operand2}) from an {@code EncodedNumber} ({@code operand1}).
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return subtract(encrypt(operand1), operand2);
  }

  /**
   * Subtracts an {@code EncodedNumber} ({@code operand2}) from another {@code EncodedNumber} ({@code operand1}).
   *
   * @param operand1 first {@code EncodedNumber}.
   * @param operand2 second {@code EncodedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncodedNumber subtract(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, operand2.additiveInverse());
  }

  /**
   * Multiplies an EncyptedNumber with an {@code EncodedNumber}.
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber multiply(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.getValue();
    BigInteger neg_plain = publicKey.getModulus().subtract(value2);
    // If the plaintext is large, exponentiate using its negative instead.
    if (neg_plain.compareTo(encoding.getMaxEncoded()) <= 0) {
        value1 = BigIntegerUtil.modInverse(value1, publicKey.getModulusSquared());
        value2 = neg_plain;
    }
    final BigInteger result = publicKey.raw_multiply(value1, value2);
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncryptedNumber(this, result, exponent, operand1.isSafe);
  }

  /**
   * Multiplies an {@code EncodedNumber} with an {@code EncryptedNumber}.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber multiply(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return multiply(operand2, operand1);
  }

  /**
   * Multiplies two {@code EncodedNumber}s.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncodedNumber multiply(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = value1.multiply(value2).mod(modulus);
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncodedNumber(this, result, exponent);
  }
  
  /**
   * returns a random {@code EncodedNumber}, consisting of a significant, chosen uniformly 
   * at random out of the message space and an exponent specified in parameter (@code exponent}.
   * @param exponent
   * @return a random EncodedNumber
   */
  public EncodedNumber randomEncodedNumber(int exponent){
    return new EncodedNumber(this, BigIntegerUtil.randomPositiveNumber(publicKey.getModulus()), exponent);
  }


  // TODO Issue #10
  /*
	public EncodedNumber multiplicativeInverse(EncodedNumber operand1) throws
		PaillierContextMismatchException
	{
		checkSameContext(operand1);
		return encode(operand1.decode().multiplicativeInverse());
	}

	public EncryptedNumber divide(
		EncryptedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		return divideUnsafe(operand1, operand2).obfuscate();
	}

	public EncodedNumber divide(
		EncodedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		return multiply(operand1, multiplicativeInverse(operand2));
	}

	EncryptedNumber divideUnsafe(
		EncryptedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		checkSameContext(operand1);
		checkSameContext(operand2);
		return multiplyUnsafe(operand1, multiplicativeInverse(operand2));
	}
	*/

  @Override
  public int hashCode() {
    return new HashChain().chain(publicKey).chain(encoding).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != PaillierContext.class) {
      return false;
    }
    PaillierContext context = (PaillierContext) o;
    return publicKey.equals(context.publicKey) &&
            encoding.equals(context.encoding);
  }

  public boolean equals(PaillierContext o) {
    return o == this || (o != null &&
            publicKey.equals(o.publicKey) &&
            encoding.equals(o.encoding));
  }
}
