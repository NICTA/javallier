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
import com.n1analytics.paillier.util.HashChain;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

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

  // Source: http://docs.oracle.com/javase/specs/jls/se7/html/jls-4.html#jls-4.2.3
  private static final int DOUBLE_MANTISSA_BITS = 53;

  /**
   * The public key associated with this PaillierContext.
   */
  private final PaillierPublicKey publicKey;

  /**
   * Denotes whether the numbers represented are signed or unsigned.
   */
  private final boolean signed;

  /**
   * The precision of this PaillierContext, denotes the number of bits used to represent valid numbers
   * that can be encrypted using the associated {@code publicKey}.
   */
  private final int precision;

  /**
   * The maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger maxEncoded;

  /**
   * The minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger minEncoded;

  /**
   * The maximum value that can be encoded and encrypted using the associated {@code publicKey}.
   */
  private final BigInteger maxSignificand;

  /**
   * The minimum value that can be encoded and encrypted using the associated {@code publicKey}.
   */
  private final BigInteger minSignificand;

  /**
   * The base used to compute encoding.
   */
  private final int base;

  /**
   * The result of log<sub>2</sub>base.
   */
  private final double log2Base;

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
    if (precision < 1) {
      throw new IllegalArgumentException("Precision must be greater than zero");
    }
    if (signed && precision < 2) {
      throw new IllegalArgumentException(
              "Precision must be greater than one when signed is true");
    }

    final int modulusBitLength = publicKey.getModulus().bitLength();
    if (precision > modulusBitLength) {
      throw new IllegalArgumentException(
              "Precision must be less than or equal to the number of bits in the modulus");
    }

    if (base < 2) {
      throw new IllegalArgumentException(
              "Base must be at least equals to 2.");
    }

    this.publicKey = publicKey;
    this.signed = signed;
    this.precision = precision;
    this.base = base;
    this.log2Base = Math.log((double) base)/ Math.log(2.0);

    // Determines the appropriate values for maxEncoded, minEncoded,
    // maxSignificand, and minSignificand based on the signedness and
    // precision of the encoding scheme
    final boolean fullPrecision = precision == modulusBitLength;
    if (signed) {
      if (fullPrecision) {
        maxEncoded = publicKey.getModulus().shiftRight(1);
      } else {
        maxEncoded = BigInteger.ONE.shiftLeft(precision - 1).subtract(BigInteger.ONE);
      }
      minEncoded = publicKey.getModulus().subtract(maxEncoded);
      maxSignificand = maxEncoded;
      minSignificand = maxEncoded.negate();
    } else {
      if (fullPrecision) {
        maxEncoded = publicKey.getModulus().subtract(BigInteger.ONE);
      } else {
        maxEncoded = BigInteger.ONE.shiftLeft(precision).subtract(BigInteger.ONE);
      }
      minEncoded = BigInteger.ZERO;
      maxSignificand = maxEncoded;
      minSignificand = BigInteger.ZERO;
    }
  }

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
   * @return public key of this PaillierContext.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * @return encoding base used in this PaillierContext.
   */
  public int getBase() { return base; }

  /**
   * Checks whether this PaillierContext supports signed numbers.
   *
   * @return true if this PaillierContext support signed numbers, false otherwise.
   */
  public boolean isSigned() {
    return signed;
  }

  /**
   * Checks whether this PaillierContext supports unsigned numbers.
   *
   * @return true if this PaillierContext support unsigned numbers, false otherwise.
   */
  public boolean isUnsigned() {
    return !signed;
  }

  /**
   * @return the precision of this PaillierContext.
   */
  public int getPrecision() {
    return precision;
  }

  /**
   * Checks whether this PaillierContext has full precision.
   *
   * @return true if this PaillierContext has full precision, false otherwise.
   */
  public boolean isFullPrecision() {
    return precision == publicKey.getModulus().bitLength();
  }

  /**
   * @return the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  /**
   * @return the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  /**
   * @return the maximum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  /**
   * @return the minimum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMinSignificand() {
    return minSignificand;
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
      throw new PaillierContextMismatchException();
    }
    if (signed != context.signed) {
      throw new PaillierContextMismatchException();
    }
    if (precision != context.precision) {
      throw new PaillierContextMismatchException();
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
    // NOTE signed == true implies minEncoded > maxEncoded
    if (!equals(encoded.getContext())) {
      return false;
    }
    if (encoded.getValue().compareTo(maxEncoded) <= 0) {
      return true;
    }
    if (signed && encoded.getValue().compareTo(minEncoded) >= 0) {
      return true;
    }
    return false;
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
    if (BigIntegerUtil.greater(value, maxSignificand) || BigIntegerUtil.less(value, minSignificand)) {
      throw new EncodeException("Input value cannot be encoded.");
    }

    int exponent = 0;
    if(value.signum() < 0)
      value = value.add(publicKey.getModulus());
    return new EncodedNumber(this, value, exponent);
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
    if(Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if(value < 0 && isUnsigned())
      throw new EncodeException("Input value cannot be encoded using this Paillier context.");

    int exponent = getDoublePrecExponent(value);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value), exponent), exponent);
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
    if(Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if(value < 0 && isUnsigned())
      throw new EncodeException("Input value is not valid for this Paillier context.");

    int exponent = getExponent(getDoublePrecExponent(value), maxExponent);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value),
            getExponent(getDoublePrecExponent(value), maxExponent)), exponent);
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
  public EncodedNumber encode(double value, double precision) {
    if(Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if(value < 0 && isUnsigned())
      throw new EncodeException("Input value is not valid for this Paillier context.");

    if (precision > 1 || precision <= 0)
      throw new EncodeException("Precision must be 10^-i where i > 0.");

    int exponent = getPrecExponent(precision);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value), exponent), exponent);
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

  /**
   * Returns an exponent derived from precision. The exponent is calculated as
   * <code>floor(log<sub>base</sub>precision)</code>.
   *
   * @param precision input precision used to generate an exponent.
   * @return exponent for this {@code precision}.
   */
  private int getPrecExponent(double precision) {
    return (int) Math.floor(Math.log(precision) / Math.log((double) base));
  }

  /**
   * Returns an exponent for a double value.
   *
   * @param value input double value to be encoded.
   * @return exponent for the input double value.
   */
  private int getDoublePrecExponent(double value) {
    int binFltExponent = Math.getExponent(value) + 1;
    int binLsbExponent = binFltExponent - DOUBLE_MANTISSA_BITS;
    return (int) Math.floor((double) binLsbExponent / log2Base);
  }

  /**
   * Given an exponent derived from precision and another exponent denoting the maximum desirable exponent,
   * returns the smaller of the two.
   *
   * @param precExponent denotes the exponent derived from precision.
   * @param maxExponent denotes the max exponent given.
   * @return the smaller exponent.
   */
  private int getExponent(int precExponent, int maxExponent){
    return Math.min(precExponent, maxExponent);
  }
  
  /**
   * Returns the signum function of this EncodedNumber.
   * @return -1, 0 or 1 as the value of this EncodedNumber is negative, zero or positive.
   */
  public int signum(EncodedNumber number){
    if(number.value.equals(BigInteger.ZERO)){
      return 0;
    }
    if(isUnsigned()){
      return 1;
    }
    //if this context is signed, then a negative significant is strictly greater 
    //than modulus/2.
    BigInteger halfModulus = getPublicKey().modulus.shiftRight(1);
    return number.value.compareTo(halfModulus) > 0 ? -1 : 1;
  }

  /**
   * Returns an integer ({@code BigInteger}) representation of a floating point number.
   * The integer representation is computed as <code>value * base<sup>exponent</sup></code> for non-negative
   * numbers and <code>modulus + (value * base<sup>exponent</sup>)</code> for negative numbers.
   *
   * @param value a floating point number to be encoded.
   * @param exponent the exponent to encode the number.
   * @return the integer representation of the input floating point number.
   */
  private BigInteger innerEncode(BigDecimal value, int exponent) {
    // Compute BASE^(-exponent)
    BigDecimal bigDecBaseExponent = (new BigDecimal(base)).pow(-exponent, MathContext.DECIMAL128);

    // Compute the integer representation, ie, value * (BASE^-exponent)
    BigInteger bigIntRep =
            ((value.multiply(bigDecBaseExponent)).setScale(0, BigDecimal.ROUND_HALF_UP)).toBigInteger();

    if(BigIntegerUtil.greater(bigIntRep, maxSignificand) ||
            (value.signum() < 0 && BigIntegerUtil.less(bigIntRep, minSignificand))) {
      throw new EncodeException("Input value cannot be encoded.");
    }

    if (bigIntRep.signum() < 0) {
      bigIntRep = bigIntRep.add(publicKey.getModulus());
    }

    return bigIntRep;
  }

  /**
   * Returns the rescaling factor to re-encode an {@code EncodedNumber} using the same {@code base}
   * but with a different {@code exponent}. The rescaling factor is computed as <code>base</code><sup>expDiff</sup>.
   *
   * @param expDiff the exponent to for the new rescaling factor.
   * @return the rescaling factor.
   */
  public BigInteger getRescalingFactor(int expDiff) {
    return (BigInteger.valueOf(base)).pow(expDiff);
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
   * Returns the value of an {@code EncodedNumber} for decoding. Throws a DecodeException if the value is
   * greater than the {@code publicKey}'s {@code modulus}. If the value is less than or equal to
   * {@code maxEncoded}, return the value. If the {@code PaillierContext} is signed and the value is
   * less than or equal to {@code minEncoded}, return the value subtracted by {@code publicKey}'s
   * {@code modulus}. Otherwise the significand is in the overflow region and hence throws a DecodeException.
   *
   * @param encoded the input {@code EncodedNumber}.
   * @return the significand of the {@code EncodedNumber}.
   */
  private BigInteger getSignificand(EncodedNumber encoded) {
    checkSameContext(encoded);
    final BigInteger value = encoded.getValue();

    if(value.compareTo(publicKey.getModulus()) > 0)
      throw new DecodeException("The significand of the encoded number is corrupted");

    // Non-negative
    if (value.compareTo(maxEncoded) <= 0) {
      return value;
    }

    // Negative - note that negative encoded numbers are greater than
    // non-negative encoded numbers and hence minEncoded > maxEncoded
    if (signed && value.compareTo(minEncoded) >= 0) {
      final BigInteger modulus = publicKey.getModulus();
      return value.subtract(modulus);
    }

    throw new DecodeException("Detected overflow");
  }

  /**
   * Decodes to the exact {@code BigInteger} representation.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
    BigInteger significand = getSignificand(encoded);
    return significand.multiply(BigInteger.valueOf(base).pow(encoded.getExponent()));
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
    BigInteger significand = getSignificand(encoded);
    double decoded = significand.doubleValue() * Math.pow((double) base, (double) encoded.getExponent());

    if(Double.isInfinite(decoded) || Double.isNaN(decoded)) {
      throw new DecodeException("Decoded value cannot be represented as double.");
    }
    return decoded;
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
    BigInteger decoded = decodeBigInteger(encoded);
    if(BigIntegerUtil.less(decoded, BigIntegerUtil.LONG_MIN_VALUE) ||
            BigIntegerUtil.greater(decoded, BigIntegerUtil.LONG_MAX_VALUE)) {
      throw new DecodeException("Decoded value cannot be represented as long.");
    }
    return decoded.longValue();

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
    return new EncryptedNumber(operand1.getContext(), operand1.ciphertext.modInverse(
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
    final BigInteger value1 = operand1.ciphertext;
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = publicKey.raw_multiply(value1, value2);
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncryptedNumber(this, result, exponent);
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
    return new HashChain().chain(publicKey).chain(signed).chain(precision).hashCode();
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
            signed == context.signed &&
            precision == context.precision;
  }

  public boolean equals(PaillierContext o) {
    return o == this || (o != null &&
            publicKey.equals(o.publicKey) &&
            signed == o.signed &&
            precision == o.precision);
  }
}
