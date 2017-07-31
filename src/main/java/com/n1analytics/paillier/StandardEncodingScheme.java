package com.n1analytics.paillier;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;

import com.n1analytics.paillier.util.BigIntegerUtil;
import com.n1analytics.paillier.util.HashChain;

public class StandardEncodingScheme implements EncodingScheme{
  
  //Source: http://docs.oracle.com/javase/specs/jls/se7/html/jls-4.html#jls-4.2.3
  private static final int DOUBLE_MANTISSA_BITS = 53;
  
  /**
   * The result of log<sub>2</sub>base.
   */
  private final double log2Base;
   
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
  
  private final PaillierContext context;
  
  public StandardEncodingScheme(PaillierContext context, boolean signed, int precision, int base){
    this.context = context;
    this.signed = signed;
    if (base < 2) {
      throw new IllegalArgumentException("Base must be at least equals to 2.");
    }
    this.base =base;
    this.log2Base = Math.log((double) base)/ Math.log(2.0);
    BigInteger modulus = context.getPublicKey().getModulus();
    if(modulus.bitLength() < precision || precision < 1) {
      throw new IllegalArgumentException("Precision must be greater than zero and less than or equal to the number of bits in the modulus");
    }
    if (signed && precision < 2) {
      throw new IllegalArgumentException(
              "Precision must be greater than one when signed is true");
    }
    this.precision = precision;
    BigInteger encSpace = modulus.bitLength() == precision ? modulus : BigInteger.ONE.shiftLeft(precision);
    if (signed) {
      maxEncoded = encSpace.add(BigInteger.ONE).shiftRight(1).subtract(BigInteger.ONE);   
      minEncoded = modulus.subtract(maxEncoded);
      maxSignificand = maxEncoded;
      minSignificand = maxEncoded.negate();
    } else {
      maxEncoded = encSpace.subtract(BigInteger.ONE);
      minEncoded = BigInteger.ZERO;
      maxSignificand = maxEncoded;
      minSignificand = BigInteger.ZERO;
    }
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
    if (value == null) {
      throw new EncodeException("cannot encode 'null'");
    }
    if(value.compareTo(BigInteger.ZERO) < 0 && isUnsigned()) {
      throw new EncodeException("Input value cannot be encoded using this EncodingScheme.");
    }
    int exponent = 0;
    if (!value.equals(BigInteger.ZERO)) {
      while (value.mod(BigInteger.valueOf(base)).equals(BigInteger.ZERO)) {
        value = value.divide(BigInteger.valueOf(base));
        exponent++;
      }
    }
    if (BigIntegerUtil.greater(value, maxSignificand) || BigIntegerUtil.less(value, minSignificand)) {
      throw new EncodeException("Input value cannot be encoded.");
    }
    if(value.signum() < 0)
      value = value.add(context.getPublicKey().getModulus()); 
    return new EncodedNumber(context, value, exponent);
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
      throw new EncodeException("Input value cannot be encoded using this EncodingScheme.");

    int exponent = value == 0 ? 0 : getDoublePrecExponent(value);
    return new EncodedNumber(context, innerEncode(new BigDecimal(value), exponent), exponent);
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
    return new EncodedNumber(context, innerEncode(new BigDecimal(value),
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
  public EncodedNumber encode(double value, double precision) throws EncodeException{
    if(Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if(value < 0 && isUnsigned())
      throw new EncodeException("Input value is not valid for this Paillier context.");

    if (precision > 1 || precision <= 0)
      throw new EncodeException("Precision must be 10^-i where i > 0.");

    int exponent = getPrecExponent(precision);
    return new EncodedNumber(context, innerEncode(new BigDecimal(value), exponent), exponent);
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
    return encode(value, BIG_DECIMAL_ENCODING_PRECISION);
  }
  
  public EncodedNumber encode(BigDecimal value, int precision) throws EncodeException {
    if (value == null) {
      throw new EncodeException("cannot encode 'null'");
    }
    if(value.compareTo(BigDecimal.ZERO) < 0 && isUnsigned()) {
      throw new EncodeException("Input value cannot be encoded using this EncodingScheme.");
    }
    if (base == 10) {
      BigInteger significant;
      int exp = -value.scale();
      if (value.scale() > 0) {
        significant = value.scaleByPowerOfTen(value.scale()).toBigInteger();
      } else {
        significant = value.unscaledValue();
      }
      if (BigIntegerUtil.greater(significant, maxSignificand) || BigIntegerUtil.less(significant, minSignificand)) {
        throw new EncodeException("Input value cannot be encoded.");
      }
      if (significant.signum() < 0) {
        significant = context.getPublicKey().getModulus().add(significant);
      }
      return new EncodedNumber(context, significant, exp);
    } else {
      if (value.scale() > 0) { //we've got a fractional part
        BigDecimal EPSILON = new BigDecimal(BigInteger.ONE, precision); //that's the max relative error we are willing to accept
        MathContext mc = new MathContext(precision + 1, RoundingMode.HALF_EVEN);
        int newExponent = (int)Math.floor(logBigDecimal(value.multiply(EPSILON, mc), base));
        BigDecimal newValue = newExponent < 0 ? value.multiply(BigDecimal.valueOf(base).pow(-newExponent, mc), mc) : value.divide(BigDecimal.valueOf(base).pow(newExponent, mc), mc);
        BigInteger significant = newValue.setScale(0, RoundingMode.HALF_EVEN).unscaledValue();
        if (BigIntegerUtil.greater(significant, maxSignificand) || BigIntegerUtil.less(significant, minSignificand)) {
          throw new EncodeException("Input value cannot be encoded.");
        }
        if (significant.signum() < 0) {
          significant = context.getPublicKey().getModulus().add(significant);
        }
        return new EncodedNumber(context, significant, newExponent);
      } else {
        //so we can turn it into a BigInteger without precision loss
        return encode(value.toBigInteger());
      }
    }
  }
  
  /**
   * Checks whether this EncodingScheme supports signed numbers.
   *
   * @return true if this EncodingScheme support signed numbers, false otherwise.
   */
  public boolean isSigned() {
    return signed;
  }

  /**
   * Checks whether this EncodingScheme supports unsigned numbers.
   *
   * @return true if this EncodingScheme support unsigned numbers, false otherwise.
   */
  public boolean isUnsigned() {
    return !signed;
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
      bigIntRep = bigIntRep.add(context.getPublicKey().getModulus());
    }

    return bigIntRep;
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
    BigInteger halfModulus = context.getPublicKey().modulus.shiftRight(1);
    return number.value.compareTo(halfModulus) > 0 ? -1 : 1;
  }
  
  public int getBase() {
    return base;
  }
  
  public int getPrecision() {
    return precision;
  }
  
  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  public BigInteger getMinSignificand() {
    return minSignificand;
  }
  
  public boolean isValid(EncodedNumber encoded) {
    // NOTE signed == true implies minEncoded > maxEncoded
    if (!context.equals(encoded.getContext())) {
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
    BigDecimal exp = BigDecimal.valueOf(base).pow(Math.abs(encoded.getExponent()));
    BigDecimal bigDecoded;
    if (encoded.getExponent() < 0) {
      bigDecoded = new BigDecimal(significand).divide(exp, MathContext.DECIMAL128);
    } else {
      bigDecoded = new BigDecimal(significand).multiply(exp, MathContext.DECIMAL128);
    }
    //double decoded = significand.doubleValue() * Math.pow((double) base, (double) encoded.getExponent());
    double decoded = bigDecoded.doubleValue();
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
  
  public BigDecimal decodeBigDecimal(EncodedNumber encoded) throws DecodeException {
    return decodeBigDecimal(encoded, BIG_DECIMAL_ENCODING_PRECISION);
  }
  
  public BigDecimal decodeBigDecimal(EncodedNumber encoded, int precision) throws DecodeException {
    BigInteger significant = getSignificand(encoded);
    if (base == 10) {
      return new BigDecimal(significant, -encoded.getExponent());
    }
    MathContext mc = new MathContext(precision + 1, RoundingMode.HALF_EVEN);
    BigDecimal exp = BigDecimal.valueOf(base).pow(encoded.getExponent(), mc);
    return exp.multiply(new BigDecimal(significant), mc);
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
    context.checkSameContext(encoded);
    final BigInteger value = encoded.getValue();

    if(value.compareTo(context.getPublicKey().getModulus()) > 0)
      throw new DecodeException("The significand of the encoded number is corrupted");

    // Non-negative
    if (value.compareTo(maxEncoded) <= 0) {
      return value;
    }

    // Negative - note that negative encoded numbers are greater than
    // non-negative encoded numbers and hence minEncoded > maxEncoded
    if (signed && value.compareTo(minEncoded) >= 0) {
      final BigInteger modulus = context.getPublicKey().getModulus();
      return value.subtract(modulus);
    }
    throw new DecodeException("Detected overflow");
  }
  
  public BigInteger getRescalingFactor(int expDiff) {
    return (BigInteger.valueOf(base)).pow(expDiff);
  }
  
  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != StandardEncodingScheme.class) {
      return false;
    }
    StandardEncodingScheme encoding = (StandardEncodingScheme) o;
    return signed == encoding.signed &&
            precision == encoding.precision && 
            base == encoding.base;
  }

  public boolean equals(StandardEncodingScheme o) {
    return o == this || (o != null &&
            base == o.base &&
            signed == o.signed &&
            precision == o.precision);
  }
  
  @Override
  public int hashCode() {
    return new HashChain().chain(base).chain(signed).chain(precision).hashCode();
  }
  
  //code from Maarten Bodewes (http://stackoverflow.com/questions/739532/logarithm-of-a-bigdecimal)
  private static double log2(BigInteger val)
  {
      // Get the minimum number of bits necessary to hold this value.
      int n = val.bitLength();

      // Calculate the double-precision fraction of this number; as if the
      // binary point was left of the most significant '1' bit.
      // (Get the most significant 53 bits and divide by 2^53)
      long mask = 1L << 52; // mantissa is 53 bits (including hidden bit)
      long mantissa = 0;
      int j = 0;
      for (int i = 1; i < 54; i++)
      {
          j = n - i;
          if (j < 0) break;

          if (val.testBit(j)) mantissa |= mask;
          mask >>>= 1;
      }
      // Round up if next bit is 1.
      if (j > 0 && val.testBit(j - 1)) mantissa++;

      double f = mantissa / (double)(1L << 52);

      // Add the logarithm to the number of bits, and subtract 1 because the
      // number of bits is always higher than necessary for a number
      // (ie. log2(val)<n for every val).
      return (n - 1 + Math.log(f) * 1.44269504088896340735992468100189213742664595415298D);
      // Magic number converts from base e to base 2 before adding. For other
      // bases, correct the result, NOT this number!
  }
  
  private static final double LOG10 = Math.log(10.0);
  private static final double LOG2 = Math.log(2.0);

  private static double logBigDecimal(BigDecimal val, int base) {
      return (log2(val.unscaledValue()) * LOG2 - val.scale() * LOG10) / Math.log(base);
  }

}
