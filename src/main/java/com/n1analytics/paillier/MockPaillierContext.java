package com.n1analytics.paillier;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * This is a mock version of the PaillierContext.
 * 
 * !!! THIS IS FOR DEBUGGING PURPOSES ONLY !!!
 * 
 * It emulates the arithmetic of the PaillierContext without the expensive encryption operations.
 * Thus, no values get actually encrypted. Everything is in the clear!
 * 
 * @author whenecka
 *
 */
public class MockPaillierContext extends PaillierContext {

  private static Logger logger = Logger.getLogger("com.n1analytics.paillier");

  /**
   * Constructs a new mock Paillier context.
   *
   * @param publicKey associated with this MockPaillierContext.
   * @param signed to denote whether this MockPaillierContext supports signed or unsigned numbers.
   * @param precision to denote the number of bits used to represent valid numbers.
   */
  public MockPaillierContext(PaillierPublicKey publicKey, boolean signed, int precision) {
    super(publicKey, signed, precision);
    logger.warning("You are using the MockPaillierContext. Are you sure? This is NOT secure/private!");
  }
  
  public MockPaillierContext(PaillierPublicKey publicKey, boolean signed, int precision, int base) {
    super(publicKey, signed, precision, base);
    logger.warning("You are using the MockPaillierContext. Are you sure? This is NOT secure/private!");

  }

  /**
   * Performs "mock" obfuscation for an {@code EncryptedNumber}.
   *
   * @param encrypted the {@code EncryptedNumber} to be obfuscated.
   * @return the "mock" obfuscation result.
   */
  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    //we skip this
    return encrypted;
  }

  /**
   * Performs "mock" encryption for an {@code EncryptedNumber}.
   *
   * @param encoded the {@code EncodedNumber} to be encrypted.
   * @return the "mock" encryption result.
   */
  public EncryptedNumber encrypt(EncodedNumber encoded) {
    //we don't actually encrypt. 
    checkSameContext(encoded);
    final BigInteger modulus = getPublicKey().getModulus();
    final BigInteger value = encoded.getValue();
    return new EncryptedNumber(this, value.mod(modulus), encoded.getExponent());
  }

  /**
   * Performs "mock" addition between two {@code EncryptedNumber}s.
   *
   * @param operand1 first {@code EncryptedNumber}.
   * @param operand2 second {@code EncryptedNumber}.
   * @return the "mock" addition result.
   * @throws PaillierContextMismatchException if {@code operand1}'s mock context is not the same as
   * {@code operand2}'s mock context.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
      throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = getPublicKey().getModulus();
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.ciphertext;
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = value1.multiply(getRescalingFactor(exponent1 - exponent2)).mod(modulus);
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.multiply(getRescalingFactor(exponent2 - exponent1)).mod(modulus);
      exponent2 = exponent1;
    } // else do nothing
    BigInteger result = value1.add(value2);
    //this tests for overflows
    BigInteger posValue1 = (isSigned() && value1.compareTo(getMinEncoded())>=0)? value1.subtract(this.getPublicKey().modulus) : value1;
    BigInteger posValue2 = (isSigned() && value2.compareTo(getMinEncoded())>=0)? value2.subtract(this.getPublicKey().modulus) : value2;

    if(posValue1.add(posValue2).compareTo(modulus) != -1){
      logger.warning("Overflow occured in add()");
    }
    return new EncryptedNumber(this, result.mod(modulus), exponent1);
  }

  /**
   * Performs "mock" additive inverse for {@code EncryptedNumber}.
   *
   * @param operand1 input.
   * @return the "mock" additive inverse.
   * @throws PaillierContextMismatchException if {@code operand1}'s mock context is not the same as this mock context.
   */
  public EncryptedNumber additiveInverse(EncryptedNumber operand1) throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(),
        getPublicKey().modulus.subtract(operand1.ciphertext),
        operand1.getExponent());
  }

  /**
   * Performs "mock" additive inverse for {@code EncodedNumber}
   *
   * @param operand1 input.
   * @return the "mock" additive inverse.
   * @throws PaillierContextMismatchException if {@code operand1}'s mock context is not the same as this mock context.
   */
  public EncodedNumber additiveInverse(EncodedNumber operand1) throws PaillierContextMismatchException {
    checkSameContext(operand1);
    if (operand1.getValue().signum() == 0) {
      return operand1;
    }
    final BigInteger modulus = getPublicKey().getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger result = modulus.subtract(value1);
    return new EncodedNumber(this, result, operand1.getExponent());
  }

  /**
   * Performs "mock" multiplication between an {@code EncryptedNumber} and an {@code EncodedNumber}.
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the "mock" multiplication result.
   * @throws PaillierContextMismatchException if {@code operand1}'s mock context is not the same as
   * {@code operand2}'s mock context.
   */
  public EncryptedNumber multiply(EncryptedNumber operand1, EncodedNumber operand2)
      throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger value1 = operand1.ciphertext;
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = value1.multiply(value2);
    
    //this tests for overflows
    BigInteger posValue1 = (isSigned() && value1.compareTo(getMinEncoded())>=0)? value1.subtract(this.getPublicKey().modulus) : value1;
    BigInteger posValue2 = (isSigned() && value2.compareTo(getMinEncoded())>=0)? value2.subtract(this.getPublicKey().modulus) : value2;
    if(posValue1.multiply(posValue2).compareTo(getPublicKey().getModulus()) != -1){
      logger.warning("Overflow occured in multiply()");
    }
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncryptedNumber(this, result.mod(getPublicKey().getModulus()), exponent);
  }
  
  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != MockPaillierContext.class) {
      return false;
    }
    MockPaillierContext context = (MockPaillierContext) o;
    return getPublicKey().equals(context.getPublicKey()) &&
            isSigned() == context.isSigned() &&
            getPrecision() == context.getPrecision();
  }

  public boolean equals(MockPaillierContext o) {
    return o == this || (o != null &&
            getPublicKey().equals(o.getPublicKey()) &&
            isSigned() == o.isSigned() &&
            getPrecision() == o.getPrecision());
  }
}
