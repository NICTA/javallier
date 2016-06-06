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

import java.math.BigInteger;

import com.n1analytics.paillier.util.BigIntegerUtil;

import static com.n1analytics.paillier.util.BigIntegerUtil.randomPositiveNumber;

/**
 * A class representing Paillier public key.
 *
 * The attributes stored in this class are:
 * <ul>
 *     <li>A BigInteger <code>modulus</code> (n) that is the first parameter of the public key.</li>
 *     <li>A BigInteger <code>generator</code> (g) that is the second parameter of the public key.</li>
 *     <li>A BigInteger <code>modulusSquared</code> (n<sup>2</sup>) that is the square of the modulus,
 *         often used in Paillier computation.</li>
 * </ul>
 *
 * Besides storing Paillier public key, the class has methods to generate the corresponding encoding
 * scheme (i.e., Paillier context).
 */
public final class PaillierPublicKey {

  /**
   * The modulus (n) of the public key.
   */
  protected final BigInteger modulus;

  /**
   * The modulus squared (n<sup>2</sup>) of the public key.
   */
  protected final BigInteger modulusSquared;

  /**
   * The generator (g) of the public key
   */
  protected final BigInteger generator;

  /**
   * A serializer interface for {@code PaillierPublicKey}.
   */
  public static interface Serializer {

    void serialize(BigInteger modulus);
  }

  /**
   * Constructs a Paillier public key.
   *
   * @param modulus of the public key
   */
  public PaillierPublicKey(BigInteger modulus) {
    if (modulus == null) {
      throw new NullPointerException("modulus must not be null");
    }
    this.modulus = modulus;
    this.modulusSquared = modulus.multiply(modulus);
    //the generator is always set to modulus+1, as this allows a 
    //significantly more efficient encryption function.
    this.generator = modulus.add(BigInteger.ONE);
  }

  /**
   * @return the modulus.
   */
  public BigInteger getModulus() {
    return modulus;
  }

  /**
   * @return the modulus<sup>2</sup>.
   */
  public BigInteger getModulusSquared() {
    return modulusSquared;
  }

  /**
   * @return the generator.
   */
  public BigInteger getGenerator() {
    return generator;
  }

  /**
   * Serializes the {@code PaillierPublicKey}.
   *
   * @param serializer to serialize the {@code PaillierPublicKey}.
   */
  public void serialize(Serializer serializer) {
    serializer.serialize(modulus);
  }

  /**
   * Creates a new full precision, unsigned Paillier context. The precision of the new context
   * equals to the modulus's bit length.
   *
   * @return the Paillier context.
   */
  public PaillierContext createUnsignedContext() {
    return new PaillierContext(this, false, modulus.bitLength());
  }

  /**
   * Creates a new partial precision, unsigned Paillier context.
   *
   * @param precision of the Paillier context.
   * @return the Paillier context.
   * @throws IllegalArgumentException if {@code precision} is invalid.
   */
  public PaillierContext createUnsignedContext(int precision)
          throws IllegalArgumentException {
    return new PaillierContext(this, false, precision);
  }

  /**
   * Creates a new full precision, signed Paillier context. The precision of the new context
   * equals to the modulus's bit length.
   *
   * @return the Paillier context.
   */
  public PaillierContext createSignedContext() {
    return new PaillierContext(this, true, modulus.bitLength());
  }

  /**
   * Creates a new partial precision, signed Paillier context.
   *
   * @param precision of the Paillier context.
   * @return the Paillier context.
   */
  public PaillierContext createSignedContext(int precision) {
    return new PaillierContext(this, true, precision);
  }

  /**
   * Creates a new unsigned, full precision {@code MockPaillierContext}.
   *
   * @return the  {@code MockPaillierContext}.
   */
  public MockPaillierContext createMockUnsignedContext() {
    return new MockPaillierContext(this, false, modulus.bitLength());
  }

  /**
   * Creates a new unsigned, partial precision  {@code MockPaillierContext}.
   *
   * @param precision of the {@code MockPaillierContext}.
   * @return the {@code MockPaillierContext}.
   * @throws IllegalArgumentException if the precision is not valid
   */
  public MockPaillierContext createMockUnsignedContext(int precision)
          throws IllegalArgumentException {
    return new MockPaillierContext(this, false, precision);
  }

  /**
   * Creates a new signed, full precision {@code MockPaillierContext}.
   *
   * @return the {@code MockPaillierContext}.
   */
  public MockPaillierContext createMockSignedContext() {
    return new MockPaillierContext(this, true, modulus.bitLength());
  }

  /**
   * Creates a new signed, partial precision {@code MockPaillierContext}.
   *
   * @param precision of the {@code MockPaillierContext}.
   * @return {@code MockPaillierContext}.
   */
  public MockPaillierContext createMockSignedContext(int precision) {
    return new MockPaillierContext(this, true, precision);
  }
  
  /**
   * Implements the encryption function of the Paillier encryption scheme.
   *
   * @param plaintext to be encrypted.
   * @return corresponding ciphertext.
   */
  public BigInteger raw_encrypt(BigInteger plaintext){
    return raw_obfuscate(raw_encrypt_without_obfuscation(plaintext));
  }
  
  /**
   * The encryption function of the Paillier encryption scheme can be divided into 
   * two parts:
   *  - The first part, as implemented here, maps the plaintext into the encrypted space.
   *    But be aware, that this function is invertible, that is, the ciphertext is not yet 
   *    secure.
   *  - Only after the second part, the 'raw_obfuscate' function, the ciphertext is secure 
   *    and the corresponding plaintext can't be recovered without the secret key.
   * The reason we split the encryption is that the second part is computationally significantly
   * more expensive than the first part and since the obfuscation has to be done only once
   * before you can securely share the generated ciphertext, there are scenarios, where
   * obfuscating at encryption is unnecessary. 
   *  
   * @param plaintext to be encrypted.
   * @return corresponding unobfuscated ciphertext.
   */
  public BigInteger raw_encrypt_without_obfuscation(BigInteger plaintext){
    return modulus.multiply(plaintext).add(BigInteger.ONE).mod(modulusSquared);
  }
  
  /**
   * Implements the obfuscation function of the Paillier encryption scheme.
   * It changes the value of a ciphertext without changing the corresponding plaintext.
   *
   * @param ciphertext to be ofuscated
   * @return obfuscated ciphertext.
   */
  public BigInteger raw_obfuscate(BigInteger ciphertext) {
    return BigIntegerUtil.modPow(randomPositiveNumber(modulus), modulus, modulusSquared).multiply(ciphertext).mod(modulusSquared);
  }
  
  /**
   * Implements the addition function of two ciphertexts of the Paillier encryption scheme.
   *
   * @param ciphertext1 first ciphertext.
   * @param ciphertext2 second ciphertext.
   * @return ciphertext of the sum of the two plaintexts corresponding to {@code ciphertext1} and {@code ciphertext2}.
   */
  public BigInteger raw_add(BigInteger ciphertext1, BigInteger ciphertext2){
    return ciphertext1.multiply(ciphertext2).mod(modulusSquared);
  }
  
  /**
   * Implements the multiplication function of the Paillier encryption scheme.
   * In the Paillier scheme you can only multiply an unencrypted value with an encrypted value.
   *
   * @param ciphertext of factor a.
   * @param plainfactor b.
   * @return product a*b.
   */
  public BigInteger raw_multiply(BigInteger ciphertext, BigInteger plainfactor){
    return BigIntegerUtil.modPow(ciphertext, plainfactor, modulusSquared);
  }

  @Override
  public int hashCode() {
    return modulus.hashCode();
    // NOTE we don't need to hash modulusSquared or generator since they
    //      are uniquely determined by modulus
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null &&
            o.getClass() == PaillierPublicKey.class &&
            modulus.equals(((PaillierPublicKey) o).modulus));
    // NOTE we don't need to compare modulusSquared or generator since they
    //      are uniquely determined by modulus
  }

  public boolean equals(PaillierPublicKey o) {
    return o == this || (o != null && modulus.equals(o.modulus));
    // NOTE we don't need to compare modulusSquared or generator since they
    //      are uniquely determined by modulus
  }
}
