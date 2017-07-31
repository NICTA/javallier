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
import java.security.SecureRandom;

/**
 * An immutable class representing Paillier private key.
 *
 * A private key (and it's corresponding public key) are generated via the
 * following procedure, given a public key length <code>modulusLength</code>:
 * <ul>
 *   <li>
 *     Generate two primes <code>p, q</code>, each of bit length
 *     <code>modulusLength/2</code> and with a product <code>p * q</code> of bit
 *     length <code>modulusLength</code>.
 *   </li>
 *   <li>
 *     Calculate <code>modulus = p * q</code>.
 *   </li>
 *   <li>
 *     Calculate <code>generator = modulus + 1</code>.
 *   </li>
 *   <li>
 *     Calculate the totient function of <code>modulus</code>:
 *     <code>totient = (p-1)*(q-1)</code>. This represents the number of
 *     positive integers less than or equal to <code>modulus</code> which
 *     are relatively prime to <code>modulus</code>.
 *   </li>
 *   <li>
 *     Calculate the inverse of <code>totient</code> modulo <code>modulus</code>.
 *   </li>
 * </ul>
 *
 * The result of this procedure is a public key comprising a
 * <code>modulus</code>, its square <code>modulusSquared</code> and a
 * <code>generator</code> as well as  a private key comprising a reference to
 * the <code>publicKey</code> and the prime factors <code>p</code> and <code>q</code>.
 * In order to speed up the decryption, we also precompute the values:
 * <ul>
 *   <li>
 *     <code>pSquared = p*p</code>,
 *   </li>
 *   <li>
 *     <code>qSquared = q*q</code>,
 *   </li>
 *   <li>
 *     <code>pInverse</code>, the modular inverse of <code>p</code> modulo <code>q</code>,
 *   </li>
 *   <li>
 *     <code>hp</code> and <code>hq</code>, precomputations of the parts of the decryption
 *     function which do not depend on the ciphertext.
 *   </li>
 * </ul>
 * 
 * Examples:
 * <ul>
 *   <li>
 *     <p>To create a 1024 bit keypair:</p>
 *     <p><code>PaillierPrvateKey privateKey = PaillierPrivateKey.create(1024);</code></p>
 *   </li>
 *   <li>
 *     <p>To decrypt an encrypted number <code>encryption</code>:</p>
 *     <p><code>EncodedNumber encodedNumber = privateKey.decrypt(encryption);</code></p>
 *   </li>
 *   <li>
 *     <p>
 *       To decrypt an encrypted number <code>encryption</code> and obtain the
 *       (double) value of the decryption:
 *     </p>
 *     <p>
 *       <code>double plaintext = privateKey.decrypt(encryption).decodeDouble();</code>
 *     </p>
 *   </li>
 * </ul>
 */
public final class PaillierPrivateKey {

  /**
   * A serializer interface for {@code PaillierPrivateKey}.
   */
  public static interface Serializer {
    void serialize(PaillierPublicKey publickey, BigInteger p, BigInteger q);
  }

  /**
   * The corresponding public key.
   */
  protected final PaillierPublicKey publicKey;

  /**
   * The first prime number, {@code p} such that {@code p*q = publicKey.modulus}.
   */
  protected final BigInteger p;

  /**
   * The first prime number, {@code q} such that  {@code p*q = publicKey.modulus}.
   */
  protected final BigInteger q;

  /**
   * The value <code>p<sup>2</sup></code>
   */
  protected final BigInteger pSquared;

  /**
   * The value <code>q<sup>2</sup></code>
   */
  protected final BigInteger qSquared;

  /**
   * The modular inverse of <code>p modulo q</code>
   */
  protected final BigInteger pInverse;

  /**
   * Precomputed <code>hp</code> as defined in Paillier's paper page 12: Decryption using Chinese-remaindering.
   */
  protected final BigInteger hp;

  /**
   * Precomputed <code>hq</code> as defined in Paillier's paper page 12: Decryption using Chinese-remaindering.
   */
  protected final BigInteger hq;

  /**
   * Constructs a Paillier private key given the associated public key and the totient.
   *
   * @param publicKey associated with this private key.
   * @param totient of the private key.
   */
  public PaillierPrivateKey(PaillierPublicKey publicKey, BigInteger totient) {
    // Some basic error checking. Note though that passing these tests does
    // not guarantee that the private key is valid.
    if (publicKey == null) {
      throw new IllegalArgumentException("publicKey must not be null");
    }
    if (totient == null) {
      throw new IllegalArgumentException("totient must not be null");
    }
    if (totient.signum() < 0) {
      throw new IllegalArgumentException("totient must be non-negative");
    }
    if (totient.compareTo(publicKey.getModulus()) >= 0) {
      throw new IllegalArgumentException(
          "totient must be less than public key modulus");
    }

    this.publicKey = publicKey;
    // given the totient, one can factorize the modulus
    BigInteger pPlusq = publicKey.modulus.subtract(totient).add(BigInteger.ONE);
    BigInteger pMinusq = BigIntegerUtil.sqrt(pPlusq.multiply(pPlusq).subtract(
        publicKey.modulus.multiply(BigInteger.valueOf(4))));
    this.q = (pPlusq.subtract(pMinusq)).divide(BigInteger.valueOf(2));
    this.p = pPlusq.subtract(q);
    // now do some precomputations
    this.qSquared = q.multiply(q);
    this.pSquared = p.multiply(p);
    this.pInverse = p.modInverse(q);
    this.hp = hFunction(p, pSquared);
    this.hq = hFunction(q, qSquared);

  }

  /**
   * Constructs a Paillier private key given an associated public key and the
   * two prime numbers p and q of the factorization of the public key's modulus.
   * 
   * @param publicKey associated with this private key.
   * @param p prime p.
   * @param q prime q.
   */
  protected PaillierPrivateKey(PaillierPublicKey publicKey, BigInteger p,
      BigInteger q) {
    if (publicKey == null) {
      throw new IllegalArgumentException("publicKey must not be null");
    }
    if (!publicKey.modulus.equals(p.multiply(q))) {
      throw new IllegalArgumentException(
          "publicKey does not match the given prime numbers.");
    }
    this.publicKey = publicKey;
    this.p = p;
    this.pSquared = p.multiply(p);
    this.q = q;
    this.qSquared = q.multiply(q);
    this.pInverse = p.modInverse(q);
    this.hp = hFunction(p, pSquared);
    this.hq = hFunction(q, qSquared);
  }

  /**
   * Creates a Paillier keypair of the specified modulus key length.
   *
   * @param modulusLength the length of the public key modulus. Must be a positive multiple of 8.
   * @return a Paillier keypair consists of a private key and the corresponding public key.
   * @throws IllegalArgumentException on illegal {@code modulusLength}.
   */
  public static PaillierPrivateKey create(int modulusLength) {
    if (modulusLength < 8 || modulusLength % 8 != 0) {
      throw new IllegalArgumentException("modulusLength must be a multiple of 8");
    }

    // Find two primes p and q whose multiple has the same number of bits
    // as modulusLength
    BigInteger p, q, modulus;
    int primeLength = modulusLength / 2;
    SecureRandom random = new SecureRandom();
    do {
      p = BigInteger.probablePrime(primeLength, random);
      do {
        q = BigInteger.probablePrime(primeLength, random);
      } while (p.equals(q)); //p and q must not be equal 
      modulus = p.multiply(q);
    } while (modulus.bitLength() != modulusLength);

    final PaillierPublicKey publicKey = new PaillierPublicKey(modulus);
    return new PaillierPrivateKey(publicKey, p, q);
  }

  /**
   * @return the associated public key.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Decrypts an encrypted number.
   *
   * @param encrypted EncryptedNumber to be decrypted.
   * @return the decryption result.
   * @throws PaillierKeyMismatchException if the encrypted number was not
   * encoded with the appropriate public key.
   */
  public EncodedNumber decrypt(EncryptedNumber encrypted)
      throws PaillierKeyMismatchException {
    if (!publicKey.equals(encrypted.getContext().getPublicKey())) {
      throw new PaillierKeyMismatchException();
    }
    
    if(encrypted.getContext() instanceof MockPaillierContext){
      return new EncodedNumber(encrypted.getContext(), encrypted.ciphertext, encrypted.getExponent());
    }
    return new EncodedNumber(encrypted.getContext(), raw_decrypt(encrypted.ciphertext),
        encrypted.getExponent());
  }
  
  /**
   * Implementation of the decryption function of the Paillier encryption scheme.
   * Returns the plain text of a given cipher text.
   *
   * @param ciphertext to be decrypted.
   * @return the decrypted plaintext.
   */
  public BigInteger raw_decrypt(BigInteger ciphertext){
    BigInteger decryptedToP = lFunction(BigIntegerUtil.modPowSecure(ciphertext, p.subtract(BigInteger.ONE), pSquared),p).multiply(hp).mod(p);
    BigInteger decryptedToQ = lFunction(BigIntegerUtil.modPowSecure(ciphertext, q.subtract(BigInteger.ONE), qSquared),q).multiply(hq).mod(q);
    return crt(decryptedToP, decryptedToQ);
  }

  /**
   * Computes the L function as defined in Paillier's paper. That is: L(x,p) =
   * (x-1)/p
   */
  private BigInteger lFunction(BigInteger x, BigInteger p) {
    return x.subtract(BigInteger.ONE).divide(p);
  }

  /**
   * Computes the h-function as defined in Paillier's paper page 12, 'Decryption
   * using Chinese-remaindering'.
   */
  private BigInteger hFunction(BigInteger x, BigInteger xSquared) {
    return lFunction(BigIntegerUtil.modPow(publicKey.generator, x.subtract(BigInteger.ONE), xSquared),x).modInverse(x);
  }

  /**
   * The Chinese Remainder Theorem as needed for decryption.
   *
   * @param mp the solution modulo p.
   * @param mq the solution modulo q.
   * @return the solution modulo n=pq.
   */
  private BigInteger crt(BigInteger mp, BigInteger mq) {
    BigInteger u = mq.subtract(mp).multiply(pInverse).mod(q);
    return mp.add(u.multiply(p));
  }

  /**
   * Serializes the {@code PaillierPrivateKey}.
   *
   * @param serializer to serialize the {@code PaillierPrivateKey}.
   */
  public void serialize(Serializer serializer) {
    serializer.serialize(publicKey, p, q);
  }

  @Override
  public int hashCode() {
    return publicKey.hashCode();
    // NOTE we don't need to hash any other variables since they are
    //      uniquely determined by publicKey
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null &&
            o.getClass() == PaillierPrivateKey.class &&
            publicKey.equals(((PaillierPrivateKey) o).publicKey));
    // NOTE we don't need to compare any other variables since they
    //      are uniquely determined by publicKey
  }

  public boolean equals(PaillierPrivateKey o) {
    return o == this || (o != null && publicKey.equals(o.publicKey));
    // NOTE we don't need to compare any other variables since they
    //      are uniquely determined by publicKey
  }
}
