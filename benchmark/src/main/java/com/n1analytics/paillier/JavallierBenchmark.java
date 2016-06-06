package com.n1analytics.paillier;

import org.openjdk.jmh.annotations.*;

import java.util.Random;


@State(Scope.Thread)
public class JavallierBenchmark {
   
  public static final int BITS = 1024; 
  public final int KEYS = 1000;
  public final int NUMBERS = 10000;

  public static PaillierPrivateKey KEY = PaillierPrivateKey.create(BITS);
  public static PaillierContext context = KEY.getPublicKey().createSignedContext();

  public final EncodedNumber encodedNumbers[] = new EncodedNumber[NUMBERS];
  public final EncodedNumber encodedNumbersSE[] = new EncodedNumber[NUMBERS];
  public final EncryptedNumber encryptedNumbers[] = new EncryptedNumber[NUMBERS];
  public final EncryptedNumber encryptedNumbersSE[] = new EncryptedNumber[NUMBERS];
  public final double[] doubleNumbers = new double[NUMBERS];
  
  public static Random rnd = new Random();

  public String currentTestName;
  public long currentTestRepititions;
  public long currentTestStartTime;
  public long currentTestEndTime;
  
  
  @Benchmark public PaillierPrivateKey keyGeneration(){
    return PaillierPrivateKey.create(BITS);
  }
  
  @Benchmark public EncryptedNumber encryptUnsafe(){
    return context.encrypt(rnd.nextDouble()-0.5);
  }
  
  @Benchmark public EncryptedNumber encryptSafe(){
    return context.obfuscate(context.encrypt(rnd.nextDouble()-0.5));
  }
  
  @State(Scope.Benchmark)
  public static class EncryptedNumberPairSameExponent{
    EncryptedNumber n1, n2;

    @Setup(Level.Iteration)
    public void setup(){
      int exp = rnd.nextInt(512);
      n1 = context.encrypt(context.randomEncodedNumber(exp));
      n2 = context.encrypt(context.randomEncodedNumber(exp));
    }
  }
  
  @Benchmark public EncryptedNumber addEncryptedToEncryptedSameExponent(EncryptedNumberPairSameExponent pair){
    return pair.n1.add(pair.n2);
  }
  
  @State(Scope.Benchmark)
  public static class EncryptedNumberPairDifferentExponent{
    public EncryptedNumber n1, n2;

    @Setup(Level.Iteration)
    public void setup(){
      n1 = context.encrypt(context.randomEncodedNumber(rnd.nextInt(512)));
      n2 = context.encrypt(context.randomEncodedNumber(rnd.nextInt(512)));
    }
  }
  
  @Benchmark public EncryptedNumber addEncryptedToEncryptedDifferentExponent(EncryptedNumberPairDifferentExponent dePair){
    return dePair.n1.add(dePair.n2);
  }
  
  @State(Scope.Benchmark)
  public static class EncryptedEncodedNumberPairSameExponent{
    EncryptedNumber n1;
    EncodedNumber n2;

    @Setup(Level.Iteration)
    public void setup(){      
      int exp = rnd.nextInt(512);
      n1 = context.encrypt(context.randomEncodedNumber(exp));
      n2 = context.randomEncodedNumber(exp);
    }
  }
  
  @Benchmark public EncryptedNumber addEncodedToEncryptedSameExponent(EncryptedEncodedNumberPairSameExponent pair){
    return pair.n1.add(pair.n2);
  }
  
  @Benchmark public EncryptedNumber paillierMultiply(EncryptedEncodedNumberPairSameExponent pair){
    return pair.n1.multiply(pair.n2);
  }
  
  @State(Scope.Benchmark)
  public static class EncryptedEncodedNumberPairDifferentExponent{
    public static EncryptedNumber n1 = null;
    public static EncodedNumber n2 = null;

    @Setup(Level.Iteration)
    public void setup(){      
      n1 = context.encrypt(context.randomEncodedNumber(rnd.nextInt(512)));
      n2 = context.randomEncodedNumber(rnd.nextInt(512));
    }
  }
  
  @Benchmark public EncryptedNumber addEncodedToEncryptedDifferentExponent(EncryptedEncodedNumberPairDifferentExponent dePair){
    return dePair.n1.add(dePair.n2);
  }
  
  //for comparison, we measure add and multiply on doubles
  @State(Scope.Benchmark)
  public static class Doubles{
    double d1, d2;
    @Setup(Level.Invocation)
    public void setup(){
      d1 = rnd.nextDouble() - 0.5;
      d2 = rnd.nextDouble() - 0.5;
    }
  }
  
  @Benchmark public double doublePrecicionAdd(Doubles ds){
    return ds.d1+ds.d2;
  }
  
  @Benchmark public double doublePrecicionMultiply(Doubles ds){
    return ds.d1*ds.d2;
  }
  
}
