# Benchmarking Javallier

We use the [JMH framework](http://openjdk.java.net/projects/code-tools/jmh/) for benchmarking.

Execute with the [sbt jmh plugin](https://github.com/ktoso/sbt-jmh):

 - change to `project benchmark`
 - execute with `jmh:run`
 - `jmh:run -h` will show you all available parameters.

To run from the command line:

    sbt 'project benchmark' jmh:run

Note with default settings, the benchmarking will take around an hour. A fast, but
inaccurate benchmark can be run in around a minute with:

    sbt 'project benchmark' 'jmh:run -i 3 -wi 3 -f1 -t1'

Which means 3 iterations, 3 warm-up iterations, 1 fork, 1 thread. An example output:


    addEncodedToEncryptedDifferentExponent    thrpt    3      450.864 ±    3217.173  ops/s
    addEncodedToEncryptedSameExponent         thrpt    3    50617.242 ±    6319.803  ops/s
    addEncryptedToEncryptedDifferentExponent  thrpt    3     1709.128 ±   19356.119  ops/s
    addEncryptedToEncryptedSameExponent       thrpt    3    54404.080 ±    7314.757  ops/s
    doublePrecicionAdd                        thrpt    3  1432289.203 ±  113905.788  ops/s
    doublePrecicionMultiply                   thrpt    3  1514150.591 ± 1466066.951  ops/s
    encryptSafe                               thrpt    3       74.502 ±      13.634  ops/s
    encryptUnsafe                             thrpt    3   807898.600 ± 3634045.919  ops/s
    keyGeneration                             thrpt    3       12.976 ±      12.215  ops/s
    paillierMultiply                          thrpt    3       78.604 ±       8.876  ops/s
