[![Build Status](https://travis-ci.org/NICTA/javallier.svg?branch=master)](https://travis-ci.org/NICTA/javallier)

# javallier

A Java library for [Paillier partially homomorphic encryption](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
based on [python-paillier](https://github.com/NICTA/python-paillier).

The homomorphic properties of the paillier crypto system are:

- Encrypted numbers can be multiplied by a non encrypted scalar.
- Encrypted numbers can be added together.
- Encrypted numbers can be added to non encrypted scalars.


To use the library add the following dependency to your SBT configuration:

    libraryDependencies += "com.n1analytics" % "javallier_2.10" % "0.4.2"


Example usages are provided in the `/examples` source directory. A benchmarking script
can be found in `/benchmark`.


## Build


Compile the library:

    $ sbt compile
    
Create a jar file:

    $ sbt package
    

Run all tests with `sbt`:

    $ sbt test
    
Or run just fast tests:

    $ ./test-fast.sh

## Command Line Tool

A small command line tool has been created to wrap the `javallier` library.

Use the `javallier` cli tool to:

- generate and serialize key pairs (of different key sizes)
- encrypt and serialize signed floating point numbers given a public key
- add two encrypted numbers together
- add an encrypted number to a plaintext number
- TODO multiply an encrypted number by a plaintext number
- decrypt an encrypted number given the private key


Build the `javallier` CLI tool:

    sbt stage

Then run the binary for your system, e.g., on Linux:

    ./target/universal/stage/bin/javallier


Alternatively you can run directly with sbt:

    sbt "runMain com.n1analytics.paillier.cli.Main"


### Example CLI session

    $ javallier genpkey --keysize 256 -m "Example keypair" examplekey.priv
    $ cat examplekey.priv | python -m json.tool
    {
        "kty": "DAJ",
        "key_ops": [ "decrypt" ],
        "pub": {
            "alg": "PAI-GN1",
            "kty": "DAJ",
            "kid": "Example keypair",
            "n": "AImjybsy4/6Lwrl71OoOFyQ//Zvn5AaHt4JXdY4uiEsB",
            "key_ops": [ "encrypt" ]
        },
        "kid": "Example keypair",
        "lambda": "AImjybsy4/6Lwrl71OoOFyLITnbXrH/Z6PoGtpWokAAA",
        "mu": "c6zkHofGK9uWqWX1eXTIydCqUnvBJKlDHOZ0fEcZCeQ="
    }

    $ javallier extract examplekey.priv examplekey.pub
    $ javallier encrypt examplekey.pub "12" -o encA.json
    $ javallier encrypt examplekey.pub "8" -o encB.json
    $ javallier addenc examplekey.pub encA.json encB.json -o encC.json
    $ javallier decrypt examplekey.priv encC.json
    20.0
    $ javallier add -o encD.json examplekey.pub encA.json 12
    $ javallier decrypt examplekey.priv encD.json
    24.0

Release
-------

Releases will be signed by Brian Thorne with the PGP key
[C18347DE](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x22ADF3BFC18347DE)

* http://www.scala-sbt.org/release/docs/Using-Sonatype.html
* http://central.sonatype.org/pages/releasing-the-deployment.html


Limitations
-----------

*   Arithmetic functions that involve a combination of addition and multiplication operations, such as 
    (a + b) &times; c, might result in overflow in the `EncryptedNumber` domain. When overflow occurs, the computation 
    result is incorrect even though the the result was succesfully decrypted and decoded. At the moment, the 
    implementation does not detect overflow cause by such computation. 
    
    One way to detect this is to ensure that the inputs to the function are carefully chosen such that it does not 
    lead to overflow. For more complex arithmetic functions, such approach may not be possible. The alternative is to 
    initially perform the same arithmetic function in the `Number` domain and check whether the result is a valid 
    `Number`. The computation in the `EncryptedNumber` domain should only be performed if the result in the  the 
    `Number` domain is valid.
