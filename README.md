[![Build Status](https://travis-ci.org/n1analytics/javallier.svg?branch=master)](https://travis-ci.org/n1analytics/javallier) [![Javadocs](https://www.javadoc.io/badge/com.n1analytics/javallier_2.10.svg)](https://www.javadoc.io/doc/com.n1analytics/javallier_2.10)

# javallier

A Java library for [Paillier partially homomorphic encryption](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
based on [python-paillier](https://github.com/NICTA/python-paillier).

The homomorphic properties of the paillier cryptosystem are:

- Encrypted numbers can be multiplied by a non encrypted scalar.
- Encrypted numbers can be added together.
- Encrypted numbers can be added to non encrypted scalars.


To use the library add the following dependency to your SBT configuration:

    libraryDependencies += "com.n1analytics" % "javallier_2.10" % "0.6.0"


Example usages are provided in the `/examples` source directory. A 
benchmarking script can be found in `/benchmark`.


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
- multiply an encrypted number by a plaintext number
- decrypt an encrypted number given the private key


Build the `javallier` CLI tool:

    sbt assembly

This creates a `javallier.jar` jar file in:

    ./target/scala-2.10

To run it:

    java -jar javallier.jar <COMMAND>  

Alternatively you can run directly with sbt:

    sbt "runMain com.n1analytics.paillier.cli.Main"


### Example CLI session

    $ java -jar javallier.jar genpkey --keysize 256 -m "Example keypair" examplekey.priv
    $ cat examplekey.priv | python -m json.tool
    {
        "kty": "DAJ",
        "key_ops": [
            "decrypt"
        ],
        "pub": {
            "alg": "PAI-GN1",
            "kty": "DAJ",
            "kid": "Example keypair",
            "n": "AI9TjNmoL7p3j_D-RNK5AJQC1uDMtVvdy0MNi6ctj6Xn",
            "key_ops": [
                "encrypt"
            ]
        },
        "kid": "Example keypair",
        "lambda": "AI9TjNmoL7p3j_D-RNK5AJJ3odV_yUj39nLtFBMcrsoQ",
        "mu": "MDo136LqeN-R5W4kT2azGc6Y-cD77f6r_B6zncj48Eo"
    }
    

    $ java -jar javallier.jar extract examplekey.priv examplekey.pub
    $ java -jar javallier.jar encrypt examplekey.pub "12" -o encA.json
    $ java -jar javallier.jar encrypt examplekey.pub "8" -o encB.json
    $ java -jar javallier.jar addenc examplekey.pub encA.json encB.json -o encC.json
    $ java -jar javallier.jar decrypt examplekey.priv encC.json
    20.0
    $ java -jar javallier.jar add -o encD.json examplekey.pub encA.json 12
    $ java -jar javallier.jar decrypt examplekey.priv encD.json
    24.0

##  Releases

Releases will be signed by [Brian Thorne](https://keybase.io/hardbyte) with the PGP key
[22AD F3BF C183 47DE](https://pgp.mit.edu/pks/lookup?op=vindex&search=0x22ADF3BFC18347DE)


### Creating a release

Update the version in `build.sbt` using [semantic versioning](http://semver.org/).
Update the [CHANGELOG](./CHANGELOG), git tag the new release.

Ensure you have sonatype credentials in `~/.sbt/0.13/sonatype.sbt`, and
[install the pgp plugin](http://www.scala-sbt.org/sbt-pgp/)
(`~/.sbt/0.13/plugins/pgp.sbt`). Run `sbt publishSigned`, then visit the
[staging repositories](https://oss.sonatype.org/#stagingRepositories) of
sonatype. **Close** the staging repository which will allow you to move
to the release channel. Once you have successfully closed the staging
repository, you can **release** it.


For more information:
* http://www.scala-sbt.org/release/docs/Using-Sonatype.html
* http://central.sonatype.org/pages/releasing-the-deployment.html


## Limitation

Adding two encrypted numbers where the exponents differs wildly may result in overflow 
in the `EncryptedNumber` domain. The addition result can be successfully decrypted and 
decoded but the computation result is incorrect. Current implementation does not detect 
such overflow. 
    
