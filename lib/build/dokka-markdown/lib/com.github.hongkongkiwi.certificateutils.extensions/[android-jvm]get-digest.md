//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]getDigest]([android-jvm]get-digest.md)

# getDigest

[androidJvm]\
fun [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html).[getDigest]([android-jvm]get-digest.md)(algorithm: [DigestAlgorithm](../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-digest-algorithm/index.md)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Computes the digest of the X509Certificate using the specified algorithm.

#### Return

The computed digest as a String.

#### Parameters

androidJvm

| | |
|---|---|
| algorithm | The digest algorithm to use. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | if the algorithm is unsupported. |
