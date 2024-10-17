//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]toPem]([android-jvm]to-pem.md)

# toPem

[androidJvm]\
fun [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html).[toPem]([android-jvm]to-pem.md)(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)? = null): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts the PrivateKey to PEM format.

#### Return

The PEM formatted string representation of the PrivateKey.

#### Parameters

androidJvm

| | |
|---|---|
| passphrase | Optional passphrase for encrypted keys. |

[androidJvm]\
fun [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;.[toPem]([android-jvm]to-pem.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts the list of X509Certificates to a PEM formatted string.

#### Return

A PEM formatted string representation of the certificates.

[androidJvm]\
fun [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;.[toPem]([android-jvm]to-pem.md)(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)? = null): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts the list of PrivateKeys to a PEM formatted string.

#### Return

A PEM formatted string representation of the private keys.

#### Parameters

androidJvm

| | |
|---|---|
| passphrase | Optional passphrase for encrypted keys. |

[androidJvm]\
fun [Any](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-any/index.html).[toPem]([android-jvm]to-pem.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts any supported type to its PEM representation.

#### Return

The PEM formatted string of the provided type.

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | if the type is unsupported for PEM conversion. |
