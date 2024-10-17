//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.models](../index.md)/[[androidJvm]EncryptedPrivateKey](index.md)

# EncryptedPrivateKey

[androidJvm]\
class [EncryptedPrivateKey](index.md)(val privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), val passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html))

Encapsulates an EncryptedPrivateKey with its associated passphrase.

## Constructors

| | |
|---|---|
| [EncryptedPrivateKey](-encrypted-private-key.md) | [androidJvm]<br>constructor(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [passphrase](passphrase.md) | [androidJvm]<br>val [passphrase](passphrase.md): [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)<br>The passphrase to decrypt/encrypt the private key. |
| [privateKey](private-key.md) | [androidJvm]<br>val [privateKey](private-key.md): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)<br>The private key (in PEM format). |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [androidJvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)<br>Override `equals` to ensure equality checks consider both the private key and passphrase. |
| [getAlgorithm](get-algorithm.md) | [androidJvm]<br>fun [getAlgorithm](get-algorithm.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)<br>Returns the algorithm of the wrapped PrivateKey. |
| [getEncoded](get-encoded.md) | [androidJvm]<br>fun [getEncoded](get-encoded.md)(): [ByteArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/index.html)?<br>Returns the encoded version of the PrivateKey, if available. |
| [getFormat](get-format.md) | [androidJvm]<br>fun [getFormat](get-format.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?<br>Returns the format of the wrapped PrivateKey (usually &quot;PKCS#8&quot; for PEM-encoded keys). |
| [hashCode](hash-code.md) | [androidJvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html)<br>Override `hashCode` to include both the private key and passphrase. |
| [toString](to-string.md) | [androidJvm]<br>open override fun [toString](to-string.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)<br>Override `toString` for better debugging and logging purposes. |
