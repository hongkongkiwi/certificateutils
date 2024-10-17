//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[parsePublicKeyPem](parse-public-key-pem.md)

# parsePublicKeyPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [parsePublicKeyPem](parse-public-key-pem.md)(publicKeyPem: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](https://developer.android.com/reference/kotlin/java/security/PublicKey.html)&gt;

Parses PEM-formatted public keys.

#### Return

A list of parsed `PublicKey` objects.

#### Parameters

androidJvm

| | |
|---|---|
| publicKeyPem | The PEM-formatted public key string, potentially containing multiple keys. |

#### Throws

| | |
|---|---|
| [InvalidPublicKeyPemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-public-key-pem-exception/index.md) | If the public key PEM is invalid or cannot be parsed. |
