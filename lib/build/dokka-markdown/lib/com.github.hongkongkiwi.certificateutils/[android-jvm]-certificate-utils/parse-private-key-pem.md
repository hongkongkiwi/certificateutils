//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[parsePrivateKeyPem](parse-private-key-pem.md)

# parsePrivateKeyPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [parsePrivateKeyPem](parse-private-key-pem.md)(privateKeyPem: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html), passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)? = null): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;

Parses PEM-formatted private keys.

If any of the PEMs are encrypted (i.e., they start with &quot;-----BEGIN ENCRYPTED PRIVATE KEY-----&quot;), a passphrase must be provided to decrypt the keys.

#### Return

A list of parsed `PrivateKey` objects.

#### Parameters

androidJvm

| | |
|---|---|
| privateKeyPem | The PEM-formatted private key string, potentially containing multiple keys. |
| passphrase | Optional passphrase used to decrypt the private keys if they are encrypted. |

#### Throws

| | |
|---|---|
| [InvalidPrivateKeyPemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-private-key-pem-exception/index.md) | If the private key PEM is invalid or decryption fails. |
