//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPrivateKeyPem](get-private-key-pem.md)

# getPrivateKeyPem

[androidJvm]\
fun [getPrivateKeyPem](get-private-key-pem.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)? = null, encryptionAlgorithm: [EncryptionAlgorithm](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-encryption-algorithm/index.md) = EncryptionAlgorithm.AES_256_CBC): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts a PrivateKey to an encrypted or unencrypted PEM-formatted string.

#### Return

The PEM-formatted private key string, encrypted if a passphrase is provided.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The PrivateKey to be converted to PEM format. |
| passphrase | The passphrase used to encrypt the private key (as CharArray). If null, the key will not be encrypted. |
| encryptionAlgorithm | The encryption algorithm to use (default is AES-256-CBC). |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the passphrase is empty when encryption is requested. |
