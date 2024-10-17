//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPrivateKeysPem](get-private-keys-pem.md)

# getPrivateKeysPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getPrivateKeysPem](get-private-keys-pem.md)(privateKeys: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;, passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)? = null, encryptionAlgorithm: [EncryptionAlgorithm](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-encryption-algorithm/index.md) = EncryptionAlgorithm.AES_256_CBC): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts a list of PrivateKeys to a single PEM-formatted string.

This method iterates over each private key in the list and uses the getPrivateKeyPem method to convert each key to its PEM format.

#### Return

The concatenated PEM-formatted private keys string, with each key separated by newlines.

#### Parameters

androidJvm

| | |
|---|---|
| privateKeys | The list of PrivateKey objects to be converted. |
| passphrase | The passphrase used to encrypt the private keys (as CharArray). If null, the keys will not be encrypted. |
| encryptionAlgorithm | The encryption algorithm to use (default is AES-256-CBC). |
