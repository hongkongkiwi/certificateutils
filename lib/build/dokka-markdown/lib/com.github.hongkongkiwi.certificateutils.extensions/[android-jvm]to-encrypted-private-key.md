//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]toEncryptedPrivateKey]([android-jvm]to-encrypted-private-key.md)

# toEncryptedPrivateKey

[androidJvm]\
fun [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html).[toEncryptedPrivateKey]([android-jvm]to-encrypted-private-key.md)(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)

Converts a PEM encoded string to an encrypted PrivateKey using a passphrase.

#### Return

The decrypted PrivateKey.

#### Parameters

androidJvm

| | |
|---|---|
| passphrase | The passphrase used for decryption. |
