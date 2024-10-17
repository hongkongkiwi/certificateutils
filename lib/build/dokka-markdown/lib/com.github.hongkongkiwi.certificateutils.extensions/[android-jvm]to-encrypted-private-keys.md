//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]toEncryptedPrivateKeys]([android-jvm]to-encrypted-private-keys.md)

# toEncryptedPrivateKeys

[androidJvm]\
fun [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html).[toEncryptedPrivateKeys]([android-jvm]to-encrypted-private-keys.md)(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;

Converts a PEM encoded string to a list of encrypted PrivateKeys using a passphrase.

#### Return

A list of decrypted PrivateKeys.

#### Parameters

androidJvm

| | |
|---|---|
| passphrase | The passphrase used for decryption. |
