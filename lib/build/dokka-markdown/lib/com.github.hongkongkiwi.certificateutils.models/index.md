//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.models](index.md)

# Package-level declarations

## Types

| Name | Summary |
|---|---|
| [EncryptedPrivateKey]([android-jvm]-encrypted-private-key/index.md) | [androidJvm]<br>class [EncryptedPrivateKey]([android-jvm]-encrypted-private-key/index.md)(val privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), val passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html))<br>Encapsulates an EncryptedPrivateKey with its associated passphrase. |
| [PrivateKeyWithAlias]([android-jvm]-private-key-with-alias/index.md) | [androidJvm]<br>@Serializable<br>class [PrivateKeyWithAlias]([android-jvm]-private-key-with-alias/index.md)(val alias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?, wrappedKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html))<br>A wrapper for a PrivateKey with an alias. This class is used to store the alias of a key from Android Keystore along with the wrapped PrivateKey. |
