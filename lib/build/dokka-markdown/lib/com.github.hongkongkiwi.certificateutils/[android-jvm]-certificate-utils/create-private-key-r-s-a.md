//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[createPrivateKeyRSA](create-private-key-r-s-a.md)

# createPrivateKeyRSA

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [createPrivateKeyRSA](create-private-key-r-s-a.md)(keySize: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = 2048, keystoreAlias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? = null, keyPurposes: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)

Generates an RSA private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.

#### Return

The generated RSA private key.

#### Parameters

androidJvm

| | |
|---|---|
| keySize | The size of the key in bits (default is 2048). |
| keystoreAlias | The alias for the Android Keystore. If null, a normal private key is generated. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If the RSA algorithm is not available. |
| [NoSuchProviderException](https://developer.android.com/reference/kotlin/java/security/NoSuchProviderException.html) | If the Android Keystore provider is not available. |
| [InvalidAlgorithmParameterException](https://developer.android.com/reference/kotlin/java/security/InvalidAlgorithmParameterException.html) | If the KeyGenParameterSpec is invalid. |
