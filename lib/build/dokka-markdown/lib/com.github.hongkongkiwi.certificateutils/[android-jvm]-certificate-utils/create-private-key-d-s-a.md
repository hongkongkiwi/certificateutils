//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[createPrivateKeyDSA](create-private-key-d-s-a.md)

# createPrivateKeyDSA

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [createPrivateKeyDSA](create-private-key-d-s-a.md)(keySize: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = 2048, keystoreAlias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? = null, keyPurposes: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = KeyProperties.PURPOSE_SIGN): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)

Generates a DSA private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.

#### Return

The generated DSA private key.

#### Parameters

androidJvm

| | |
|---|---|
| keySize | The size of the key in bits (default is 2048). |
| keystoreAlias | The alias for the Android Keystore. If null, a normal private key is generated. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If the DSA algorithm is not available. |
| [NoSuchProviderException](https://developer.android.com/reference/kotlin/java/security/NoSuchProviderException.html) | If the Android Keystore provider is not available. |
| [InvalidAlgorithmParameterException](https://developer.android.com/reference/kotlin/java/security/InvalidAlgorithmParameterException.html) | If the KeyGenParameterSpec is invalid. |
