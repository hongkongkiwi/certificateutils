//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[createPrivateKeyDH](create-private-key-d-h.md)

# createPrivateKeyDH

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [createPrivateKeyDH](create-private-key-d-h.md)(keySize: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = 2048, keystoreAlias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? = null, keyPurposes: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)

Generates a Diffie-Hellman (DH) private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.

#### Return

The generated DH private key.

#### Parameters

androidJvm

| | |
|---|---|
| keySize | The size of the key in bits (default is 2048). |
| keystoreAlias | The alias for the Android Keystore. If null, a normal private key is generated. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If the DH algorithm is not available. |
| [NoSuchProviderException](https://developer.android.com/reference/kotlin/java/security/NoSuchProviderException.html) | If the Android Keystore provider is not available. |
| [InvalidAlgorithmParameterException](https://developer.android.com/reference/kotlin/java/security/InvalidAlgorithmParameterException.html) | If the KeyGenParameterSpec is invalid. |
| [UnsupportedKeyAlgorithmException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-unsupported-key-algorithm-exception/index.md) | If the algorithm is unsupported on lower SDK versions. |
