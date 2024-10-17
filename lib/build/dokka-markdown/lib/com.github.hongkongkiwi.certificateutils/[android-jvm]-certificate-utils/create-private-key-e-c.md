//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[createPrivateKeyEC](create-private-key-e-c.md)

# createPrivateKeyEC

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [createPrivateKeyEC](create-private-key-e-c.md)(ecCurve: [ECCurve](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-e-c-curve/index.md) = ECCurve.SECP256R1, keystoreAlias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)? = null, keyPurposes: [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)

Generates an EC private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.

#### Return

The generated EC private key.

#### Parameters

androidJvm

| | |
|---|---|
| ecCurve | The elliptic curve to use (default is SECP256R1). |
| keystoreAlias | The alias for the Android Keystore. If null, a normal private key is generated. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If the EC algorithm is not available. |
| [NoSuchProviderException](https://developer.android.com/reference/kotlin/java/security/NoSuchProviderException.html) | If the Android Keystore provider is not available. |
| [InvalidAlgorithmParameterException](https://developer.android.com/reference/kotlin/java/security/InvalidAlgorithmParameterException.html) | If the KeyGenParameterSpec is invalid. |
