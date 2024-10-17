//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCurveNameFromKey](get-curve-name-from-key.md)

# getCurveNameFromKey

[androidJvm]\
fun [getCurveNameFromKey](get-curve-name-from-key.md)(privateKey: [ECPrivateKey](https://developer.android.com/reference/kotlin/java/security/interfaces/ECPrivateKey.html)): [ECCurve](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-e-c-curve/index.md)

Retrieves the standard name of the elliptic curve used in the specified EC private key.

This method takes an ECPrivateKey and extracts the curve parameters associated with it. It then uses these parameters to obtain the standard curve name, which can be useful for identifying the type of elliptic curve used for cryptographic operations.

#### Return

The name of the elliptic curve as a String, or null if the key is not an EC private key.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The ECPrivateKey from which to retrieve the curve name. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the provided private key does not contain valid curve parameters. |
