//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPublicKey](get-public-key.md)

# getPublicKey

[androidJvm]\
fun [getPublicKey](get-public-key.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)): [PublicKey](https://developer.android.com/reference/kotlin/java/security/PublicKey.html)

Gets the public key corresponding to the provided private key.

#### Return

The generated public key.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The private key for which to get the public key. |

#### Throws

| | |
|---|---|
| [UnsupportedKeyAlgorithmException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-unsupported-key-algorithm-exception/index.md) | If the key algorithm is unsupported. |
