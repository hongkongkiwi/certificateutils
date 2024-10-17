//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isCertificateSignedByPrivateKey](is-certificate-signed-by-private-key.md)

# isCertificateSignedByPrivateKey

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [isCertificateSignedByPrivateKey](is-certificate-signed-by-private-key.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html), privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Ensures the provided X509Certificate and PrivateKey form a matching key pair.

#### Return

True if the private key matches the public key from the certificate.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate to compare. |
| privateKey | The PrivateKey to compare. |

#### Throws

| | |
|---|---|
| [KeyPairMismatchException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-key-pair-mismatch-exception/index.md) | If the private key does not match the certificate's public key. |
| [UnsupportedKeyAlgorithmException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-unsupported-key-algorithm-exception/index.md) | If the private key algorithm is unsupported or not available in the current SDK version. |
