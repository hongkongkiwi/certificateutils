//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isCertificateValid](is-certificate-valid.md)

# isCertificateValid

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [isCertificateValid](is-certificate-valid.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if the provided X.509 certificate is valid and not expired.

This method verifies the validity of the certificate by checking its expiration date and whether it is not yet valid. It returns true if the certificate is valid, and false if it has expired or is not yet valid.

#### Return

True if the certificate is valid; false if it is expired or not yet valid.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate object representing the certificate to validate. |

#### Throws

| | |
|---|---|
| [InvalidCertificatePemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-certificate-pem-exception/index.md) | If the certificate cannot be validated due to an invalid format or issue. |
