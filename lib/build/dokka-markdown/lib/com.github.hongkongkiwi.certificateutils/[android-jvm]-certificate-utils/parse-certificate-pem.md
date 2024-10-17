//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[parseCertificatePem](parse-certificate-pem.md)

# parseCertificatePem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [parseCertificatePem](parse-certificate-pem.md)(certificatePem: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html), allowExpired: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html) = false): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;

Parses a PEM-formatted X.509 certificate(s) and returns a list of corresponding X509Certificate objects.

This method extracts the base64-encoded certificate content from the provided PEM string, decodes it, and generates a list of X509Certificates. It can also validate the certificates' expiration status based on the provided parameter.

#### Return

A list of parsed X509Certificate objects.

#### Parameters

androidJvm

| | |
|---|---|
| certificatePem | The PEM-formatted certificate string to parse. |
| allowExpired | A boolean indicating whether to allow expired certificates.     If false, an exception will be thrown for expired certificates. |

#### Throws

| | |
|---|---|
| [InvalidCertificatePemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-certificate-pem-exception/index.md) | If the PEM content is invalid or cannot be extracted. |
| [ExpiredCertificateException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-expired-certificate-exception/index.md) | If any of the certificates has expired and expiration checking is enabled. |
| [UntrustedCertificateException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-untrusted-certificate-exception/index.md) | If any certificate is not trusted based on your trust policy. |
