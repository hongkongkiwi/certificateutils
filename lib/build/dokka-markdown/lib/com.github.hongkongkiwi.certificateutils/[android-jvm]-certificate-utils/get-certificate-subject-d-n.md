//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificateSubjectDN](get-certificate-subject-d-n.md)

# getCertificateSubjectDN

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCertificateSubjectDN](get-certificate-subject-d-n.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Extracts the subject distinguished name (DN) from an X.509 certificate.

This method retrieves the subject's distinguished name as a string from the provided X.509 certificate object.

#### Return

The subject distinguished name (DN) string extracted from the certificate.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate object representing the certificate from which     to extract the subject. |

#### Throws

| | |
|---|---|
| [InvalidCertificatePemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-certificate-pem-exception/index.md) | If the certificate is invalid or cannot be processed. |
