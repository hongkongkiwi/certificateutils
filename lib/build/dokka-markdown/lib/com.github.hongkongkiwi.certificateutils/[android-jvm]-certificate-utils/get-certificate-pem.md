//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificatePem](get-certificate-pem.md)

# getCertificatePem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCertificatePem](get-certificate-pem.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts an X509Certificate to PEM format.

#### Return

The PEM-formatted certificate string with appropriate markers based on the certificate type.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate object. |
