//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isCertificateSelfSigned](is-certificate-self-signed.md)

# isCertificateSelfSigned

[androidJvm]\
fun [isCertificateSelfSigned](is-certificate-self-signed.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if the provided X.509 certificate is self-signed.

A self-signed certificate is one where the subject and issuer distinguished names (DNs) are the same, indicating that the certificate was signed by itself rather than a trusted CA.

#### Return

True if the certificate is self-signed; false otherwise.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate to check for self-signing. |
