//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isCertificateTrusted](is-certificate-trusted.md)

# isCertificateTrusted

[androidJvm]\
fun [isCertificateTrusted](is-certificate-trusted.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html), trustedCertificates: [Set](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-set/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;? = null): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if the provided certificate is trusted by comparing it against a set of trusted certificates.

This method iterates through the provided set of trusted certificates to determine if the given certificate matches any of them based on content equality.

#### Return

True if the certificate is found in the set of trusted certificates; false otherwise.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate to check for trust. |
| trustedCertificates | A set of trusted X509Certificate objects to compare against.     If null, the method will load trusted certificates from a predefined source. |
