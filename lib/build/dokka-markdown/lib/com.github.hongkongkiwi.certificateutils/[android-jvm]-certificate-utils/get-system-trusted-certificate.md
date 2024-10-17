//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getSystemTrustedCertificate](get-system-trusted-certificate.md)

# getSystemTrustedCertificate

[androidJvm]\
fun [getSystemTrustedCertificate](get-system-trusted-certificate.md)(): [Set](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-set/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;

Loads the set of trusted X.509 certificates from the default trust store.

This method initializes a TrustManagerFactory with the default algorithm, retrieves the trust managers, and extracts the accepted issuers (trusted certificates).

#### Return

A set of X509Certificate objects representing the trusted certificates from the default trust store.

#### Throws

| | |
|---|---|
| [IllegalStateException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-state-exception/index.html) | If no X509TrustManager is found in the trust managers. |
