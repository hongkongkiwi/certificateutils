//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificatesPem](get-certificates-pem.md)

# getCertificatesPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCertificatesPem](get-certificates-pem.md)(certificates: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts a list of X509Certificates to a single PEM-formatted string.

This method iterates over each certificate in the list and uses the getCertificatePem method to convert each certificate to its PEM format.

#### Return

The concatenated PEM-formatted certificates string, with each certificate separated by newlines.

#### Parameters

androidJvm

| | |
|---|---|
| certificates | The list of X509Certificate objects. |
