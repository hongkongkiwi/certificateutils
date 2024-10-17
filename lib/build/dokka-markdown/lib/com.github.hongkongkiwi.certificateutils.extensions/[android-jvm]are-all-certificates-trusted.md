//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]areAllCertificatesTrusted]([android-jvm]are-all-certificates-trusted.md)

# areAllCertificatesTrusted

[androidJvm]\
fun [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;.[areAllCertificatesTrusted]([android-jvm]are-all-certificates-trusted.md)(trustedRoots: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if all certificates in the list are trusted according to the provided trusted roots.

#### Return

True if all certificates are trusted, false otherwise.

#### Parameters

androidJvm

| | |
|---|---|
| trustedRoots | The list of trusted root certificates. |
