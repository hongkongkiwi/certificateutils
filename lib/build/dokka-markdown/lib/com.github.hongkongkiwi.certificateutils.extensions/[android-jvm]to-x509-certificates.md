//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]toX509Certificates]([android-jvm]to-x509-certificates.md)

# toX509Certificates

[androidJvm]\
fun [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html).[toX509Certificates]([android-jvm]to-x509-certificates.md)(allowExpired: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html) = false): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;

Converts a PEM encoded string to a list of X509Certificates.

#### Return

A list of parsed X509Certificates.

#### Parameters

androidJvm

| | |
|---|---|
| allowExpired | If true, allows expired certificates. |
