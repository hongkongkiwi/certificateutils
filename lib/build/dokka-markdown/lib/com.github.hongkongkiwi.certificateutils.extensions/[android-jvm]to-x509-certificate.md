//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]toX509Certificate]([android-jvm]to-x509-certificate.md)

# toX509Certificate

[androidJvm]\
fun [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html).[toX509Certificate]([android-jvm]to-x509-certificate.md)(allowExpired: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html) = false): [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)

Converts a PEM encoded string to an X509Certificate.

#### Return

The parsed X509Certificate.

#### Parameters

androidJvm

| | |
|---|---|
| allowExpired | If true, allows expired certificates. |
