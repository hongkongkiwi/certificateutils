//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificateMd5Digest](get-certificate-md5-digest.md)

# getCertificateMd5Digest

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCertificateMd5Digest](get-certificate-md5-digest.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Generates an MD5 hash of the given X509 certificate.

#### Return

The MD5 hash as a hex string.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate object. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If MD5 algorithm is not available. |
