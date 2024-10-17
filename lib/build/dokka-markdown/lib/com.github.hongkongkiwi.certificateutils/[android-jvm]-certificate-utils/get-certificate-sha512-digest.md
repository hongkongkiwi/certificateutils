//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificateSha512Digest](get-certificate-sha512-digest.md)

# getCertificateSha512Digest

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCertificateSha512Digest](get-certificate-sha512-digest.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Generates a SHA-512 hash of the given X509 certificate.

#### Return

The SHA-512 hash as a hex string.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate object. |

#### Throws

| | |
|---|---|
| [NoSuchAlgorithmException](https://developer.android.com/reference/kotlin/java/security/NoSuchAlgorithmException.html) | If SHA-512 algorithm is not available. |
