//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCertificateFingerprint](get-certificate-fingerprint.md)

# getCertificateFingerprint

[androidJvm]\
fun [getCertificateFingerprint](get-certificate-fingerprint.md)(certificateData: [ByteArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/index.html), digestAlgorithm: [DigestAlgorithm](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-digest-algorithm/index.md)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Generates a certificate digets for the given data using the specified fingerprint algorithm.

#### Return

The generated fingerprint as a hex string.

#### Parameters

androidJvm

| | |
|---|---|
| certificateData | The data to generate a fingerprint for. |
| digestAlgorithm | The fingerprint algorithm to use. |

#### Throws

| | |
|---|---|
| [Exception](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-exception/index.html) | If the digest algorithm is not available or an error occurs during processing. |

[androidJvm]\
fun [getCertificateFingerprint](get-certificate-fingerprint.md)(certificate: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html), digestAlgorithm: [DigestAlgorithm](../../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-digest-algorithm/index.md)): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Generates a fingerprint for the given X509Certificate using the specified fingerprint algorithm.

#### Return

The generated fingerprint as a hex string.

#### Parameters

androidJvm

| | |
|---|---|
| certificate | The X509Certificate to generate a fingerprint for. |
| digestAlgorithm | The fingerprint algorithm to use. |

#### Throws

| | |
|---|---|
| [Exception](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-exception/index.html) | If the digest algorithm is not available or an error occurs during processing. |
