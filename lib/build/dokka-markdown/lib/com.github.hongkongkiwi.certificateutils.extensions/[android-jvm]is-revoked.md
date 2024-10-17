//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]isRevoked]([android-jvm]is-revoked.md)

# isRevoked

[androidJvm]\
fun [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html).[isRevoked]([android-jvm]is-revoked.md)(crl: [CRL](https://developer.android.com/reference/kotlin/java/security/cert/CRL.html)): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if the X509Certificate is revoked according to the provided Certificate Revocation List (CRL).

#### Return

True if the certificate is revoked, false otherwise.

#### Parameters

androidJvm

| | |
|---|---|
| crl | The CRL to check against. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | if the provided CRL is not of type X509CRL. |
