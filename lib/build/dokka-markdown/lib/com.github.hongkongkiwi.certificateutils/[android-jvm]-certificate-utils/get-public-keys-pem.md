//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPublicKeysPem](get-public-keys-pem.md)

# getPublicKeysPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getPublicKeysPem](get-public-keys-pem.md)(publicKeys: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[PublicKey](https://developer.android.com/reference/kotlin/java/security/PublicKey.html)&gt;): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts a list of PublicKeys to a single PEM-formatted string.

This method iterates over each public key in the list and uses the getPublicKeyPem method to convert each key to its PEM format.

#### Return

The concatenated PEM-formatted public keys string, with each key separated by newlines.

#### Parameters

androidJvm

| | |
|---|---|
| publicKeys | The list of PublicKey objects to be converted. |
