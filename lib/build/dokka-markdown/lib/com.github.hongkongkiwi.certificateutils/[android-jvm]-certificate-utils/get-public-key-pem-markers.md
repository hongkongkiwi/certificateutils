//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPublicKeyPemMarkers](get-public-key-pem-markers.md)

# getPublicKeyPemMarkers

[androidJvm]\
fun [getPublicKeyPemMarkers](get-public-key-pem-markers.md)(publicKey: [PublicKey](https://developer.android.com/reference/kotlin/java/security/PublicKey.html)): [Pair](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-pair/index.html)&lt;[String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html), [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)&gt;

Determines the appropriate PEM markers based on the PublicKey type.

This method checks the algorithm of the PublicKey (e.g., RSA, EC, DSA, Ed25519, Ed448, etc.) and returns the correct PEM begin and end markers for the key type.

#### Return

A pair of strings representing the PEM begin and end markers for the key type.

#### Parameters

androidJvm

| | |
|---|---|
| publicKey | The PublicKey object to determine the PEM type for. |
