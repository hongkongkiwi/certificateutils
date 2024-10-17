//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getPrivateKeyPemMarkers](get-private-key-pem-markers.md)

# getPrivateKeyPemMarkers

[androidJvm]\
fun [getPrivateKeyPemMarkers](get-private-key-pem-markers.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)): [Pair](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-pair/index.html)&lt;[String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html), [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)&gt;

Determines the appropriate PEM markers based on the PrivateKey type.

This method checks the algorithm of the PrivateKey (e.g., RSA, EC, DSA, Ed25519, Ed448, etc.) and returns the correct PEM begin and end markers for the key type.

#### Return

A pair of strings representing the PEM begin and end markers for the key type.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The PrivateKey object to determine the PEM type for. |
