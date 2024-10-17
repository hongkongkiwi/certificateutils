//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.enums](../index.md)/[[androidJvm]CryptographicAlgorithm](index.md)

# CryptographicAlgorithm

[androidJvm]\
enum [CryptographicAlgorithm](index.md) : [Enum](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-enum/index.html)&lt;[CryptographicAlgorithm](index.md)&gt; 

Enum representing various cryptographic algorithms.

This enum includes algorithm names used in public key cryptography, allowing easy reference and validation of algorithm types in the application.

## Entries

| | |
|---|---|
| [RSA](-r-s-a/index.md) | [androidJvm]<br>[RSA](-r-s-a/index.md) |
| [EC](-e-c/index.md) | [androidJvm]<br>[EC](-e-c/index.md) |
| [DSA](-d-s-a/index.md) | [androidJvm]<br>[DSA](-d-s-a/index.md) |
| [Ed25519](-ed25519/index.md) | [androidJvm]<br>[Ed25519](-ed25519/index.md) |
| [Ed448](-ed448/index.md) | [androidJvm]<br>[Ed448](-ed448/index.md) |
| [X25519](-x25519/index.md) | [androidJvm]<br>[X25519](-x25519/index.md) |
| [DH](-d-h/index.md) | [androidJvm]<br>[DH](-d-h/index.md) |
| [ECDSA](-e-c-d-s-a/index.md) | [androidJvm]<br>[ECDSA](-e-c-d-s-a/index.md) |

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [androidJvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [entries](entries.md) | [androidJvm]<br>val [entries](entries.md): [EnumEntries](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.enums/-enum-entries/index.html)&lt;[CryptographicAlgorithm](index.md)&gt;<br>Returns a representation of an immutable list of all enum entries, in the order they're declared. |
| [name](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-372974862%2FProperties%2F-1973928616) | [androidJvm]<br>val [name](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-372974862%2FProperties%2F-1973928616): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html) |
| [ordinal](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-739389684%2FProperties%2F-1973928616) | [androidJvm]<br>val [ordinal](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-739389684%2FProperties%2F-1973928616): [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) |

## Functions

| Name | Summary |
|---|---|
| [toString](to-string.md) | [androidJvm]<br>open override fun [toString](to-string.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)<br>Returns a human-readable string representation of the cryptographic algorithm. |
| [valueOf](value-of.md) | [androidJvm]<br>fun [valueOf](value-of.md)(value: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [CryptographicAlgorithm](index.md)<br>Returns the enum constant of this type with the specified name. The string must match exactly an identifier used to declare an enum constant in this type. (Extraneous whitespace characters are not permitted.) |
| [values](values.md) | [androidJvm]<br>fun [values](values.md)(): [Array](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-array/index.html)&lt;[CryptographicAlgorithm](index.md)&gt;<br>Returns an array containing the constants of this enum type, in the order they're declared. |
