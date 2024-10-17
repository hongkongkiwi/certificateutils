//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.enums](../index.md)/[[androidJvm]ECCurve](index.md)

# ECCurve

[androidJvm]\
enum [ECCurve](index.md) : [Enum](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-enum/index.html)&lt;[ECCurve](index.md)&gt; 

Enum class for Elliptic Curves (EC).

This enum represents various standardized elliptic curves used in cryptography, allowing easy reference and validation of curve types in the application.

Each curve is represented by its standard name, which is used in cryptographic operations.

## Entries

| | |
|---|---|
| [SECP192R1](-s-e-c-p192-r1/index.md) | [androidJvm]<br>[SECP192R1](-s-e-c-p192-r1/index.md)<br>NIST P-192 curve |
| [SECP224R1](-s-e-c-p224-r1/index.md) | [androidJvm]<br>[SECP224R1](-s-e-c-p224-r1/index.md)<br>NIST P-224 curve |
| [SECP256R1](-s-e-c-p256-r1/index.md) | [androidJvm]<br>[SECP256R1](-s-e-c-p256-r1/index.md)<br>NIST P-256 curve (also known as prime256v1) |
| [SECP384R1](-s-e-c-p384-r1/index.md) | [androidJvm]<br>[SECP384R1](-s-e-c-p384-r1/index.md)<br>NIST P-384 curve |
| [SECP521R1](-s-e-c-p521-r1/index.md) | [androidJvm]<br>[SECP521R1](-s-e-c-p521-r1/index.md)<br>NIST P-521 curve |
| [BRAINPOOL192R1](-b-r-a-i-n-p-o-o-l192-r1/index.md) | [androidJvm]<br>[BRAINPOOL192R1](-b-r-a-i-n-p-o-o-l192-r1/index.md)<br>Brainpool P-192 curve |
| [BRAINPOOL224R1](-b-r-a-i-n-p-o-o-l224-r1/index.md) | [androidJvm]<br>[BRAINPOOL224R1](-b-r-a-i-n-p-o-o-l224-r1/index.md)<br>Brainpool P-224 curve |
| [BRAINPOOL256R1](-b-r-a-i-n-p-o-o-l256-r1/index.md) | [androidJvm]<br>[BRAINPOOL256R1](-b-r-a-i-n-p-o-o-l256-r1/index.md)<br>Brainpool P-256 curve |
| [BRAINPOOL384R1](-b-r-a-i-n-p-o-o-l384-r1/index.md) | [androidJvm]<br>[BRAINPOOL384R1](-b-r-a-i-n-p-o-o-l384-r1/index.md)<br>Brainpool P-384 curve |
| [BRAINPOOL512R1](-b-r-a-i-n-p-o-o-l512-r1/index.md) | [androidJvm]<br>[BRAINPOOL512R1](-b-r-a-i-n-p-o-o-l512-r1/index.md)<br>Brainpool P-512 curve |
| [CURVE25519](-c-u-r-v-e25519/index.md) | [androidJvm]<br>[CURVE25519](-c-u-r-v-e25519/index.md)<br>Curve25519, optimized for speed |
| [ED25519](-e-d25519/index.md) | [androidJvm]<br>[ED25519](-e-d25519/index.md)<br>Ed25519, optimized for digital signatures |
| [X25519](-x25519/index.md) | [androidJvm]<br>[X25519](-x25519/index.md)<br>X25519 for key exchange |
| [SECP256K1](-s-e-c-p256-k1/index.md) | [androidJvm]<br>[SECP256K1](-s-e-c-p256-k1/index.md)<br>Koblitz curve used in Bitcoin |

## Types

| Name | Summary |
|---|---|
| [Companion](-companion/index.md) | [androidJvm]<br>object [Companion](-companion/index.md) |

## Properties

| Name | Summary |
|---|---|
| [curveName](curve-name.md) | [androidJvm]<br>val [curveName](curve-name.md): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html) |
| [entries](entries.md) | [androidJvm]<br>val [entries](entries.md): [EnumEntries](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.enums/-enum-entries/index.html)&lt;[ECCurve](index.md)&gt;<br>Returns a representation of an immutable list of all enum entries, in the order they're declared. |
| [name](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-372974862%2FProperties%2F-1973928616) | [androidJvm]<br>val [name](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-372974862%2FProperties%2F-1973928616): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html) |
| [ordinal](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-739389684%2FProperties%2F-1973928616) | [androidJvm]<br>val [ordinal](../[android-jvm]-signature-algorithm/-s-h-a512_-w-i-t-h_-e-d-d-s-a/index.md#-739389684%2FProperties%2F-1973928616): [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) |

## Functions

| Name | Summary |
|---|---|
| [toString](to-string.md) | [androidJvm]<br>open override fun [toString](to-string.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html) |
| [valueOf](value-of.md) | [androidJvm]<br>fun [valueOf](value-of.md)(value: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [ECCurve](index.md)<br>Returns the enum constant of this type with the specified name. The string must match exactly an identifier used to declare an enum constant in this type. (Extraneous whitespace characters are not permitted.) |
| [values](values.md) | [androidJvm]<br>fun [values](values.md)(): [Array](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-array/index.html)&lt;[ECCurve](index.md)&gt;<br>Returns an array containing the constants of this enum type, in the order they're declared. |
