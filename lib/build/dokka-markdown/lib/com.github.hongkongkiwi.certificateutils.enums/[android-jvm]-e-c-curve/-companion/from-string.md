//[lib](../../../../index.md)/[com.github.hongkongkiwi.certificateutils.enums](../../index.md)/[[androidJvm]ECCurve](../index.md)/[Companion](index.md)/[fromString](from-string.md)

# fromString

[androidJvm]\
fun [fromString](from-string.md)(curveName: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [ECCurve](../index.md)

Retrieves the corresponding ECCurve enum value for the provided curve name.

#### Return

The corresponding ECCurve enum value.

#### Parameters

androidJvm

| | |
|---|---|
| curveName | The string representation of the curve name. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the curve name is not recognized. |
