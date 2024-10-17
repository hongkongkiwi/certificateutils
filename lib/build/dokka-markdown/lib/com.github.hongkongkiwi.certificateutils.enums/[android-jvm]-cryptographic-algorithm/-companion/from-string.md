//[lib](../../../../index.md)/[com.github.hongkongkiwi.certificateutils.enums](../../index.md)/[[androidJvm]CryptographicAlgorithm](../index.md)/[Companion](index.md)/[fromString](from-string.md)

# fromString

[androidJvm]\
fun [fromString](from-string.md)(algorithmName: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [CryptographicAlgorithm](../index.md)

Gets the Algorithm enum for a given algorithm name.

This function takes a string representation of an algorithm name and returns the corresponding Algorithm enum value.

#### Return

The corresponding Algorithm enum value.

#### Parameters

androidJvm

| | |
|---|---|
| algorithmName | The name of the algorithm as a String. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the algorithm name is not recognized. |
