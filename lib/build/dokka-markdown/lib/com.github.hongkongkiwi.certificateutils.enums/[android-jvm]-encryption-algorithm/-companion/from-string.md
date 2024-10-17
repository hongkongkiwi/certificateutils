//[lib](../../../../index.md)/[com.github.hongkongkiwi.certificateutils.enums](../../index.md)/[[androidJvm]EncryptionAlgorithm](../index.md)/[Companion](index.md)/[fromString](from-string.md)

# fromString

[androidJvm]\
fun [fromString](from-string.md)(algorithmName: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [EncryptionAlgorithm](../index.md)

Gets the EncryptionAlgorithm enum for a given algorithm name.

#### Return

The corresponding EncryptionAlgorithm enum.

#### Parameters

androidJvm

| | |
|---|---|
| algorithmName | The name of the algorithm. |

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the algorithm name is not recognized. |
