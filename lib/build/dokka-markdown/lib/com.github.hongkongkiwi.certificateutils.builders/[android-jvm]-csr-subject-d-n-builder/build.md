//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.builders](../index.md)/[[androidJvm]CsrSubjectDNBuilder](index.md)/[build](build.md)

# build

[androidJvm]\
fun [build](build.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Builds the subject DN string using the set attributes.

#### Return

The constructed subject DN string.

#### Throws

| | |
|---|---|
| [IllegalArgumentException](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-illegal-argument-exception/index.html) | If the required attributes are not set (e.g., country). |
