//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.models](../index.md)/[[androidJvm]PrivateKeyWithAlias](index.md)

# PrivateKeyWithAlias

[androidJvm]\
@Serializable

class [PrivateKeyWithAlias](index.md)(val alias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?, wrappedKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html))

A wrapper for a PrivateKey with an alias. This class is used to store the alias of a key from Android Keystore along with the wrapped PrivateKey.

## Constructors

| | |
|---|---|
| [PrivateKeyWithAlias](-private-key-with-alias.md) | [androidJvm]<br>constructor(alias: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?, wrappedKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)) |

## Properties

| Name | Summary |
|---|---|
| [alias](alias.md) | [androidJvm]<br>val [alias](alias.md): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?<br>The alias of the key in the Android Keystore. |

## Functions

| Name | Summary |
|---|---|
| [equals](equals.md) | [androidJvm]<br>open operator override fun [equals](equals.md)(other: [Any](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-any/index.html)?): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html) |
| [getWrappedKey](get-wrapped-key.md) | [androidJvm]<br>fun [getWrappedKey](get-wrapped-key.md)(): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)<br>Returns the wrapped PrivateKey. |
| [hashCode](hash-code.md) | [androidJvm]<br>open override fun [hashCode](hash-code.md)(): [Int](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-int/index.html) |
| [toString](to-string.md) | [androidJvm]<br>open override fun [toString](to-string.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html) |
