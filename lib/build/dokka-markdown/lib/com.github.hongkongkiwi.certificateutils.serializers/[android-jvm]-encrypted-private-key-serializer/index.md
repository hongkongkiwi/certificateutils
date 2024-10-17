//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.serializers](../index.md)/[[androidJvm]EncryptedPrivateKeySerializer](index.md)

# EncryptedPrivateKeySerializer

[androidJvm]\
class [EncryptedPrivateKeySerializer](index.md)(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)) : KSerializer&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;

## Constructors

| | |
|---|---|
| [EncryptedPrivateKeySerializer](-encrypted-private-key-serializer.md) | [androidJvm]<br>constructor(passphrase: [CharArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-char-array/index.html)) |

## Properties

| Name | Summary |
|---|---|
| [descriptor](descriptor.md) | [androidJvm]<br>open override val [descriptor](descriptor.md): SerialDescriptor |

## Functions

| Name | Summary |
|---|---|
| [deserialize](deserialize.md) | [androidJvm]<br>open override fun [deserialize](deserialize.md)(decoder: Decoder): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html) |
| [serialize](serialize.md) | [androidJvm]<br>open override fun [serialize](serialize.md)(encoder: Encoder, value: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)) |
