//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.serializers](../index.md)/[[androidJvm]PrivateKeySerializer](index.md)

# PrivateKeySerializer

[androidJvm]\
class [PrivateKeySerializer](index.md) : KSerializer&lt;[PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)&gt;

## Constructors

| | |
|---|---|
| [PrivateKeySerializer](-private-key-serializer.md) | [androidJvm]<br>constructor() |

## Properties

| Name | Summary |
|---|---|
| [descriptor](descriptor.md) | [androidJvm]<br>open override val [descriptor](descriptor.md): SerialDescriptor |

## Functions

| Name | Summary |
|---|---|
| [deserialize](deserialize.md) | [androidJvm]<br>open override fun [deserialize](deserialize.md)(decoder: Decoder): [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html) |
| [serialize](serialize.md) | [androidJvm]<br>open override fun [serialize](serialize.md)(encoder: Encoder, value: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)) |
