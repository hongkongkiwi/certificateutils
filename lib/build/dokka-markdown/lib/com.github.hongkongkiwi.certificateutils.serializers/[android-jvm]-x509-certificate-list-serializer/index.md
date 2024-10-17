//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.serializers](../index.md)/[[androidJvm]X509CertificateListSerializer](index.md)

# X509CertificateListSerializer

[androidJvm]\
object [X509CertificateListSerializer](index.md) : KSerializer&lt;[List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;&gt;

## Properties

| Name | Summary |
|---|---|
| [descriptor](descriptor.md) | [androidJvm]<br>open override val [descriptor](descriptor.md): SerialDescriptor |

## Functions

| Name | Summary |
|---|---|
| [deserialize](deserialize.md) | [androidJvm]<br>open override fun [deserialize](deserialize.md)(decoder: Decoder): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt; |
| [serialize](serialize.md) | [androidJvm]<br>open override fun [serialize](serialize.md)(encoder: Encoder, value: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;) |
