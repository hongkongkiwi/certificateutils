//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.serializers](../index.md)/[[androidJvm]X509CertificateSerializer](index.md)

# X509CertificateSerializer

[androidJvm]\
object [X509CertificateSerializer](index.md) : KSerializer&lt;[X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)&gt;

## Properties

| Name | Summary |
|---|---|
| [descriptor](descriptor.md) | [androidJvm]<br>open override val [descriptor](descriptor.md): SerialDescriptor |

## Functions

| Name | Summary |
|---|---|
| [deserialize](deserialize.md) | [androidJvm]<br>open override fun [deserialize](deserialize.md)(decoder: Decoder): [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html) |
| [serialize](serialize.md) | [androidJvm]<br>open override fun [serialize](serialize.md)(encoder: Encoder, value: [X509Certificate](https://developer.android.com/reference/kotlin/java/security/cert/X509Certificate.html)) |
