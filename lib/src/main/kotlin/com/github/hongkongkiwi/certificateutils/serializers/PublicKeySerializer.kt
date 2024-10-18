package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.extensions.isPublicKeyPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.PublicKey

class PublicKeySerializer : KSerializer<PublicKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PublicKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PublicKey) {
    if (value.format == "X.509") {
      val pemString = CertificateUtils.getPublicKeyPem(value)
      encoder.encodeString(pemString)
    } else {
      throw IllegalArgumentException("Unsupported key format: ${value.format}")
    }
  }

  override fun deserialize(decoder: Decoder): PublicKey {
    val encoded = decoder.decodeString()

    if (encoded.isPublicKeyPem()) {
      try {
        return CertificateUtils.parsePublicKeyPem(encoded).first()
      } catch (e: Exception) {
        throw IllegalArgumentException(e.message, e)
      }
    } else {
      throw IllegalArgumentException("No Public Key PEM found in string")
    }
  }
}
