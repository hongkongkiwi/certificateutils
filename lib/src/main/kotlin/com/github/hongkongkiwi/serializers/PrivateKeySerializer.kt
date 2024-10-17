package com.github.hongkongkiwi.serializers

import com.github.hongkongkiwi.CertificateUtils
import com.github.hongkongkiwi.extensions.isPrivateKeyPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.PrivateKey

class PrivateKeySerializer : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    if (value.format == "PKCS#8") {
      val pemString = CertificateUtils.getPrivateKeyPem(value)
      encoder.encodeString(pemString)
    } else {
      throw IllegalArgumentException("Unsupported key format: ${value.format}")
    }
  }

  override fun deserialize(decoder: Decoder): PrivateKey {
    val encoded = decoder.decodeString()

    if (encoded.isPrivateKeyPem()) {
      return CertificateUtils.parsePrivateKeyPem(encoded).first()
    } else {
      throw IllegalArgumentException("Invalid PEM format for PrivateKey")
    }
  }
}
