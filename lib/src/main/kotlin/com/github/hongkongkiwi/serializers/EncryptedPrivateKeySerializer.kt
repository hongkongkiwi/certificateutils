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

class EncryptedPrivateKeySerializer(
  private val passphrase: CharArray
) : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("EncryptedPrivateKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    if (value.format == "PKCS#8") {
      // Encrypt the private key and serialize as PEM
      val pemString = CertificateUtils.getPrivateKeyPem(value, passphrase)
      encoder.encodeString(pemString)
    } else {
      throw IllegalArgumentException("Unsupported key format for encryption: ${value.format}")
    }
  }

  override fun deserialize(decoder: Decoder): PrivateKey {
    val encoded = decoder.decodeString()

    if (encoded.isPrivateKeyPem()) {
      return CertificateUtils.parsePrivateKeyPem(encoded, passphrase).first()
    } else {
      throw IllegalArgumentException("Invalid PEM format for encrypted PrivateKey")
    }
  }
}
