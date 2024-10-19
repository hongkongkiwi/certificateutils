package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.extensions.getAndroidKeyStoreAlias
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.isPublicKeyPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.PublicKey

class PublicKeySerializer : KSerializer<PublicKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PublicKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PublicKey) {
    try {
      if (value.isFromAndroidKeyStore()) {
        val alias = value.getAndroidKeyStoreAlias()
          ?: throw KeyStoreException("Alias is missing for the PublicKey from the Android Keystore.")
        encoder.encodeString(alias)
      } else {
        when (value.format) {
          "X.509" -> encoder.encodeString(PEMUtils.getPublicKeyPem(value, format = "X.509"))
          "OpenSSH" -> encoder.encodeString(PEMUtils.getOpenSSHPem(value))
          else -> throw InvalidKeyException("Unsupported key format: ${value.format}")
        }
      }
    } catch (e: Exception) {
      throw IllegalArgumentException("Failed to serialize PublicKey: ${e.message}", e)
    }
  }

  override fun deserialize(decoder: Decoder): PublicKey {
    val encoded = decoder.decodeString()

    return if (encoded.isPublicKeyPem()) {
      try {
        PEMUtils.parsePublicKeyPem(encoded).first()
      } catch (e: Exception) {
        throw InvalidKeyException("Failed to parse the PublicKey from PEM: ${e.message}", e)
      }
    } else if (encoded.isNotEmpty()) {
      try {
        return AndroidKeyStoreUtils.getPublicKey(encoded)
          ?: throw KeyStoreException("No PublicKey found for alias: '$encoded'. Ensure the alias exists in the Android Keystore.")
      } catch (e: KeyStoreException) {
        throw KeyStoreException("Keystore access failed: ${e.message}", e)
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to retrieve PublicKey from alias '$encoded': ${e.message}", e)
      }
    } else {
      throw IllegalArgumentException("Empty or invalid input for PEM or keystore alias.")
    }
  }
}
