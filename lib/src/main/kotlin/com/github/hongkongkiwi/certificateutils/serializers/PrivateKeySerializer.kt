package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.extensions.getAndroidKeyStoreAlias
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.isPrivateKeyPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.InvalidKeyException

class PrivateKeySerializer : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    try {
      if (value.isFromAndroidKeyStore()) {
        val alias = value.getAndroidKeyStoreAlias()
          ?: throw KeyStoreException("Alias is missing for the PrivateKey from the Android Keystore.")
        encoder.encodeString(alias)
      } else {
        when (value.format) {
          "PKCS#8" -> encoder.encodeString(PEMUtils.getPrivateKeyPem(value, format = "PKCS#8"))
          "PKCS#1" -> encoder.encodeString(PEMUtils.getPrivateKeyPem(value, format = "PKCS#1"))
          "OpenSSH" -> encoder.encodeString(PEMUtils.getOpenSSHPem(value))
          else -> throw InvalidKeyException("Unsupported key format: ${value.format}")
        }
      }
    } catch (e: Exception) {
      throw IllegalArgumentException("Failed to serialize PrivateKey: ${e.message}", e)
    }
  }

  override fun deserialize(decoder: Decoder): PrivateKey {
    val encoded = decoder.decodeString()

    return if (encoded.isPrivateKeyPem()) {
      try {
        PEMUtils.parsePrivateKeyPem(encoded).first()
      } catch (e: Exception) {
        throw InvalidKeyException("Failed to parse the PrivateKey from PEM: ${e.message}", e)
      }
    } else if (encoded.isNotEmpty()) {
      try {
        val privateKey = AndroidKeyStoreUtils.getPrivateKey(encoded)
          ?: throw KeyStoreException("No PrivateKey found for alias: '$encoded'. Ensure the alias exists in the Android Keystore.")
        privateKey
      } catch (e: KeyStoreException) {
        throw KeyStoreException("Keystore access failed: ${e.message}", e)
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to retrieve PrivateKey from alias '$encoded': ${e.message}", e)
      }
    } else {
      throw IllegalArgumentException("Empty or invalid input for PEM or keystore alias.")
    }
  }
}
