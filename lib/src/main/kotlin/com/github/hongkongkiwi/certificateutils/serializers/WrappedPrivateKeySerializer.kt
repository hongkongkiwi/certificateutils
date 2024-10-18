package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.extensions.toPem
import com.github.hongkongkiwi.certificateutils.extensions.toPrivateKey
import com.github.hongkongkiwi.certificateutils.models.WrappedPrivateKey
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import java.security.KeyStore
import java.security.PrivateKey

class WrappedPrivateKeySerializer : KSerializer<WrappedPrivateKey> {

  override val descriptor: SerialDescriptor = buildClassSerialDescriptor("WrappedPrivateKey") {
    element<String>("alias")
    element<String>("wrappedKey") // For PEM serialization when alias is empty
  }

  override fun serialize(encoder: Encoder, value: WrappedPrivateKey) {
    encoder.encodeStructure(descriptor) {
      encodeStringElement(descriptor, 0, value.alias ?: "")

      // If alias is null or empty, serialize the PrivateKey directly to PEM format
      if (value.alias.isNullOrEmpty()) {
        encodeStringElement(descriptor, 1, value.getWrappedKey().toPem())
      }
    }
  }

  override fun deserialize(decoder: Decoder): WrappedPrivateKey {
    return decoder.decodeStructure(descriptor) {
      var alias: String? = null
      var pemKey: String? = null

      while (true) {
        when (val index = decodeElementIndex(descriptor)) {
          0 -> alias = decodeStringElement(descriptor, 0)
          1 -> pemKey = decodeStringElement(descriptor, 1) // For deserializing PEM format
          CompositeDecoder.DECODE_DONE -> break
          else -> throw SerializationException("Unexpected index: $index")
        }
      }

      return@decodeStructure if (alias.isNullOrEmpty()) {
        // Deserialize the PEM key to PrivateKey
        val privateKey = pemKey?.toPrivateKey()
          ?: throw IllegalArgumentException("Failed to deserialize private key from PEM")

        WrappedPrivateKey(alias, privateKey)
      } else {
        try {
          // Retrieve the private key from the Android Keystore using the alias
          val keyStore = KeyStore.getInstance("AndroidKeyStore")
          keyStore.load(null)
          val privateKey = keyStore.getKey(alias, null) as PrivateKey
          WrappedPrivateKey(alias, privateKey)
        } catch (e: Exception) {
          throw IllegalArgumentException("Failed to retrieve private key with alias: $alias", e)
        }
      }
    }
  }
}
