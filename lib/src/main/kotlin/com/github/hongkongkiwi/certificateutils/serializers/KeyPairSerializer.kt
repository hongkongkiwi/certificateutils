package com.github.hongkongkiwi.certificateutils.serializers

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

class KeyPairSerializer : KSerializer<KeyPair> {

  override val descriptor: SerialDescriptor = buildClassSerialDescriptor("KeyPair") {
    element("privateKey", PrivateKeySerializer().descriptor)
    element("publicKey", PublicKeySerializer().descriptor)
  }

  override fun serialize(encoder: Encoder, value: KeyPair) {
    // Check if the private key is from the Android Keystore
    if (isFromAndroidKeyStore(value.private)) {
      throw IllegalArgumentException("Cannot serialize a PrivateKey stored in the Android Keystore.")
    }

    encoder.encodeStructure(descriptor) {
      encodeSerializableElement(descriptor, 0, PrivateKeySerializer(), value.private)
      encodeSerializableElement(descriptor, 1, PublicKeySerializer(), value.public)
    }
  }

  override fun deserialize(decoder: Decoder): KeyPair {
    return decoder.decodeStructure(descriptor) {
      lateinit var privateKey: PrivateKey
      lateinit var publicKey: PublicKey

      while (true) {
        when (val index = decodeElementIndex(descriptor)) {
          0 -> privateKey = decodeSerializableElement(descriptor, 0, PrivateKeySerializer())
          1 -> publicKey = decodeSerializableElement(descriptor, 1, PublicKeySerializer())
          CompositeDecoder.DECODE_DONE -> break
          else -> throw IllegalArgumentException("Unexpected index: $index")
        }
      }

      KeyPair(publicKey, privateKey)
    }
  }

  /**
   * Checks whether the private key is from the Android Keystore.
   * Replace this with your actual implementation for checking.
   */
  private fun isFromAndroidKeyStore(privateKey: PrivateKey): Boolean {
    // Check if the private key comes from Android Keystore.
    // This logic will depend on your project's specific implementation.
    return privateKey.algorithm.contains("AndroidKeyStore", ignoreCase = true)
  }
}
