package com.github.hongkongkiwi.serializers

import com.github.hongkongkiwi.models.PrivateKeyWithAlias
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.KeyStore
import java.security.PrivateKey

class PrivateKeyWithAliasSerializer : KSerializer<PrivateKeyWithAlias> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKeyWithAlias", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKeyWithAlias) {
    value.alias?.let { encoder.encodeString(it) }
  }

  override fun deserialize(decoder: Decoder): PrivateKeyWithAlias {
    val alias = decoder.decodeString()

    // Retrieve the private key from the Android Keystore using the alias
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    val privateKey = keyStore.getKey(alias, null) as PrivateKey
    return PrivateKeyWithAlias(alias, privateKey)
  }
}
