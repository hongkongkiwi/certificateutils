package com.github.hongkongkiwi.certificateutils.serializers

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.X509Certificate

object X509CertificateListSerializer : KSerializer<List<X509Certificate>> {

  private val delegateSerializer = ListSerializer(X509CertificateSerializer)

  override val descriptor: SerialDescriptor = delegateSerializer.descriptor

  override fun serialize(encoder: Encoder, value: List<X509Certificate>) {
    delegateSerializer.serialize(encoder, value)
  }

  override fun deserialize(decoder: Decoder): List<X509Certificate> {
    return delegateSerializer.deserialize(decoder)
  }
}
