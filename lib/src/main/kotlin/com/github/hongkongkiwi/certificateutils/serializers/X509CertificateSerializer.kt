package com.github.hongkongkiwi.certificateutils.serializers

import android.util.Log
import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.extensions.toPem
import com.github.hongkongkiwi.certificateutils.extensions.toX509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.X509Certificate

object X509CertificateSerializer : KSerializer<X509Certificate> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: X509Certificate) {
    // Convert the certificate to a PEM-formatted string using CertificateUtils.
    val pemString = value.toPem()
    encoder.encodeString(pemString)
  }

  override fun deserialize(decoder: Decoder): X509Certificate {
    val pemString = decoder.decodeString()
    try {
      val cert = pemString.toX509Certificate()
      return cert
    } catch (e: Exception) {
      throw IllegalArgumentException("Invalid PEM format for X509Certificate", e)
    }
  }
}
