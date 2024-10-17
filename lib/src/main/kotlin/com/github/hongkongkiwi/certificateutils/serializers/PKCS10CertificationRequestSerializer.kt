package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.extensions.toPKCS10CertificationRequest
import com.github.hongkongkiwi.certificateutils.extensions.toPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.bouncycastle.pkcs.PKCS10CertificationRequest

object PKCS10CertificationRequestSerializer : KSerializer<PKCS10CertificationRequest> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PKCS10CertificationRequest", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PKCS10CertificationRequest) {
    // Convert the PKCS10CertificationRequest to a PEM-formatted string using CertificateUtils.
    val pemString = value.toPem()
    encoder.encodeString(pemString)
  }

  override fun deserialize(decoder: Decoder): PKCS10CertificationRequest {
    // Decode the PEM string back into a PKCS10CertificationRequest using CertificateUtils.
    val pemString = decoder.decodeString()
    return pemString.toPKCS10CertificationRequest()
  }
}
