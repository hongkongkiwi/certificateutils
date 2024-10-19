package com.github.hongkongkiwi.certificateutils.serializers

import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.isValidPem
import com.github.hongkongkiwi.certificateutils.extensions.toPrivateKey
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.KeyStore
import java.security.PrivateKey

class PrivateKeyAndroidKeyStoreSerializer : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    // Check if the private key is from the Android Keystore
    if (value.isFromAndroidKeyStore()) {
      // Instead of converting to PEM, serialize it as a simple string (e.g., alias or some identifier)
      val alias = CertificateUtils.getKeyAlias(value) // Custom function to get alias from Android Keystore
      encoder.encodeString(alias)
    } else {
      // If not from the Android Keystore, serialize as PEM if in PKCS#8 format
      if (value.format == "PKCS#8") {
        val pemString = CertificateUtils.getPrivateKeyPem(value)
        encoder.encodeString(pemString)
      } else {
        throw IllegalArgumentException("Unsupported key format: ${value.format}")
      }
    }
  }

  override fun deserialize(decoder: Decoder): PrivateKey {
    val encoded = decoder.decodeString()

    // Check if the encoded string is a valid PEM
    return if (encoded.isValidPem()) {
      // Deserialize the PEM string to PrivateKey
      try {
        encoded.toPrivateKey()
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to parse PEM: ${e.message}", e)
      }
    } else {
      // Assume the string is an Android Keystore alias and retrieve the key
      try {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.getKey(encoded, null) as PrivateKey
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to retrieve PrivateKey from Android Keystore using alias: $encoded", e)
      }
    }
  }
}
