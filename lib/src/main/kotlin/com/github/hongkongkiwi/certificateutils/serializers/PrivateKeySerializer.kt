import android.util.Log
import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.extensions.getAndroidKeyStoreAlias
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.isPrivateKeyPem
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.KeyStore
import java.security.PrivateKey

class PrivateKeySerializer : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKey", PrimitiveKind.STRING)

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    // Check if the private key is from the Android Keystore
    if (value.isFromAndroidKeyStore()) {
      // Get the alias of the PrivateKey
      val alias = value.getAndroidKeyStoreAlias()
        ?: throw IllegalArgumentException("Cannot serialize a PrivateKey from the Android Keystore without an alias.")

      // Serialize the alias as a string
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
    if (encoded.isPrivateKeyPem()) {
      try {
        // Deserialize the PEM string to PrivateKey
        return CertificateUtils.parsePrivateKeyPem(encoded).first()
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to parse PEM: ${e.message}", e)
      }
    } else if (encoded.isNotEmpty()) {
      // Assume it's a keystore alias and retrieve the PrivateKey
      try {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(encoded, null) as PrivateKey
      } catch (e: Exception) {
        throw IllegalArgumentException("Failed to retrieve PrivateKey from Android Keystore using alias: $encoded", e)
      }
    } else {
      throw IllegalArgumentException("Invalid PEM or keystore alias format.")
    }
  }
}
