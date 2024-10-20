package com.github.hongkongkiwi.certificateutils.serializers

import android.util.Log
import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.extensions.getAndroidKeyStoreAlias
import com.github.hongkongkiwi.certificateutils.extensions.isEncryptedPrivateKeyPem
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.isKeyStorePem
import com.github.hongkongkiwi.certificateutils.extensions.isPrivateKeyPem
import com.github.hongkongkiwi.certificateutils.extensions.toPem
import com.github.hongkongkiwi.certificateutils.extensions.toPrivateKey
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.InvalidKeyException

// Note to support setting a passphrase you'll probably need to use contextual serialization
// so you can manually instantiate the serializer since we cannot pass parameers to serializer
// class in constructor.
class PrivateKeySerializer : KSerializer<PrivateKey> {

  override val descriptor: SerialDescriptor =
    PrimitiveSerialDescriptor("PrivateKey", PrimitiveKind.STRING)

  private var pemPassphrase: CharArray? = null // Passphrase is initially null
  private var allowUnencryptedPem: Boolean = true // Allow unencrypted PEM by default

  /**
   * Sets the passphrase to be used during serialization/deserialization of the PrivateKey.
   * If the passphrase is provided, it will be used to encrypt the private key when serializing
   * into PEM format. If no passphrase is provided or the passphrase is empty, the private key
   * can be serialized in an unencrypted format, depending on the `allowUnencryptedPem` flag.
   *
   * @param passphrase The passphrase to encrypt the private key during serialization.
   *                   If the passphrase is null or empty, the private key may be serialized
   *                   in an unencrypted format if `allowUnencryptedPem` is set to true.
   * @param allowUnencryptedPem A flag that determines whether unencrypted PEM serialization
   *                            is allowed if no passphrase is provided. Defaults to false,
   *                            meaning unencrypted PEM serialization is disallowed unless
   *                            explicitly enabled.
   */
  fun setPassphrase(passphrase: CharArray?, allowUnencryptedPem: Boolean? = false) {
    // Set the passphrase if it is not empty, otherwise set it to null
    this.pemPassphrase = passphrase.takeIf { it?.isNotEmpty() ?: false }

    // If no passphrase is provided, allow unencrypted PEM based on the flag
    if (this.pemPassphrase == null) {
      this.allowUnencryptedPem = true
    } else {
      this.allowUnencryptedPem = allowUnencryptedPem ?: false
    }
  }

  override fun serialize(encoder: Encoder, value: PrivateKey) {
    try {
      if (value.isFromAndroidKeyStore()) {
        require(pemPassphrase == null) { "Passphrase is not supported for Android Keystore keys." }

        // Get the alias for the key from Android Keystore
        val alias = value.getAndroidKeyStoreAlias()
          ?: throw KeyStoreException("Alias is missing for the PrivateKey from the Android Keystore.")
        val startMarker = AndroidKeyStoreUtils.KEYSTORE_ALIAS_MARKERS.first
        val endMarker = AndroidKeyStoreUtils.KEYSTORE_ALIAS_MARKERS.second
        encoder.encodeString("${startMarker}${alias}${endMarker}")
      } else {
        // Encrypt the private key using the provided passphrase and serialize to PEM format
        when (value.format) {
          "PKCS#8" -> {
            val pemString = value.toPem(format = "PKCS#8", passphrase = pemPassphrase)
            encoder.encodeString(pemString)
          }
          "PKCS#1" -> {
            val pemString = value.toPem(format = "PKCS#1", passphrase = pemPassphrase)
            encoder.encodeString(pemString)
          }
          "OpenSSH" -> {
            require(pemPassphrase == null) { "Passphrase is not supported for OpenSSH PEM keys." }
            val pemString = PEMUtils.getOpenSSHPem(value)
            encoder.encodeString(pemString)
          }
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
        require(allowUnencryptedPem) { "Unencrypted PEM keys are not allowed when passphrase is set and allowUnencryptedPem = false." }

        // Just ignore passphrase since our PEM is not passphrase encrypted
        encoded.toPrivateKey()
      } catch (e: Exception) {
        throw InvalidKeyException("Failed to parse the PrivateKey from PEM: ${e.message}", e)
      }
    } else if (encoded.isEncryptedPrivateKeyPem()) {
      try {
        require(pemPassphrase != null) { "Passphrase is required for encrypted PEM keys." }

        // Decrypt the PEM using the provided passphrase and convert it to a PrivateKey
        encoded.toPrivateKey(passphrase = pemPassphrase)
      } catch (e: Exception) {
        throw InvalidKeyException("Failed to parse the PrivateKey from PEM: ${e.message}", e)
      }
    } else if (encoded.isKeyStorePem()) {
      try {
        require(pemPassphrase == null) { "Passphrase is not supported for Android Keystore keys." }

        // Retrieve the key from the Android Keystore using its alias
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
