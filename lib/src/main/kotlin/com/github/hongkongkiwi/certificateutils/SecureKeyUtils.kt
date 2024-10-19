package com.github.hongkongkiwi.certificateutils

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.SecureRandom
import java.security.Security
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object SecureKeyUtils {
  internal val TAG = SecureKeyUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  /**
   * Generates an AES symmetric encryption key. If `keyStoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keySize The size of the AES key in bits (128, 192, or 256). Default is 256.
   * @param keyStoreAlias The alias for storing the key in the Android Keystore. If null, a normal AES key is generated.
   * @param keyStoreKeyPurposes The intended purposes for the key (default is encryption and decryption).
   * @return The generated AES key.
   * @throws NoSuchAlgorithmException If the AES algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws IllegalArgumentException If the key size is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateSecretKeyAES(
    keySize: Int = 256, // Default to a strong AES encryption value
    keyStoreAlias: String? = null,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): SecretKey {
    require(keySize == 128 || keySize == 192 || keySize == 256) { "AES key size must be 128, 192, or 256 bits." }
    require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }

    val keyGenerator: KeyGenerator = if (!keyStoreAlias.isNullOrBlank()) {
      return AndroidKeyStoreUtils.generateSecretKeyAES(keySize, keyStoreAlias, keyStoreKeyPurposes)
    } else {
      // Generate a normal AES key
      val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
      keyGen.init(keySize, SecureRandom())
      keyGen
    }

    return keyGenerator.generateKey()
  }

  /**
   * Generates an HMAC-SHA256 key. If `keyStoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keyStoreAlias The alias for storing the key in the Android Keystore. If null, a normal HMAC-SHA256 key is generated.
   * @param keyStoreKeyPurposes The intended purposes for the key (default is signing and verifying).
   * @return The generated HMAC-SHA256 key.
   * @throws NoSuchAlgorithmException If the HmacSHA256 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws IllegalArgumentException If the key purposes are invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateSecretKeyHmacSHA256(
    keyStoreAlias: String? = null,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): SecretKey {
    val keyGenerator: KeyGenerator = if (!keyStoreAlias.isNullOrBlank()) {
      require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }

      try {
        // Generate key in Android Keystore
        val keyGen =
          KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
          keyStoreAlias,
          keyStoreKeyPurposes
        )
          .setDigests(KeyProperties.DIGEST_SHA256)
          .build()

        keyGen.init(keyGenParameterSpec)
        keyGen
      } catch (e: Exception) {
        throw IllegalStateException("Failed to initialize key generator for Android Keystore", e)
      }
    } else {
      // Generate a normal HMAC-SHA256 key
      val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
      keyGen.init(SecureRandom())
      keyGen
    }

    return keyGenerator.generateKey()
  }
}