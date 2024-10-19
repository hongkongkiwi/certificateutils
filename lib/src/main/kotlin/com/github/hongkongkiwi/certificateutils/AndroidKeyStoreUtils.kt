package com.github.hongkongkiwi.certificateutils

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.github.hongkongkiwi.certificateutils.exceptions.AndroidKeyStoreException
import com.github.hongkongkiwi.certificateutils.exceptions.CACertificateUpdateException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCertificatePemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPrivateKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.KeyPairMismatchException
import com.github.hongkongkiwi.certificateutils.exceptions.PrivateKeyImportException
import com.github.hongkongkiwi.certificateutils.exceptions.PublicKeyImportException
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AndroidKeyStoreUtils {
  internal val TAG = AndroidKeyStoreUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  /**
   * Imports a PrivateKey into the Android Keystore under the specified alias, along with its certificate chain.
   *
   * @param alias The alias under which to store the private key in the Android Keystore.
   * @param keyPair The key pair to be imported.
   * @param certificateChain The certificate chain (X.509 certificates) associated with the private key.
   * @param password An optional password for protecting the key entry.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws PrivateKeyImportException If there is any issue with importing the private key.
   */
  @JvmStatic
  @Throws(
    PrivateKeyImportException::class,
  )
  fun importKeyPairToAndroidKeyStore(
    alias: String,
    keyPair: KeyPair,
    certificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Make sure the first certificate is signed by the private key in the key pair
      val certificate = certificateChain.firstOrNull() as? X509Certificate
        ?: throw PrivateKeyImportException("The certificate chain must contain at least one X.509 certificate.")

      // Verify that the public key of the certificate matches the public key in the key pair
      if (certificate.publicKey != keyPair.public) {
        throw PrivateKeyImportException("The first certificate's public key does not match the provided key pair's public key.")
      }

      // Import the private key and its certificate chain into the keystore
      keyStore.setKeyEntry(
        alias,
        keyPair.private,
        password.takeIf { it != null && it.isNotEmpty() },
        certificateChain.toTypedArray()
      )
    } catch (e: Exception) {
      throw PrivateKeyImportException(
        "Failed to import private key into the Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Updates the certificate chain for an existing private key in the Android Keystore under the specified alias.
   *
   * @param alias The alias under which the private key is stored in the Android Keystore.
   * @param certificateChain The new certificate chain (X.509 certificates) to associate with the private key.
   * @param password An optional password for protecting the key entry.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws InvalidCertificatePemException If the certificate chain is invalid.
   * @throws KeyPairMismatchException If the private key and certificate's public key do not match.
   * @throws InvalidPrivateKeyPemException If no private key is found under the alias.
   */
  @JvmStatic
  @Throws(
    InvalidCertificatePemException::class,
    KeyPairMismatchException::class,
    InvalidPrivateKeyPemException::class,
  )
  fun updateCertificateChainInAndroidKeyStore(
    alias: String,
    certificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Check if the alias exists in the keystore
      if (!keyStore.containsAlias(alias)) {
        throw InvalidPrivateKeyPemException("No private key found under alias: $alias")
      }

      // Retrieve the existing private key from the keystore
      val privateKey = keyStore.getKey(alias, null) as? PrivateKey
        ?: throw InvalidPrivateKeyPemException("No private key found under alias: $alias")
      val publicKey = (keyStore.getCertificate(alias) as? X509Certificate)?.publicKey
        ?: throw InvalidPrivateKeyPemException("No certificate found under alias: $alias")

      // Ensure the first certificate is signed by the private key
      val certificate = certificateChain.firstOrNull() as? X509Certificate
        ?: throw InvalidCertificatePemException("The certificate chain must contain at least one X.509 certificate.")

      // Verify that the public key of the first certificate matches the existing private key's public key
      if (certificate.publicKey != publicKey) {
        throw KeyPairMismatchException("The first certificate's public key does not match the private key in the Keystore.")
      }

      // Update the certificate chain associated with the private key
      keyStore.setKeyEntry(alias, privateKey, password, certificateChain.toTypedArray())
    } catch (e: Exception) {
      throw Exception("Failed to update certificate chain in the Keystore: ${e.message}", e)
    }
  }

  /**
   * Updates the end-entity certificate for an existing private key in the Android Keystore under the specified alias.
   * The rest of the certificate chain remains unchanged.
   *
   * @param alias The alias under which the private key is stored in the Android Keystore.
   * @param newEndEntityCertificate The new end-entity certificate (X.509 certificate) to associate with the private key.
   * @param password An optional password for protecting the key entry.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws InvalidCertificatePemException If the new certificate is invalid.
   * @throws KeyPairMismatchException If the private key and new certificate's public key do not match.
   * @throws InvalidPrivateKeyPemException If no private key is found under the alias.
   */
  @JvmStatic
  @Throws(
    InvalidCertificatePemException::class,
    KeyPairMismatchException::class,
    InvalidPrivateKeyPemException::class,
  )
  fun updateEndEntityCertificateInAndroidKeyStore(
    alias: String,
    newEndEntityCertificate: Certificate,
    password: CharArray? = null,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Check if the alias exists in the keystore
      if (!keyStore.containsAlias(alias)) {
        throw InvalidPrivateKeyPemException("No private key found under alias: $alias")
      }

      // Retrieve the existing private key from the keystore
      val privateKey = keyStore.getKey(alias, password) as? PrivateKey
        ?: throw InvalidPrivateKeyPemException("No private key found under alias: $alias")
      val publicKey = (keyStore.getCertificate(alias) as? X509Certificate)?.publicKey
        ?: throw InvalidPrivateKeyPemException("No certificate found under alias: $alias")

      // Retrieve the existing certificate chain
      val existingCertificateChain = keyStore.getCertificateChain(alias)
        ?: throw InvalidCertificatePemException("No certificate chain found under alias: $alias")

      // Ensure the new end-entity certificate is an X.509 certificate
      val newCertificate = newEndEntityCertificate as? X509Certificate
        ?: throw InvalidCertificatePemException("The new end-entity certificate must be an X.509 certificate.")

      // Verify that the public key of the new certificate matches the private key
      if (newCertificate.publicKey != publicKey) {
        throw KeyPairMismatchException("The new certificate's public key does not match the private key in the Keystore.")
      }

      // Create a new certificate chain with the updated end-entity certificate
      val updatedCertificateChain =
        listOf(newEndEntityCertificate) + existingCertificateChain.drop(1)

      // Update the certificate chain in the keystore while keeping the private key
      keyStore.setKeyEntry(alias, privateKey, password, updatedCertificateChain.toTypedArray())
    } catch (e: Exception) {
      throw Exception("Failed to update end-entity certificate in the Keystore: ${e.message}", e)
    }
  }

  /**
   * Updates the intermediate and CA certificates for an existing private key in the Android Keystore under the specified alias.
   * The end-entity certificate remains unchanged.
   *
   * @param alias The alias under which the private key is stored in the Android Keystore.
   * @param newCACertificateChain The new intermediate and CA certificates (X.509 certificates) to associate with the private key.
   * @param password An optional password for protecting the key entry.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws InvalidCertificatePemException If the new certificate chain is invalid.
   * @throws InvalidPrivateKeyPemException If no private key is found under the alias.
   * @throws CACertificateUpdateException If there is any issue updating the CA certificates.
   */
  @JvmStatic
  @Throws(
    InvalidCertificatePemException::class,
    InvalidPrivateKeyPemException::class,
    CACertificateUpdateException::class,
  )
  fun updateCACertificatesInAndroidKeyStore(
    alias: String,
    newCACertificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Check if the alias exists in the keystore
      if (!keyStore.containsAlias(alias)) {
        throw InvalidPrivateKeyPemException("No private key found under alias: $alias")
      }

      // Retrieve the existing private key from the keystore
      val privateKey = keyStore.getKey(alias, password) as? PrivateKey
        ?: throw InvalidPrivateKeyPemException("No private key found under alias: $alias")

      // Retrieve the existing end-entity certificate
      val endEntityCertificate = keyStore.getCertificate(alias) as? X509Certificate
        ?: throw InvalidCertificatePemException("No end-entity certificate found under alias: $alias")

      // Ensure the new CA certificates are X.509 certificates
      if (newCACertificateChain.isEmpty()) {
        throw InvalidCertificatePemException("The new CA certificate chain must contain at least one X.509 certificate.")
      }

      // Combine the end-entity certificate with the new CA certificates
      val updatedCertificateChain = listOf(endEntityCertificate) + newCACertificateChain

      // Update the certificate chain in the keystore while keeping the private key
      keyStore.setKeyEntry(alias, privateKey, password, updatedCertificateChain.toTypedArray())
    } catch (e: InvalidCertificatePemException) {
      throw e // rethrow known certificate exceptions
    } catch (e: InvalidPrivateKeyPemException) {
      throw e // rethrow known private key exceptions
    } catch (e: Exception) {
      throw CACertificateUpdateException(
        "Failed to update CA certificates in the Keystore for alias: $alias",
        e
      )
    }
  }

  /**
   * Removes a key alias from the Android Keystore if it exists.
   *
   * @param alias The alias of the key to remove.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws KeyStoreException If there is an issue accessing the Keystore or removing the alias.
   */
  @JvmStatic
  @Throws(
    KeyStoreException::class,
  )
  fun removeKeyAliasFromAndroidKeystore(
    alias: String,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Check if the alias exists in the Keystore
      if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias)
        println("Key alias '$alias' removed from Android Keystore.")
      } else {
        println("Key alias '$alias' does not exist in the Android Keystore.")
      }
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to remove key alias '$alias' from the Android Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Checks if a key alias exists in the Android Keystore.
   *
   * @param alias The alias of the key to check.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return True if the alias exists in the Android Keystore, false otherwise.
   * @throws KeyStoreException If there is an issue accessing the Keystore.
   */
  @JvmStatic
  @Throws(
    KeyStoreException::class,
  )
  fun aliasExistsInAndroidKeyStore(
    alias: String,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ): Boolean {
    return try {
      keyStore.containsAlias(alias)
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to check key alias '$alias' in the Android Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Imports a PublicKey into the Android Keystore under the specified alias.
   *
   * This function takes a public key and its associated certificate, then stores
   * the certificate in the Android Keystore. The public key is part of the certificate.
   *
   * @param alias The alias under which to store the public key in the Android Keystore.
   * @param certificate The X.509 certificate associated with the public key.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @throws PublicKeyImportException If there is any issue with importing the public key.
   */
  @JvmStatic
  @Throws(
    PublicKeyImportException::class,
  )
  fun importPublicKeyToAndroidKeystore(
    alias: String,
    certificate: X509Certificate,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ) {
    try {
      // Import the certificate (which contains the public key) into the keystore
      keyStore.setCertificateEntry(alias, certificate)
    } catch (e: Exception) {
      throw PublicKeyImportException(
        "Failed to import public key into the Keystore under alias: $alias",
        e
      )
    }
  }

  /**
   * Searches the Android Keystore to find the alias for the given [PrivateKey].
   *
   * This method iterates over all the aliases in the Android Keystore, retrieves the key associated
   * with each alias, and compares it to the provided [privateKey]. If a match is found, the alias is
   * returned. If no matching alias is found, the method returns `null`.
   *
   * @param privateKey The [PrivateKey] whose alias needs to be found in the Android Keystore.
   *
   * @return The alias associated with the provided [privateKey], or `null` if no matching alias is found.
   *
   * @throws AndroidKeyStoreException If an error occurs while searching the Android Keystore.
   * This could be due to issues loading the keystore or retrieving the key.
   */
  @JvmStatic
  @Throws(
    AndroidKeyStoreException::class,
  )
  fun getAndroidKeyStoreAlias(
    privateKey: PrivateKey,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ): String? {
    try {
      require(privateKey.isFromAndroidKeyStore()) { "Provided private key is not from the Android Keystore." }

      // Iterate through all aliases in the Keystore
      val aliases = keyStore.aliases()
      while (aliases.hasMoreElements()) {
        val alias = aliases.nextElement()

        // Retrieve the key associated with this alias
        val key = keyStore.getKey(alias, null)
        if (key is PrivateKey && key == privateKey) {
          // We found the alias that matches the PrivateKey
          return alias
        }
      }
    } catch (e: Exception) {
      throw AndroidKeyStoreException(e.message, e.cause)
    }

    // Return null if no matching alias was found
    return null
  }

  /**
   * Searches the Android Keystore to find the alias for the given [PublicKey].
   *
   * This method iterates over all the aliases in the Android Keystore, retrieves the key associated
   * with each alias, and compares it to the provided [publicKey]. If a match is found, the alias is
   * returned. If no matching alias is found, the method returns `null`.
   *
   * @param publicKey The [PublicKey] whose alias needs to be found in the Android Keystore.
   *
   * @return The alias associated with the provided [publicKey], or `null` if no matching alias is found.
   *
   * @throws AndroidKeyStoreException If an error occurs while searching the Android Keystore.
   * This could be due to issues loading the keystore or retrieving the key.
   */
  @JvmStatic
  @Throws(
    AndroidKeyStoreException::class,
  )
  fun getAndroidKeyStoreAlias(
    publicKey: PublicKey,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ): String? {
    require(publicKey.isFromAndroidKeyStore()) { "Provided public key is not from the Android Keystore." }

    try {
      // Iterate through all aliases in the Keystore
      val aliases = keyStore.aliases()
      while (aliases.hasMoreElements()) {
        val alias = aliases.nextElement()

        // Retrieve the key associated with this alias
        val key = keyStore.getKey(alias, null)
        if (key is PublicKey && key == publicKey) {
          // We found the alias that matches the PublicKey
          return alias
        }
      }
    } catch (e: Exception) {
      throw AndroidKeyStoreException(e.message, e.cause)
    }

    // Return null if no matching alias was found
    return null
  }

  /**
   * Generates an AES symmetric encryption key and stores it in the Android Keystore.
   *
   * @param keySize The size of the AES key in bits (128 or 256). Default is 256.
   * @param keyStoreAlias The alias under which to store the key in the Android Keystore.
   * @param keyStoreKeyPurposes The purposes for the key (default is encryption and decryption).
   * @return The generated AES SecretKey.
   * @throws IllegalStateException If there is an error generating the key.
   */
  @JvmStatic
  @Throws(
    IllegalStateException::class,
  )
  fun generateSecretKeyAES(
    keySize: Int = 256, // Default to a strong AES encryption value
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): SecretKey {
    require(keySize == 128 || keySize == 256) { "AES key size must be 128 or 256 bits when using the Android Keystore." }
    require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }

    try {
      // Generate key in Android Keystore
      val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keyStoreAlias,
        keyStoreKeyPurposes
      )
        .setKeySize(keySize)
        .setBlockModes(
          KeyProperties.BLOCK_MODE_GCM,
          KeyProperties.BLOCK_MODE_CBC
        ) // Set block modes directly
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // Set encryption padding directly
        .setRandomizedEncryptionRequired(true)
        .build()

      keyGen.init(keyGenParameterSpec)
      return keyGen.generateKey()
    } catch (e: Exception) {
      throw IllegalStateException("Failed to initialize key generator for Android Keystore", e)
    }
  }
}