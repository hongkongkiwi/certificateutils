package com.github.hongkongkiwi.certificateutils

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
import com.github.hongkongkiwi.certificateutils.exceptions.AndroidKeyStoreException
import com.github.hongkongkiwi.certificateutils.exceptions.CACertificateUpdateException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCertificatePemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPrivateKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.KeyPairMismatchException
import com.github.hongkongkiwi.certificateutils.exceptions.PrivateKeyImportException
import com.github.hongkongkiwi.certificateutils.exceptions.PublicKeyImportException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.InvalidAlgorithmParameterException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
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
  fun importKeyPair(
    alias: String,
    keyPair: KeyPair,
    certificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun updateCertificateChain(
    alias: String,
    certificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun updateEndEntityCertificate(
    alias: String,
    newEndEntityCertificate: Certificate,
    password: CharArray? = null,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun updateCACertificates(
    alias: String,
    newCACertificateChain: List<Certificate>,
    password: CharArray? = null,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun removeKeyAlias(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ) {
    try {
      // Check if the alias exists in the Keystore
      if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias)
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
  fun aliasExists(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun importPublicKey(
    alias: String,
    certificate: X509Certificate,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
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
  fun getAliasForKey(
    privateKey: PrivateKey,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): String? {
    try {
      require(isFromAndroidKeyStore(privateKey)) { "Provided private key is not from the Android Keystore." }

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
  fun getAliasForKey(
    publicKey: PublicKey,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): String? {
    require(isFromAndroidKeyStore(publicKey)) { "Provided public key is not from the Android Keystore." }

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

  /**
   * Retrieves a KeyPair (PrivateKey and PublicKey) from the Android Keystore.
   *
   * @param alias The alias of the key to retrieve.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return A KeyPair containing the PrivateKey and PublicKey, or null if the alias does not exist or keys cannot be retrieved.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the keys.
   */
  @JvmStatic
  @Throws(
    KeyStoreException::class
  )
  fun getKeyPair(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): KeyPair? {
    return try {
      // Check if the alias exists in the Keystore
      if (keyStore.containsAlias(alias)) {
        // Retrieve the PrivateKey from the Keystore
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
          ?: throw KeyStoreException("No private key found for alias '$alias'.")

        // Retrieve the corresponding certificate (which contains the PublicKey)
        val certificate = keyStore.getCertificate(alias)
        val publicKey = certificate?.publicKey
          ?: throw KeyStoreException("No public key found for alias '$alias'.")

        // Return the KeyPair
        KeyPair(publicKey, privateKey)
      } else {
        null
      }
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve key pair for alias '$alias' from the Android Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Retrieves a Private Key from the Android Keystore.
   *
   * @param alias The alias of the key to retrieve.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return A KeyPair containing the PrivateKey and PublicKey, or null if the alias does not exist or keys cannot be retrieved.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the keys.
   */
  @JvmStatic
  @Throws(
    KeyStoreException::class
  )
  fun getPrivateKey(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): PrivateKey? {
    return try {
      // Check if the alias exists in the Keystore
      if (keyStore.containsAlias(alias)) {
        // Retrieve the PrivateKey from the Keystore
        return keyStore.getKey(alias, null) as? PrivateKey
          ?: throw KeyStoreException("No private key found for alias '$alias'.")
      } else {
        null
      }
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve private key for alias '$alias' from the Android Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Retrieves a Public Key from the Android Keystore.
   *
   * @param alias The alias of the key to retrieve.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return A KeyPair containing the PrivateKey and PublicKey, or null if the alias does not exist or keys cannot be retrieved.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the keys.
   */
  @JvmStatic
  @Throws(
    KeyStoreException::class
  )
  fun getPublicKey(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): PublicKey? {
    return try {
      // Check if the alias exists in the Keystore
      if (keyStore.containsAlias(alias)) {
        // Retrieve the corresponding certificate (which contains the PublicKey)
        val certificate = keyStore.getCertificate(alias)
        return certificate?.publicKey
          ?: throw KeyStoreException("No public key found for alias '$alias'.")
      } else {
        null
      }
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve key pair for alias '$alias' from the Android Keystore: ${e.message}",
        e
      )
    }
  }

  /**
   * Retrieves the end certificate (leaf certificate) for a given alias from the Android Keystore.
   *
   * @param alias The alias of the key to retrieve the certificate for.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return The end certificate (X509Certificate) or null if not found.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the certificate.
   */
  @JvmStatic
  @Throws(KeyStoreException::class)
  fun getEndCertificate(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): X509Certificate? {
    return try {
      // Retrieve the certificate for the alias
      val certificate = keyStore.getCertificate(alias) as? X509Certificate
      certificate
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve end certificate for alias '$alias': ${e.message}",
        e
      )
    }
  }

  /**
   * Retrieves the full certificate chain for a given alias from the Android Keystore.
   *
   * @param alias The alias of the key to retrieve the certificate chain for.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return The certificate chain (Array of Certificates) or null if not found.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the certificate chain.
   */
  @JvmStatic
  @Throws(KeyStoreException::class)
  fun getCertificateChain(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): Array<Certificate>? {
    return try {
      // Retrieve the certificate chain for the alias
      val certificateChain = keyStore.getCertificateChain(alias)
      certificateChain
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve certificate chain for alias '$alias': ${e.message}",
        e
      )
    }
  }

  /**
   * Retrieves the CA certificates (excluding the end certificate) from the Android Keystore for a given alias.
   *
   * @param alias The alias of the key to retrieve the CA certificates for.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return An array of CA certificates or null if no chain is found.
   * @throws KeyStoreException If there is an issue accessing the Keystore or retrieving the CA certificates.
   */
  @JvmStatic
  @Throws(KeyStoreException::class)
  fun getCACertificates(
    alias: String,
    keyStore: KeyStore = getAndroidKeyStoreInstance()
  ): Array<Certificate>? {
    return try {
      // Retrieve the certificate chain for the alias
      val certificateChain = keyStore.getCertificateChain(alias)
      if (certificateChain != null && certificateChain.size > 1) {
        // Return only the CA certificates (i.e., excluding the first certificate)
        val caCertificates = certificateChain.drop(1).toTypedArray()
        caCertificates
      } else {
        null
      }
    } catch (e: Exception) {
      throw KeyStoreException(
        "Failed to retrieve CA certificates for alias '$alias': ${e.message}",
        e
      )
    }
  }

  /**
   * Checks if the PrivateKey is stored in the Android Keystore.
   *
   * @return True if the algorithm is "AndroidKeyStore", false otherwise.
   */
  fun isFromAndroidKeyStore(privateKey: PrivateKey): Boolean {
    return privateKey::class.java.name.contains("AndroidKeyStore")
  }

  /**
   * Checks if the PublicKey is stored in the Android Keystore.
   *
   * @return True if the algorithm is "AndroidKeyStore", false otherwise.
   */
  fun isFromAndroidKeyStore(publicKey: PublicKey): Boolean {
    return publicKey::class.java.name.contains("AndroidKeyStore")
  }

  /**
   * Retrieves an instance of the Android Keystore.
   *
   * @return An instance of the Android Keystore.
   */
  private fun getAndroidKeyStoreInstance(): KeyStore {
    return KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  }

  /**
   * Generates an EC key pair. If `keystoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param ecCurve The elliptic curve to use (default is SECP256R1).
   * @param keyStoreAlias The alias for the Android Keystore. If null, a normal key pair is generated.
   * @param keyStoreKeyPurposes The purposes for which the key can be used (default is signing and verifying).
   * @return The generated EC key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the EC algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  fun generateKeyPairEC(
    ecCurve: ECCurve = ECCurve.SECP256R1,
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): KeyPair {
    require(keyStoreAlias.isNotBlank()) { "Keystore alias must not be blank." }
    require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }
    require(ecCurve == ECCurve.SECP256R1) { "Only SECP256R1 (NIST P256) is supported for Android Key Store" }

    // Generate key in Android Keystore
    val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
    val keyGenParameterSpec = KeyGenParameterSpec.Builder(
      keyStoreAlias,
      keyStoreKeyPurposes
    )
      .setAlgorithmParameterSpec(ECGenParameterSpec(ecCurve.toString()))
      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
      .build()

    keyPairGenerator.initialize(keyGenParameterSpec)
    return keyPairGenerator.generateKeyPair() // Returns both public and private keys
  }

  /**
   * Generates an EC private key. If `keystoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param ecCurve The elliptic curve to use (default is SECP256R1).
   * @param keyStoreAlias The alias for the Android Keystore. If null, a normal key pair is generated.
   * @param keyStoreKeyPurposes The purposes for which the key can be used (default is signing and verifying).
   * @return The generated EC key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the EC algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  fun generatePrivateKeyEC(
    ecCurve: ECCurve = ECCurve.SECP256R1,
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): PrivateKey {
    val keyPair = generateKeyPairEC(ecCurve, keyStoreAlias, keyStoreKeyPurposes)
    return keyPair.private
  }

  /**
   * Generates an RSA key pair. If `keyStoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param keyStoreAlias The alias for the Android Keystore. If null, a normal RSA key pair is generated.
   * @param keyStoreKeyPurposes The purposes for which the key can be used (default is signing and verifying).
   * @return The generated RSA key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedOperationException If an unsupported key size is used for the Android Keystore.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateKeyPairRSA(
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
  ): KeyPair {
    require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }
    require(keyStoreAlias.isNotBlank()) { "Keystore alias must not be blank." }

    // Generate RSA key in Android Keystore
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
    val keyGenParameterSpec = KeyGenParameterSpec.Builder(
      keyStoreAlias,
      keyStoreKeyPurposes
    )
      .setKeySize(2048) // Android Keystore supports only 2048-bit RSA
      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512) // Set directly
      .setEncryptionPaddings(
        KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
        KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
      ) // Set directly
      .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1) // Set directly
      .build()

    keyPairGenerator.initialize(keyGenParameterSpec)
    return keyPairGenerator.generateKeyPair() // Returns both public and private keys
  }

  /**
   * Generates an RSA private key. If `keyStoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param keyStoreAlias The alias for the Android Keystore. If null, a normal RSA key pair is generated.
   * @param keyStoreKeyPurposes The purposes for which the key can be used (default is signing and verifying).
   * @return The generated RSA key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedOperationException If an unsupported key size is used for the Android Keystore.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generatePrivateKeyRSA(
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
  ): PrivateKey {
    val keyPair = generateKeyPairRSA(keyStoreAlias, keyStoreKeyPurposes)
    return keyPair.private
  }
}