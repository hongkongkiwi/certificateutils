package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.KeyUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.enums.CryptographicAlgorithm
import com.github.hongkongkiwi.certificateutils.exceptions.AndroidKeyStoreException
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.X509EncodedKeySpec

/**
 * Retrieves the algorithm name of the PrivateKey.
 *
 * @return The algorithm name as a String.
 */
fun PrivateKey.getAlgorithmName(): String {
  return this.algorithm
}

/**
 * Extension function to retrieve the name of the elliptic curve for an EC private key.
 *
 * This function checks if the private key is of type ECPrivateKey, and if so, it retrieves
 * the curve name using the method defined in CertificateUtils. If the private key is of
 * a different type, it returns null.
 *
 * @return The name of the elliptic curve as a String, or null if the private key is not an ECPrivateKey.
 */
fun PrivateKey.getCurveName(): String? {
  return when (this) {
    is ECPrivateKey -> {
      // Use the existing getCurveName method in CertificateUtils
      KeyUtils.getCurveNameFromSpec(this.params)
    }
    else -> null // Return null if it's not an ECPrivateKey
  }
}

/**
 * Checks if the PrivateKey is generated from the Android Keystore.
 *
 * @return True if the algorithm is "AndroidKeyStore", false otherwise.
 */
fun PrivateKey.isFromAndroidKeyStore(): Boolean {
  return AndroidKeyStoreUtils.isFromAndroidKeyStore(this)
}

/**
 * Converts the PrivateKey to PEM format.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return The PEM formatted string representation of the PrivateKey.
 */
fun PrivateKey.toPem(format: String = "PKCS#8", passphrase: CharArray? = null): String {
  return PEMUtils.getPrivateKeyPem(this, format = format, passphrase = passphrase)
}

/**
 * Converts the list of PrivateKeys to a PEM formatted string.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return A PEM formatted string representation of the private keys.
 */
fun List<PrivateKey>.toPem(passphrase: CharArray? = null): String {
  return this.joinToString("\n") { it.toPem(format = "PKCS#8", passphrase) }
}

/**
 * Checks if the PrivateKey is in PKCS#8 format.
 *
 * @return True if the format is PKCS#8, false otherwise.
 */
fun PrivateKey.isPkcs8(): Boolean {
  return this.format == "PKCS#8"
}

/**
 * Checks if the PrivateKey is in encrypted PKCS8 format.
 *
 * @return True if the PrivateKey is encrypted PKCS8, false otherwise.
 */
fun PrivateKey.isEncryptedPkcs8(): Boolean {
  return this.format == "PKCS#8" && this::class.java.name.contains("Encrypted")
}

/**
 * Checks if the PrivateKey is in PKCS#1 format.
 *
 * @return True if the format is PKCS#1, false otherwise.
 */
fun PrivateKey.isPkcs1(): Boolean {
  return this.format == "PKCS#1"
}

/**
 * Retrieves the PublicKey associated with the PrivateKey.
 *
 * @return The PublicKey as a String.
 */
fun PrivateKey.getPublicKey(): PublicKey {
  return KeyUtils.getPublicKey(this)
}

fun PrivateKey.testSigning(publicKey: PublicKey): Boolean {
  return KeyUtils.isPublicKeyMatchingPrivateKey(this, publicKey)
}

/**
 * Checks if the provided PublicKey matches the generated PublicKey from the PrivateKey.
 *
 * @param publicKey The PublicKey to compare with.
 * @return True if the PublicKey matches the one derived from the PrivateKey, false otherwise.
 */
fun PrivateKey.matchesPublicKey(publicKey: PublicKey): Boolean {
  if (this.isFromAndroidKeyStore()) {
    throw IllegalArgumentException("Public key cannot be from Android Keystore")
  } else if (publicKey.isFromAndroidKeyStore()) {
    throw IllegalArgumentException("Public key cannot be from Android Keystore")
  }

  // Generate PublicKey from the PrivateKey
  val keyFactoryAlgorithm = when (this.algorithm) {
    "ECDSA" -> "EC"
    else -> this.algorithm
  }
  val keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm)
  val derivedPublicKeySpec = X509EncodedKeySpec(publicKey.encoded)
  val derivedPublicKey = keyFactory.generatePublic(derivedPublicKeySpec)

  // Compare the encoded forms of both keys
  return derivedPublicKey.encoded.contentEquals(publicKey.encoded)
}

/**
 * Checks if the PrivateKey is an RSA key.
 *
 * @return True if the PrivateKey is RSA, false otherwise.
 */
fun PrivateKey.isRsaKey(): Boolean {
  return this.algorithm.equals("RSA", ignoreCase = true)
}

/**
 * Checks if the PrivateKey is an EC key.
 *
 * @return True if the PrivateKey is EC, false otherwise.
 */
fun PrivateKey.isEcOrEcdsa(): Boolean {
  return CryptographicAlgorithm.EC.matches(this.algorithm) || CryptographicAlgorithm.ECDSA.matches(this.algorithm)
}

/**
 * Checks if the PrivateKey is a DSA key.
 *
 * @return True if the PrivateKey is DSA, false otherwise.
 */
fun PrivateKey.isDsaKey(): Boolean {
  return this.algorithm.equals("DSA", ignoreCase = true)
}

/**
 * Checks if the PrivateKey is an EdDSA key.
 *
 * @return True if the PrivateKey is EdDSA, false otherwise.
 */
fun PrivateKey.isEdDsaKey(): Boolean {
  return this.algorithm.equals("EdDSA", ignoreCase = true)
}

/**
 * Retrieves the key length of the PrivateKey, applicable for RSA, DSA, and EC keys.
 *
 * @return The key length in bits, or null if the key type is unsupported.
 */
// TODO: don't use "is" becuase it's not supported by Android Keystores
fun PrivateKey.getKeyLength(): Int? {
  return when (this) {
    is RSAPrivateKey -> this.modulus.bitLength()
    is DSAPrivateKey -> this.params.p.bitLength()
    is ECPrivateKey -> this.params.curve.field.fieldSize // EC keys define key size via curve parameters
    else -> null // Unsupported key type for key length calculation
  }
}

/**
 * Checks if the PrivateKey can be used for signing operations.
 *
 * @return True if the PrivateKey is suitable for signing, false otherwise.
 */
fun PrivateKey.isSuitableForSigning(): Boolean {
  return this.isRsaKey() || this.isEcOrEcdsa() || this.isDsaKey() || this.isEdDsaKey() // Suitable for signing
}

/**
 * Checks if the PrivateKey can be used for encryption.
 *
 * @return True if the PrivateKey is suitable for encryption, false otherwise.
 */
fun PrivateKey.isSuitableForEncryption(): Boolean {
  return this.isRsaKey() // Only RSA keys are typically used for encryption
}

/**
 * Computes the SHA-256 fingerprint of the PrivateKey.
 *
 * @return The fingerprint as a hex string.
 */
fun PrivateKey.getFingerprint(algorithm: String = "SHA-256"): String {
  val md = MessageDigest.getInstance(algorithm)
  val digest = md.digest(this.encoded)
  return digest.joinToString("") { "%02x".format(it) }
}

/**
 * Extension function for [PrivateKey] that converts the private key to a DER-encoded byte array.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding format for X.509 certificates
 * and public keys. This function converts the public key to its DER-encoded byte array
 * by accessing the key's encoded form.
 *
 * @return A byte array containing the DER-encoded representation of the private key.
 */
fun PrivateKey.toDer(): ByteArray {
  require(!this.isFromAndroidKeyStore()) { "Private key must not be from Android Keystore" }
  return this.encoded ?: throw IllegalArgumentException("Failed to encode private key to DER format.")
}

/**
 * Extension function to create a [KeyPair] from a [PrivateKey].
 *
 * This function constructs a [KeyPair] using the provided [PublicKey] or derives one if not provided.
 * If `keysMustMatch` is set to true, the function ensures that the provided [PublicKey] matches
 * the [PrivateKey] before creating the [KeyPair].
 *
 * @receiver [PrivateKey] The private key that will be used in the key pair.
 * @param publicKey [PublicKey]? An optional public key to include in the key pair. If not provided,
 * the function will attempt to derive the public key using [KeyUtils.getPublicKey].
 * @param keysMustMatch [Boolean] If true, ensures that the provided [PublicKey] matches the [PrivateKey].
 * If the keys do not match, an [IllegalArgumentException] is thrown. Defaults to true.
 *
 * @throws IllegalArgumentException if [keysMustMatch] is true and the provided [PublicKey] does not
 * match the [PrivateKey].
 *
 * @return [KeyPair] A new [KeyPair] containing the private and public keys.
 */
fun PrivateKey.toKeyPair(publicKey: PublicKey?, keysMustMatch: Boolean = true): KeyPair {
  if (publicKey != null && keysMustMatch) {
    require(this.matchesPublicKey(publicKey)) { "Public key does not match the private key" }
  }
  val actualPublicKey = publicKey ?: KeyUtils.getPublicKey(this)
  return KeyPair(actualPublicKey, this)
}

/**
 * Extension function for [PrivateKey] that retrieves the alias of the key from the Android Keystore.
 *
 * This function searches the Android Keystore for the alias associated with this [PrivateKey]. It uses
 * the [AndroidKeyStoreUtils.getAliasForKey] method to perform the search.
 *
 * @receiver The [PrivateKey] whose alias needs to be retrieved from the Android Keystore.
 *
 * @return The alias associated with this [PrivateKey], or `null` if no matching alias is found.
 *
 * @throws AndroidKeyStoreException If an error occurs while searching the Android Keystore,
 * such as issues loading the keystore or retrieving the key.
 */
fun PrivateKey.getAndroidKeyStoreAlias(): String? {
  return AndroidKeyStoreUtils.getAliasForKey(this)
}

/**
 * Extension function for [PrivateKey] that converts the private key to a PEM-encoded byte array.
 *
 * This function converts the private key into a PEM format string, which includes the necessary
 * header and footer (`-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----`).
 * It then converts this PEM string into a byte array using the specified [charset].
 *
 * @param charset The [Charset] to be used for encoding the PEM string into a byte array.
 * Defaults to [Charsets.UTF_8].
 *
 * @return A byte array containing the PEM-encoded representation of the private key.
 */
fun PrivateKey.toPemByteArray(charset: Charset = Charsets.UTF_8): ByteArray {
  require(!this.isFromAndroidKeyStore()) { "Private key must not be from Android Keystore" }
  return this.toPem().toByteArray(charset)
}


