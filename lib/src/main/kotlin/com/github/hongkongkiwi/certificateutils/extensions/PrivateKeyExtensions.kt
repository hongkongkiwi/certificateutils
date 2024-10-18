package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
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
fun PrivateKey.getCurveName(): ECCurve? {
  return when (this) {
    is ECPrivateKey -> {
      // Use the existing getCurveName method in CertificateUtils
      CertificateUtils.getCurveNameFromSpec(this.params)
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
  return this::class.java.name.contains("AndroidKeyStore")
}

/**
 * Converts the PrivateKey to PEM format.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return The PEM formatted string representation of the PrivateKey.
 */
fun PrivateKey.toPem(passphrase: CharArray? = null): String {
  return CertificateUtils.getPrivateKeyPem(this, passphrase)
}

/**
 * Converts the list of PrivateKeys to a PEM formatted string.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return A PEM formatted string representation of the private keys.
 */
fun List<PrivateKey>.toPem(passphrase: CharArray? = null): String {
  return this.joinToString("\n") { it.toPem(passphrase) }
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
  return CertificateUtils.getPublicKey(this)
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
  val keyFactory = KeyFactory.getInstance(this.algorithm)
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
fun PrivateKey.isEcKey(): Boolean {
  return this.algorithm.equals("EC", ignoreCase = true)
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
  return this.isRsaKey() || this.isEcKey() || this.isDsaKey() || this.isEdDsaKey() // Suitable for signing
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
 * Converts the PrivateKey to DER format (binary representation).
 *
 * @return ByteArray in DER format.
 */
fun PrivateKey.toDer(): ByteArray {
  return this.encoded // Returns the key in its raw binary format (DER)
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
 * the function will attempt to derive the public key using [CertificateUtils.getPublicKey].
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
  val actualPublicKey = publicKey ?: CertificateUtils.getPublicKey(this)
  return KeyPair(actualPublicKey, this)
}




