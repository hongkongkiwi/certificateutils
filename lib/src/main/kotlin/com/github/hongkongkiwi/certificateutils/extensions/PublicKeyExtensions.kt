package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.exceptions.AndroidKeyStoreException
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Checks if the PublicKey is generated from the Android Keystore.
 *
 * @return True if the algorithm is "AndroidKeyStore", false otherwise.
 */
fun PublicKey.isFromAndroidKeyStore(): Boolean {
  return AndroidKeyStoreUtils.isFromAndroidKeyStore(this)
}

/**
 * Converts the PublicKey to PEM format.
 *
 * @return The PEM formatted string of the PublicKey object.
 */
fun PublicKey.toPem(): String {
  return PEMUtils.getPublicKeyPem(this)
}

/**
 * Checks if the provided PrivateKey matches the PublicKey.
 *
 * @param privateKey The PrivateKey to compare with.
 * @return True if the PrivateKey matches the one derived from the PublicKey, false otherwise.
 */
fun PublicKey.matchesPrivateKey(privateKey: PrivateKey): Boolean {
  if (this.isFromAndroidKeyStore()) {
    throw IllegalArgumentException("Public key cannot be from Android Keystore")
  } else if (privateKey.isFromAndroidKeyStore()) {
    throw IllegalArgumentException("Private key cannot be from Android Keystore")
  }

  // Generate PrivateKey from the PublicKey
  val keyFactory = KeyFactory.getInstance(privateKey.algorithm)
  val derivedPrivateKeySpec = PKCS8EncodedKeySpec(privateKey.encoded)
  val derivedPrivateKey = keyFactory.generatePrivate(derivedPrivateKeySpec)

  // Compare the encoded forms of both keys
  return this.encoded.contentEquals(derivedPrivateKey.encoded)
}

/**
 * Checks if the PublicKey is an RSA key.
 *
 * @return True if the PublicKey is RSA, false otherwise.
 */
fun PublicKey.isRsaKey(): Boolean {
  return this.algorithm.equals("RSA", ignoreCase = true)
}

/**
 * Checks if the PublicKey is an EC key.
 *
 * @return True if the PublicKey is EC, false otherwise.
 */
fun PublicKey.isEcKey(): Boolean {
  return this.algorithm.equals("EC", ignoreCase = true)
}

/**
 * Checks if the PublicKey is a DSA key.
 *
 * @return True if the PublicKey is DSA, false otherwise.
 */
fun PublicKey.isDsaKey(): Boolean {
  return this.algorithm.equals("DSA", ignoreCase = true)
}

/**
 * Checks if the PublicKey is an EdDSA key.
 *
 * @return True if the PublicKey is EdDSA, false otherwise.
 */
fun PublicKey.isEdDsaKey(): Boolean {
  return this.algorithm.equals("EdDSA", ignoreCase = true)
}

/**
 * Extension function for [PublicKey] that retrieves the alias of the key from the Android Keystore.
 *
 * This function searches the Android Keystore for the alias associated with this [PublicKey]. It uses
 * the [AndroidKeyStoreUtils.getAliasForKey] method to perform the search.
 *
 * @receiver The [PublicKey] whose alias needs to be retrieved from the Android Keystore.
 *
 * @return The alias associated with this [PublicKey], or `null` if no matching alias is found.
 *
 * @throws AndroidKeyStoreException If an error occurs while searching the Android Keystore,
 * such as issues loading the keystore or retrieving the key.
 */
fun PublicKey.getAndroidKeyStoreAlias(): String? {
  return AndroidKeyStoreUtils.getAliasForKey(this)
}

/**
 * Extension function for [PublicKey] that converts the public key to a PEM-encoded byte array.
 *
 * This function converts the public key into a PEM format string, which includes the necessary
 * header and footer (`-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`).
 * It then converts this PEM string into a byte array using the specified [charset].
 *
 * @param charset The [Charset] to be used for encoding the PEM string into a byte array.
 * Defaults to [Charsets.UTF_8].
 *
 * @return A byte array containing the PEM-encoded representation of the public key.
 */
fun PublicKey.toPemByteArray(charset: Charset = Charsets.UTF_8): ByteArray {
  require(!this.isFromAndroidKeyStore()) { "Public key must not be from Android Keystore" }
  return this.toPem().toByteArray(charset)
}

/**
 * Extension function for [PublicKey] that converts the public key to a DER-encoded byte array.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding format for X.509 certificates
 * and public keys. This function converts the public key to its DER-encoded byte array
 * by accessing the key's encoded form.
 *
 * @return A byte array containing the DER-encoded representation of the public key.
 */
fun PublicKey.toDer(): ByteArray {
  require(!this.isFromAndroidKeyStore()) { "Public key must not be from Android Keystore" }
  return this.encoded ?: throw IllegalArgumentException("Failed to encode public key to DER format.")
}