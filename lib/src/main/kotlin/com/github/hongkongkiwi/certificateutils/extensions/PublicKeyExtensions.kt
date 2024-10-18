package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.CertificateUtils
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
  return this::class.java.name.contains("AndroidKeyStore")
}

/**
 * Converts the PublicKey to PEM format.
 *
 * @return The PEM formatted string of the PublicKey object.
 */
fun PublicKey.toPem(): String {
  return CertificateUtils.getPublicKeyPem(this)
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

