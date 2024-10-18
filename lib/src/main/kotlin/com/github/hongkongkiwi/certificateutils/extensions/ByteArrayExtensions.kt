package com.github.hongkongkiwi.certificateutils.extensions

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Converts a DER encoded byte array back into a PrivateKey.
 *
 * @param algorithm The algorithm used for the key (e.g., "RSA", "EC", "DSA").
 * @return The reconstructed PrivateKey.
 * @throws IllegalArgumentException if the key cannot be reconstructed.
 */
fun ByteArray.toPrivateKeyFromDer(algorithm: String): PrivateKey {
  try {
    val keyFactory = KeyFactory.getInstance(algorithm)
    val keySpec = PKCS8EncodedKeySpec(this) // Convert DER to PKCS8 encoded key spec
    return keyFactory.generatePrivate(keySpec)
  } catch (e: Exception) {
    throw IllegalArgumentException("Failed to reconstruct PrivateKey from DER data", e)
  }
}

/**
 * Converts a DER encoded byte array back into a PublicKey.
 *
 * @param algorithm The algorithm used for the key (e.g., "RSA", "EC", "DSA").
 * @return The reconstructed PublicKey.
 * @throws IllegalArgumentException if the key cannot be reconstructed.
 */
fun ByteArray.toPublicKeyFromDer(algorithm: String): PublicKey {
  try {
    val keyFactory = KeyFactory.getInstance(algorithm)
    val keySpec = X509EncodedKeySpec(this) // Convert DER to X.509 encoded key spec
    return keyFactory.generatePublic(keySpec)
  } catch (e: Exception) {
    throw IllegalArgumentException("Failed to reconstruct PublicKey from DER data", e)
  }
}

/**
 * Converts a DER encoded byte array to a PEM encoded string.
 *
 * @param type The type of the PEM structure (e.g., "CERTIFICATE", "PRIVATE KEY", "PUBLIC KEY").
 * @return The PEM encoded string.
 */
fun ByteArray.derToPem(type: String): String {
  val base64Encoded = Base64.getEncoder().encodeToString(this)
  return "-----BEGIN $type-----\n$base64Encoded\n-----END $type-----"
}

/**
 * Converts a ByteArray to a hexadecimal string.
 *
 * @return The hexadecimal string representation.
 */
fun ByteArray.toHexString(): String {
  return joinToString("") { "%02x".format(it) }
}
