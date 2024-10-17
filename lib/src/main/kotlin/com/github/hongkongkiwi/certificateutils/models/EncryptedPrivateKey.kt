package com.github.hongkongkiwi.certificateutils.models

import java.security.PrivateKey
import java.util.Objects

/**
 * Encapsulates an EncryptedPrivateKey with its associated passphrase.
 *
 * @property privateKey The private key (in PEM format).
 * @property passphrase The passphrase to decrypt/encrypt the private key.
 */
class EncryptedPrivateKey(
  val privateKey: PrivateKey,
  val passphrase: CharArray
) {

  /**
   * Returns the algorithm of the wrapped PrivateKey.
   */
  fun getAlgorithm(): String {
    return privateKey.algorithm
  }

  /**
   * Returns the format of the wrapped PrivateKey (usually "PKCS#8" for PEM-encoded keys).
   */
  fun getFormat(): String? {
    return privateKey.format
  }

  /**
   * Returns the encoded version of the PrivateKey, if available.
   */
  fun getEncoded(): ByteArray? {
    return privateKey.encoded
  }

  /**
   * Override `equals` to ensure equality checks consider both the private key and passphrase.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is EncryptedPrivateKey) return false
    return privateKey == other.privateKey && passphrase.contentEquals(other.passphrase)
  }

  /**
   * Override `hashCode` to include both the private key and passphrase.
   */
  override fun hashCode(): Int {
    return Objects.hash(privateKey, passphrase.contentHashCode())
  }

  /**
   * Override `toString` for better debugging and logging purposes.
   */
  override fun toString(): String {
    return "EncryptedPrivateKey(algorithm=${privateKey.algorithm}, format=${privateKey.format})"
  }
}
