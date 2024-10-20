package com.github.hongkongkiwi.certificateutils.enums

/**
 * Enum representing the supported signature algorithms.
 */
enum class SignatureAlgorithm(private val algorithm: String) {
  // SHA-1 with DSA algorithm (considered weak).
  SHA1_WITH_DSA("SHA1withDSA"),

  // SHA-1 with ECDSA algorithm (considered weak).
  SHA1_WITH_ECDSA("SHA1withECDSA"),

  // SHA-1 with RSA algorithm (considered weak).
  SHA1_WITH_RSA("SHA1withRSA"),

  // SHA-224 with ECDSA algorithm.
  SHA224_WITH_ECDSA("SHA224withECDSA"),

  // SHA-224 with RSA algorithm.
  SHA224_WITH_RSA("SHA224withRSA"),

  // SHA-256 with ECDSA algorithm.
  SHA256_WITH_ECDSA("SHA256withECDSA"),

  // SHA-256 with RSA algorithm.
  SHA256_WITH_RSA("SHA256withRSA"),

  // SHA-384 with ECDSA algorithm.
  SHA384_WITH_ECDSA("SHA384withECDSA"),

  // SHA-384 with RSA algorithm.
  SHA384_WITH_RSA("SHA384withRSA"),

  // SHA-512 with ECDSA algorithm.
  SHA512_WITH_ECDSA("SHA512withECDSA"),

  // SHA-512 with RSA algorithm.
  SHA512_WITH_RSA("SHA512withRSA");

  companion object {
    /**
     * Returns the SignatureAlgorithm corresponding to the provided algorithm string.
     *
     * @param algorithm The algorithm string.
     * @return The corresponding SignatureAlgorithm, or null if not found.
     */
    fun fromString(algorithm: String): SignatureAlgorithm? {
      return entries.find { it.algorithm.equals(algorithm, ignoreCase = true) }
    }
  }

  /**
   * Returns the string representation of the signature algorithm.
   *
   * This method provides the actual algorithm string (e.g., "SHA256withRSA").
   *
   * @return The algorithm string.
   */
  override fun toString(): String {
    return algorithm
  }
}