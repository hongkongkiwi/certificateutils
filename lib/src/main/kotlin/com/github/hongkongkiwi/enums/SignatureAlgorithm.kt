package com.github.hongkongkiwi.enums

/**
 * Enum representing the supported signature algorithms.
 */
enum class SignatureAlgorithm(val algorithm: String) {
  // SHA-1 with DSA algorithm (considered weak).
  SHA1_WITH_DSA("SHA1withDSA"),

  // SHA-1 with ECDSA algorithm (considered weak).
  SHA1_WITH_ECDSA("SHA1withECDSA"),

  // SHA-1 with RSA algorithm (considered weak).
  SHA1_WITH_RSA("SHA1withRSA"),

  // DSA with SHA-1 algorithm (considered weak).
  DSA_WITH_SHA1("DSAwithSHA1"),

  // DSA with SHA-256 algorithm.
  DSA_WITH_SHA256("DSAwithSHA256"),

  // SHA-224 with ECDSA algorithm.
  SHA224_WITH_ECDSA("SHA224withECDSA"),

  // SHA-224 with RSA algorithm.
  SHA224_WITH_RSA("SHA224withRSA"),

  // SHA-256 with ECDSA algorithm.
  SHA256_WITH_ECDSA("SHA256withECDSA"),

  // SHA-256 with EdDSA (Edwards-curve Digital Signature Algorithm).
  SHA256_WITH_EDDSA("SHA256withEdDSA"),

  // SHA-256 with RSA algorithm.
  SHA256_WITH_RSA("SHA256withRSA"),

  // SHA-384 with ECDSA algorithm.
  SHA384_WITH_ECDSA("SHA384withECDSA"),

  // SHA-384 with RSA algorithm.
  SHA384_WITH_RSA("SHA384withRSA"),

  // SHA-512 with ECDSA algorithm.
  SHA512_WITH_ECDSA("SHA512withECDSA"),

  // SHA-512 with RSA algorithm.
  SHA512_WITH_RSA("SHA512withRSA"),

  // SHA-512 with EdDSA (Edwards-curve Digital Signature Algorithm).
  SHA512_WITH_EDDSA("SHA512withEdDSA");

  companion object {
    /**
     * Returns the SignatureAlgorithm corresponding to the provided algorithm string.
     *
     * @param algorithm The algorithm string.
     * @return The corresponding SignatureAlgorithm, or null if not found.
     */
    fun fromString(algorithm: String): SignatureAlgorithm? {
      return values().find { it.algorithm.equals(algorithm, ignoreCase = true) }
    }
  }

  /**
   * Returns the name of the signature algorithm in a more readable format.
   *
   * @return The name of the algorithm as a String.
   */
  override fun toString(): String {
    return this.name.replace("_", " ").replace("WITH", "with").replace("SHA", "SHA-")
      .replace("EDDSA", "EdDSA")
  }
}