package com.github.hongkongkiwi.certificateutils.enums

/**
 * Enum class for Elliptic Curves (EC).
 *
 * This enum represents various standardized elliptic curves used in cryptography,
 * allowing easy reference and validation of curve types in the application.
 *
 * Each curve is represented by its standard name, which is used in cryptographic operations.
 */
enum class ECCurve(val curveName: String) {
  /** NIST P-192 curve */
  SECP192R1("secp192r1"),

  /** NIST P-224 curve */
  SECP224R1("secp224r1"),

  /** NIST P-256 curve (also known as prime256v1) */
  SECP256R1("secp256r1"),

  /** Alias for NIST P-256 */
  PRIME256V1("prime256v1"),

  /** NIST P-384 curve */
  SECP384R1("secp384r1"),

  /** NIST P-521 curve */
  SECP521R1("secp521r1"),

  /** Brainpool P-192 curve */
  BRAINPOOL192R1("brainpoolP192r1"),

  /** Brainpool P-224 curve */
  BRAINPOOL224R1("brainpoolP224r1"),

  /** Brainpool P-256 curve */
  BRAINPOOL256R1("brainpoolP256r1"),

  /** Brainpool P-384 curve */
  BRAINPOOL384R1("brainpoolP384r1"),

  /** Brainpool P-512 curve */
  BRAINPOOL512R1("brainpoolP512r1"),

  /** Curve25519, optimized for speed */
  CURVE25519("Curve25519"),

  /** Ed25519, optimized for digital signatures */
  ED25519("Ed25519"),

  /** X25519 for key exchange */
  X25519("X25519"),

  /** Koblitz curve used in Bitcoin */
  SECP256K1("secp256k1"),

  /** Alias for Koblitz curve */
  KOBLITZ("secp256k1");

  override fun toString(): String {
    return curveName
  }

  companion object {
    /**
     * Retrieves the corresponding ECCurve enum value for the provided curve name.
     *
     * @param curveName The string representation of the curve name.
     * @return The corresponding ECCurve enum value.
     * @throws IllegalArgumentException If the curve name is not recognized.
     */
    fun fromString(curveName: String): ECCurve {
      return entries.find { it.curveName.equals(curveName, ignoreCase = true) }
        ?: throw IllegalArgumentException("Unsupported elliptic curve: $curveName")
    }
  }

  /**
   * Compares the curve with a given string representation, including aliases.
   *
   * @param curveName The name of the curve as a String.
   * @return True if the curve matches the given string (including aliases), false otherwise.
   */
  fun matches(curveName: String): Boolean {
    val normalizedCurveName = curveName.lowercase()

    return this.curveName.equals(normalizedCurveName, ignoreCase = true) ||
      when (this) {
        PRIME256V1 -> normalizedCurveName in listOf("secp256r1", "prime256v1")
        KOBLITZ -> normalizedCurveName in listOf("secp256k1", "koblitz")
        else -> false
      }
  }

  /**
   * Retrieves a list of all supported elliptic curves.
   *
   * @return A list of all ECCurve enum values.
   */
  fun getAllCurves(): List<ECCurve> {
    return entries
  }

  /**
   * Finds the corresponding curve for a specified key size.
   *
   * @param keySize The key size in bits.
   * @return The corresponding ECCurve, or null if no match is found.
   */
  fun findByKeySize(keySize: Int): ECCurve? {
    return entries.find { it.getKeySize() == keySize }
  }

  /**
   * Checks if the curve is a standardized elliptic curve.
   *
   * @return True if the curve is a standardized elliptic curve, false otherwise.
   */
  fun isStandard(): Boolean {
    return when (this) {
      SECP192R1, SECP224R1, SECP256R1, SECP384R1, SECP521R1,
      BRAINPOOL192R1, BRAINPOOL224R1, BRAINPOOL256R1,
      BRAINPOOL384R1, BRAINPOOL512R1,
      CURVE25519, ED25519, X25519, SECP256K1 -> true

      else -> false
    }
  }

  /**
   * Retrieves the key size for the given elliptic curve.
   *
   * @return The key size in bits for the elliptic curve.
   */
  @Suppress("MemberVisibilityCanBePrivate")
  fun getKeySize(): Int {
    return when (this) {
      SECP192R1 -> 192
      SECP224R1 -> 224
      SECP256R1, PRIME256V1, SECP256K1 -> 256
      SECP384R1 -> 384
      SECP521R1 -> 521
      BRAINPOOL192R1 -> 192
      BRAINPOOL224R1 -> 224
      BRAINPOOL256R1 -> 256
      BRAINPOOL384R1 -> 384
      BRAINPOOL512R1 -> 512
      CURVE25519 -> 255 // Actual order may vary
      ED25519 -> 255 // Actual order may vary
      X25519 -> 255 // Actual order may vary
      else -> throw IllegalArgumentException("Key size not defined for the curve: $this")
    }
  }

  /**
   * Retrieves a human-readable name for the curve.
   *
   * @return A string representing the human-readable name of the elliptic curve.
   */
  fun getHumanReadableName(): String {
    return when (this) {
      SECP192R1 -> "NIST P-192"
      SECP224R1 -> "NIST P-224"
      SECP256R1 -> "NIST P-256"
      PRIME256V1 -> "NIST P-256 (also known as prime256v1)"
      SECP384R1 -> "NIST P-384"
      SECP521R1 -> "NIST P-521"
      BRAINPOOL192R1 -> "Brainpool P-192"
      BRAINPOOL224R1 -> "Brainpool P-224"
      BRAINPOOL256R1 -> "Brainpool P-256"
      BRAINPOOL384R1 -> "Brainpool P-384"
      BRAINPOOL512R1 -> "Brainpool P-512"
      CURVE25519 -> "Curve25519"
      ED25519 -> "Ed25519"
      X25519 -> "X25519"
      SECP256K1 -> "Koblitz curve (used in Bitcoin)"
      KOBLITZ -> "Koblitz curve (used in Bitcoin)"
    }
  }
}
