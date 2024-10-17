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
  SECP256K1("secp256k1");

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
}