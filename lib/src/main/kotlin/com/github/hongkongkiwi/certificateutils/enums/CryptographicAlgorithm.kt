package com.github.hongkongkiwi.certificateutils.enums

/**
 * Enum representing various cryptographic algorithms.
 *
 * This enum includes algorithm names used in public key cryptography,
 * allowing easy reference and validation of algorithm types in the application.
 */
enum class CryptographicAlgorithm {
  RSA,        // RSA algorithm
  EC,         // Elliptic Curve algorithm
  DSA,        // Digital Signature Algorithm
  Ed25519,    // Ed25519 algorithm (Elliptic Curve)
  Ed448,      // Ed448 algorithm (Elliptic Curve)
  X25519,     // X25519 algorithm (Elliptic Curve)
  DH,         // Diffie-Hellman algorithm
  ECDSA;      // Elliptic Curve Digital Signature Algorithm

  companion object {
    /**
     * Gets the Algorithm enum for a given algorithm name.
     *
     * This function takes a string representation of an algorithm name
     * and returns the corresponding Algorithm enum value.
     *
     * @param algorithmName The name of the algorithm as a String.
     * @return The corresponding Algorithm enum value.
     * @throws IllegalArgumentException If the algorithm name is not recognized.
     */
    fun fromString(algorithmName: String): CryptographicAlgorithm {
      return when (algorithmName) {
        "RSA" -> RSA
        "EC" -> EC
        "DSA" -> DSA
        "Ed25519" -> Ed25519
        "Ed448" -> Ed448
        "X25519" -> X25519
        "DH" -> DH
        "ECDSA" -> ECDSA
        else -> throw IllegalArgumentException("Unsupported algorithm: $algorithmName")
      }
    }
  }

  /**
   * Returns a human-readable string representation of the cryptographic algorithm.
   *
   * @return The name of the algorithm as a String.
   */
  override fun toString(): String {
    return when (this) {
      RSA -> "RSA Algorithm"
      EC -> "Elliptic Curve Algorithm"
      DSA -> "Digital Signature Algorithm"
      Ed25519 -> "Ed25519 Algorithm (Elliptic Curve)"
      Ed448 -> "Ed448 Algorithm (Elliptic Curve)"
      X25519 -> "X25519 Algorithm (Elliptic Curve)"
      DH -> "Diffie-Hellman Algorithm"
      ECDSA -> "Elliptic Curve Digital Signature Algorithm"
    }
  }
}
