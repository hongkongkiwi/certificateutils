package com.github.hongkongkiwi.certificateutils.enums

import java.util.Locale

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
  ECDSA,      // Elliptic Curve Digital Signature Algorithm
  AES,        // Advanced Encryption Standard (Symmetric Key Algorithm)
  HMAC_SHA256; // HMAC with SHA-256 Hash Function

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
      return when (algorithmName.uppercase(Locale.getDefault())) {
        "RSA" -> RSA
        "EC" -> EC
        "DSA" -> DSA
        "Ed25519" -> Ed25519
        "Ed448" -> Ed448
        "X25519" -> X25519
        "DH" -> DH
        "ECDSA" -> ECDSA
        "AES" -> AES
        "HMAC-SHA256" -> HMAC_SHA256
        else -> throw IllegalArgumentException("Unsupported algorithm: $algorithmName")
      }
    }
  }

  /**
   * Returns a string representation of the cryptographic algorithm.
   *
   * This method provides a concise name for the algorithm.
   *
   * @return A string representing the algorithm's name.
   */
  override fun toString(): String {
    return when (this) {
      RSA -> "RSA"
      EC -> "EC"
      DSA -> "DSA"
      Ed25519 -> "Ed25519"
      Ed448 -> "Ed448"
      X25519 -> "X25519"
      DH -> "DH"
      ECDSA -> "ECDSA"
      AES -> "AES"
      HMAC_SHA256 -> "HMAC-SHA256"
    }
  }

  /**
   * Returns a human-readable string representation of the cryptographic algorithm.
   *
   * This method provides a more detailed description of the algorithm,
   * including its type or classification.
   *
   * @return A string that describes the algorithm in a human-readable format.
   */
  fun description(): String {
    return when (this) {
      RSA -> "RSA Algorithm"
      EC -> "Elliptic Curve Algorithm"
      DSA -> "Digital Signature Algorithm"
      Ed25519 -> "Ed25519 Algorithm (Elliptic Curve)"
      Ed448 -> "Ed448 Algorithm (Elliptic Curve)"
      X25519 -> "X25519 Algorithm (Elliptic Curve)"
      DH -> "Diffie-Hellman Algorithm"
      ECDSA -> "Elliptic Curve Digital Signature Algorithm"
      AES -> "Advanced Encryption Standard (Symmetric Key Algorithm)"
      HMAC_SHA256 -> "HMAC with SHA-256 Hash Function"
    }
  }

  /**
   * Compares the algorithm with a given string representation.
   *
   * @param algorithmName The name of the algorithm as a String.
   * @return True if the algorithm matches the given string, false otherwise.
   */
  fun matches(algorithmName: String): Boolean {
    return this.toString().equals(algorithmName, ignoreCase = true)
  }

  /**
   * Compares the current `CryptographicAlgorithm` with another string.
   *
   * This method compares the `other` string (which could be a plain string representing an algorithm name)
   * with the current `CryptographicAlgorithm` enum's name (converted to a string).
   * It provides an option to ignore case during the comparison.
   *
   * @param other The string to compare against the current algorithm's name. If `null`, the method returns `false`.
   * @param ignoreCase If `true`, the comparison will ignore case differences. Defaults to `false`, meaning the comparison is case-sensitive.
   * @return `true` if the `other` string matches the current algorithm's name, `false` otherwise.
   */
  fun equals(other: String?, ignoreCase: Boolean = false): Boolean {
    return other?.equals(this.toString(), ignoreCase) == true
  }
}
