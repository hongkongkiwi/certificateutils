package com.github.hongkongkiwi.certificateutils.enums

import android.security.keystore.KeyProperties
import java.util.Locale

/**
 * Enum representing various fingerprint algorithms and their corresponding message digest algorithms.
 */
enum class DigestAlgorithm(val digest: String) {
  NONE(KeyProperties.DIGEST_NONE),
  MD5(KeyProperties.DIGEST_MD5),
  SHA1(KeyProperties.DIGEST_SHA1),
  SHA224(KeyProperties.DIGEST_SHA224),
  SHA256(KeyProperties.DIGEST_SHA256),
  SHA384(KeyProperties.DIGEST_SHA384),
  SHA512(KeyProperties.DIGEST_SHA512);

  companion object {
    /**
     * Gets the DigestAlgorithm enum for a given algorithm name.
     *
     * @param algorithmName The name of the algorithm.
     * @return The corresponding DigestAlgorithm enum.
     * @throws IllegalArgumentException If the algorithm name is not recognized.
     */
    fun fromString(algorithmName: String): DigestAlgorithm {
      return when (algorithmName.uppercase(Locale.ROOT)) {
        KeyProperties.DIGEST_NONE -> NONE
        KeyProperties.DIGEST_MD5 -> MD5
        KeyProperties.DIGEST_SHA1 -> SHA1
        KeyProperties.DIGEST_SHA224 -> SHA224
        KeyProperties.DIGEST_SHA256 -> SHA256
        KeyProperties.DIGEST_SHA384 -> SHA384
        KeyProperties.DIGEST_SHA512 -> SHA512
        else -> throw IllegalArgumentException("Unsupported digest algorithm: $algorithmName")
      }
    }
  }
}