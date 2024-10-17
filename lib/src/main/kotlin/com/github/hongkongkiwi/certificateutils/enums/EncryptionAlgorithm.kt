package com.github.hongkongkiwi.certificateutils.enums

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.openssl.PKCS8Generator
import java.util.Locale

/**
 * Enum representing various encryption algorithms and their corresponding ASN.1 object identifiers.
 */
enum class EncryptionAlgorithm(val oid: ASN1ObjectIdentifier) {
  AES_128_CBC(PKCS8Generator.AES_128_CBC),
  AES_192_CBC(PKCS8Generator.AES_192_CBC),
  AES_256_CBC(PKCS8Generator.AES_256_CBC),
  DES3_CBC(PKCS8Generator.DES3_CBC),
  PBE_SHA1_RC4_128(PKCS8Generator.PBE_SHA1_RC4_128),
  PBE_SHA1_RC4_40(PKCS8Generator.PBE_SHA1_RC4_40),
  PBE_SHA1_3DES(PKCS8Generator.PBE_SHA1_3DES),
  PBE_SHA1_2DES(PKCS8Generator.PBE_SHA1_2DES),
  PBE_SHA1_RC2_128(PKCS8Generator.PBE_SHA1_RC2_128),
  PBE_SHA1_RC2_40(PKCS8Generator.PBE_SHA1_RC2_40);

  companion object {
    /**
     * Gets the EncryptionAlgorithm enum for a given algorithm name.
     *
     * @param algorithmName The name of the algorithm.
     * @return The corresponding EncryptionAlgorithm enum.
     * @throws IllegalArgumentException If the algorithm name is not recognized.
     */
    fun fromString(algorithmName: String): EncryptionAlgorithm {
      return when (algorithmName.uppercase(Locale.ROOT)) {
        "AES_128_CBC" -> AES_128_CBC
        "AES_192_CBC" -> AES_192_CBC
        "AES_256_CBC" -> AES_256_CBC
        "DES3_CBC" -> DES3_CBC
        "PBE_SHA1_RC4_128" -> PBE_SHA1_RC4_128
        "PBE_SHA1_RC4_40" -> PBE_SHA1_RC4_40
        "PBE_SHA1_3DES" -> PBE_SHA1_3DES
        "PBE_SHA1_2DES" -> PBE_SHA1_2DES
        "PBE_SHA1_RC2_128" -> PBE_SHA1_RC2_128
        "PBE_SHA1_RC2_40" -> PBE_SHA1_RC2_40
        else -> throw IllegalArgumentException("Unsupported encryption algorithm: $algorithmName")
      }
    }
  }
}