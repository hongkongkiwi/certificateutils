package com.github.hongkongkiwi.certificateutils

import com.github.hongkongkiwi.certificateutils.PEMUtils.getCsrPem
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import java.security.Security

object ByteUtils {
  internal val TAG = ByteUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  /**
   * Converts a byte array representing a PKCS#10 CSR (Certificate Signing Request)
   * into a PKCS10CertificationRequest object.
   *
   * This method takes a byte array that contains the encoded CSR data,
   * decodes it, and constructs a PKCS10CertificationRequest instance.
   *
   * @param byteArray The byte array containing the encoded PKCS#10 CSR data.
   * @return The corresponding PKCS10CertificationRequest object.
   * @throws IllegalArgumentException If the byte array cannot be parsed as a valid CSR.
   */
  @JvmStatic
  private fun byteArrayToCsr(byteArray: ByteArray): PKCS10CertificationRequest {
    // Ensure the provided byte array is not empty
    require(byteArray.isNotEmpty()) { "Byte array cannot be empty." }

    return try {
      // Create a PKCS10CertificationRequest from the byte array
      JcaPKCS10CertificationRequest(byteArray)
    } catch (e: Exception) {
      // Handle any exceptions that occur during CSR parsing
      throw IllegalArgumentException(
        "Failed to parse byte array into PKCS#10 Certification Request.",
        e
      )
    }
  }

  /**
   * Converts a PKCS10CertificationRequest to a PEM-formatted string.
   *
   * @param byteArray The byte array containing the encoded PKCS#10 CSR data.
   * @return The PEM-formatted CSR string.
   */
  @JvmStatic
  private fun byteArrayToCsrPem(
    byteArray: ByteArray
  ): String {
    val csr = byteArrayToCsr(byteArray)
    return getCsrPem(csr)
  }

  /**
   * Converts a list of byte arrays representing PKCS#10 CSR to a single PEM-formatted string.
   *
   * This method iterates over each byte array in the list and uses the pkcs10ByteArrayToPem method
   * to convert each to its PEM format, then concatenates them into a single string.
   *
   * @param byteArray The list of byte arrays representing the CSRs to be converted.
   * @return The concatenated PEM-formatted CSR string, with each CSR separated by newlines.
   */
  private fun byteArraysToCsrPem(byteArray: List<ByteArray>): String {
    val pemStringBuilder = StringBuilder()

    for (csrBytes in byteArray) {
      // Convert each byte array to its PEM format
      val pem = byteArrayToCsrPem(csrBytes)
      pemStringBuilder.append(pem).append("\n") // Append each CSR's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

}