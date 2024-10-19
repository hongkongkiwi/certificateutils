package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.enums.DigestAlgorithm
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.cert.CRL
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Retrieves the common name (CN) from the X509Certificate's subject.
 *
 * @return The common name as a String, or null if not found.
 */
fun X509Certificate.getCommonName(): String? {
  val subjectDN = this.subjectX500Principal.name
  return subjectDN.split(",").firstOrNull { it.trim().startsWith("CN=") }
    ?.substringAfter("=")
    ?.trim()
}

/**
 * Computes the digest of the X509Certificate using the specified algorithm.
 *
 * @param algorithm The digest algorithm to use.
 * @return The computed digest as a String.
 * @throws IllegalArgumentException if the algorithm is unsupported.
 */
fun X509Certificate.getDigest(algorithm: DigestAlgorithm): String {
  return when (algorithm) {
    DigestAlgorithm.MD5 -> CertificateUtils.getCertificateMd5Digest(this)
    DigestAlgorithm.SHA256 -> CertificateUtils.getCertificateSha256Digest(this)
    DigestAlgorithm.SHA512 -> CertificateUtils.getCertificateSha512Digest(this)
    else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
  }
}

/**
 * Retrieves the issuer common name (CN) from the X509Certificate's issuer.
 *
 * @return The issuer common name as a String, or null if not found.
 */
fun X509Certificate.getIssuerCommonName(): String? {
  val issuerDN = this.issuerX500Principal.name
  return issuerDN.split(",").firstOrNull { it.trim().startsWith("CN=") }
    ?.substringAfter("=")
    ?.trim()
}

/**
 * Checks if the X509Certificate is expired.
 *
 * @return True if the certificate is expired, false otherwise.
 */
fun X509Certificate.isExpired(): Boolean {
  return this.notBefore.after(Date()) || this.notAfter.before(Date())
}

/**
 * Checks if the X509Certificate is self-signed.
 *
 * @return True if the subject and issuer are the same, false otherwise.
 */
fun X509Certificate.isSelfSigned(): Boolean {
  return this.subjectX500Principal == this.issuerX500Principal
}

/**
 * Checks if the X509Certificate is valid at the specified date.
 *
 * @param date The date to check the validity against.
 * @return True if the certificate is valid at the given date, false otherwise.
 */
fun X509Certificate.isValidAt(date: Date): Boolean {
  return this.notBefore.before(date) && this.notAfter.after(date)
}

/**
 * Checks if the X509Certificate is valid.
 *
 * @return True if the certificate is valid, false otherwise.
 */
private fun X509Certificate.isValid(): Boolean {
  return !this.isExpired() && this.notBefore.before(Date())
}

/**
 * Checks if the X509Certificate is revoked according to the provided Certificate Revocation List (CRL).
 *
 * @param crl The CRL to check against.
 * @return True if the certificate is revoked, false otherwise.
 * @throws IllegalArgumentException if the provided CRL is not of type X509CRL.
 */
fun X509Certificate.isRevoked(crl: CRL): Boolean {
  // Check if the provided CRL is of type X509CRL
  if (crl !is X509CRL) {
    throw IllegalArgumentException("Provided CRL must be of type X509CRL")
  }

  // Check if the certificate serial number exists in the CRL
  return crl.isRevoked(this)
}

/**
 * Converts X509Certificate to its PEM representation.
 *
 * @return The PEM formatted string of the X509Certificate object.
 */
fun X509Certificate.toPem(): String {
  return PEMUtils.getCertificatePem(this)
}

/**
 * Retrieves a list of valid X509Certificates from the list.
 *
 * @return A list of valid X509Certificates.
 */
fun List<X509Certificate>.getValidCertificates(): List<X509Certificate> {
  return this.filter { it.isValid() }
}

/**
 * Converts the list of X509Certificates to a PEM formatted string.
 *
 * @return A PEM formatted string representation of the certificates.
 */
fun List<X509Certificate>.toPem(): String {
  return this.joinToString("\n") { PEMUtils.getCertificatePem(it) }
}

/**
 * Converts the valid X509Certificates in the list to a PEM formatted string.
 *
 * @return A PEM formatted string representation of valid certificates.
 */
fun List<X509Certificate>.toPemForValidCertificates(): String {
  return this.filter { it.isValid() }.toPem()
}

/**
 * Checks if all certificates in the list are trusted according to the provided trusted roots.
 *
 * @param trustedRoots The list of trusted root certificates.
 * @return True if all certificates are trusted, false otherwise.
 */
fun List<X509Certificate>.areAllCertificatesTrusted(trustedRoots: List<X509Certificate>): Boolean {
  return this.all { cert -> trustedRoots.any { it.getDigest(DigestAlgorithm.SHA256) == cert.getDigest(DigestAlgorithm.SHA256) } }
}

/**
 * Generates the SHA-1 fingerprint of the X509Certificate.
 *
 * @return The SHA-1 fingerprint as a hex string.
 */
fun X509Certificate.getSha1Fingerprint(): String {
  val md = MessageDigest.getInstance("SHA-1")
  val fingerprint = md.digest(this.encoded)
  return fingerprint.joinToString(":") { "%02X".format(it) }
}

/**
 * Generates the SHA-256 fingerprint of the X509Certificate.
 *
 * @return The SHA-256 fingerprint as a hex string.
 */
fun X509Certificate.getSha256Fingerprint(): String {
  val md = MessageDigest.getInstance("SHA-256")
  val fingerprint = md.digest(this.encoded)
  return fingerprint.joinToString(":") { "%02X".format(it) }
}

/**
 * Generates the SHA-512 fingerprint of the X509Certificate.
 *
 * @return The SHA-512 fingerprint as a hex string.
 */
fun X509Certificate.getSha512Fingerprint(): String {
  val md = MessageDigest.getInstance("SHA-512")
  val fingerprint = md.digest(this.encoded)
  return fingerprint.joinToString(":") { "%02X".format(it) }
}

/**
 * Generates the MD5 fingerprint of the X509Certificate.
 *
 * @return The MD5 fingerprint as a hex string.
 */
fun X509Certificate.getShaMD5Fingerprint(): String {
  val md = MessageDigest.getInstance("MD5")
  val fingerprint = md.digest(this.encoded)
  return fingerprint.joinToString(":") { "%02X".format(it) }
}

/**
 * Checks if the X509Certificate is a Certificate Authority (CA).
 *
 * @return True if the certificate is a CA, false otherwise.
 */
fun X509Certificate.isCertificateAuthority(): Boolean {
  return this.basicConstraints != -1
}

/**
 * Retrieves the key usage information from the X509Certificate.
 *
 * @return A list of key usage purposes, or an empty list if none are found.
 */
fun X509Certificate.getKeyUsageInfo(): List<String> {
  val keyUsage = this.keyUsage ?: return emptyList()
  val keyUsagePurposes = listOf(
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Key Cert Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only"
  )
  return keyUsagePurposes.filterIndexed { index, _ -> keyUsage[index] }
}

/**
 * Checks if the X509Certificate is trusted according to the provided trusted root certificates.
 *
 * @param trustedRoots The list of trusted root certificates.
 * @return True if the certificate is trusted, false otherwise.
 */
fun X509Certificate.isTrusted(trustedRoots: List<X509Certificate>): Boolean {
  return trustedRoots.any { it.getDigest(DigestAlgorithm.SHA256) == this.getDigest(DigestAlgorithm.SHA256) }
}

/**
 * Extension function for [X509Certificate] that converts the certificate to a PEM-encoded byte array.
 *
 * This function first converts the X.509 certificate into a PEM format string, which includes the
 * necessary header and footer (`-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`).
 * It then converts this PEM string into a byte array using the specified [charset].
 *
 * @param charset The [Charset] to be used for encoding the PEM string into a byte array.
 * Defaults to [Charsets.UTF_8].
 *
 * @return A byte array containing the PEM-encoded representation of the certificate.
 */
fun X509Certificate.toPemByteArray(charset: Charset = Charsets.UTF_8): ByteArray {
  return this.toPem().toByteArray(charset)
}

/**
 * Extension function for [X509Certificate] that converts the certificate to a DER-encoded byte array.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding format used for certificates and keys.
 * This function converts the X.509 certificate into its DER-encoded byte array representation.
 *
 * @return A byte array containing the DER-encoded representation of the certificate.
 *
 * @throws IllegalArgumentException if the certificate cannot be encoded.
 */
fun X509Certificate.toDer(): ByteArray {
  return this.encoded ?: throw IllegalArgumentException("Failed to encode X509Certificate to DER format.")
}



