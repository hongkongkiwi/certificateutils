@file:Suppress("unused")

package com.github.hongkongkiwi.extensions

import com.github.hongkongkiwi.CertificateUtils
import com.github.hongkongkiwi.enums.DigestAlgorithm
import com.github.hongkongkiwi.enums.ECCurve
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.util.Base64
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CRL
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date
import java.security.interfaces.ECPrivateKey

// String Extensions

/**
 * Checks if the string is in PEM format for a certificate.
 *
 * @return True if the string contains generic certificate markers, false otherwise.
 */
fun String.isCertificatePem(): Boolean {
  return this.contains(CertificateUtils.GENERIC_CERTIFICATE_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a private key.
 *
 * @return True if the string contains any known private key markers, false otherwise.
 */
fun String.isPrivateKeyPem(): Boolean {
  return this.contains(CertificateUtils.GENERIC_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.RSA_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ECDSA_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.DSA_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ED25519_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ED448_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.X25519_PRIVATE_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.DH_PRIVATE_KEY_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a public key.
 *
 * @return True if the string contains any known public key markers, false otherwise.
 */
fun String.isPublicKeyPem(): Boolean {
  return this.contains(CertificateUtils.RSA_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ECDSA_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.DSA_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ED25519_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.ED448_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.X25519_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.DH_PUBLIC_KEY_MARKERS.first) ||
    this.contains(CertificateUtils.GENERIC_PUBLIC_KEY_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a certificate signing request (CSR).
 *
 * @return True if the string contains any CSR markers, false otherwise.
 */
fun String.isCsrPem(): Boolean {
  return this.contains(CertificateUtils.CERTIFICATE_REQUEST_MARKERS.first) ||
    this.contains(CertificateUtils.NEW_CERTIFICATE_REQUEST_MARKERS.first)
}

/**
 * Validates if the string is a valid PEM format.
 *
 * @return True if the string starts with "-----BEGIN" and ends with "-----END", false otherwise.
 */
fun String.isValidPem(): Boolean {
  return this.trim().startsWith("-----BEGIN") && this.trim().endsWith("-----END")
}

/**
 * Converts a Base64 encoded string to a byte array.
 *
 * @return The decoded byte array.
 */
fun String.toByteArrayFromBase64(): ByteArray {
  return Base64.getDecoder().decode(this)
}

/**
 * Converts a PEM encoded string to a byte array.
 *
 * @return The decoded byte array.
 * @throws IllegalArgumentException if the PEM format is invalid.
 */
fun String.toByteArrayFromPem(): ByteArray {
  require(isValidPem()) { "Invalid PEM format." }
  return Base64.getDecoder().decode(extractBase64FromPem())
}

/**
 * Extracts the Base64 encoded content from a PEM formatted string.
 *
 * @return A string containing the Base64 encoded content.
 */
private fun String.extractBase64FromPem(): String {
  return this.trim().lines().filterNot { it.startsWith("-----") }.joinToString("")
}

/**
 * Converts a PEM encoded string to an X509Certificate.
 *
 * @param allowExpired If true, allows expired certificates.
 * @return The parsed X509Certificate.
 */
fun String.toX509Certificate(allowExpired: Boolean = false): X509Certificate {
  return CertificateUtils.parseCertificatePem(this, allowExpired).first()
}

/**
 * Converts a PEM encoded string to a list of X509Certificates.
 *
 * @param allowExpired If true, allows expired certificates.
 * @return A list of parsed X509Certificates.
 */
fun String.toX509Certificates(allowExpired: Boolean = false): List<X509Certificate> {
  return CertificateUtils.parseCertificatePem(this, allowExpired)
}

/**
 * Converts a PEM encoded string to a PKCS10CertificationRequest.
 *
 * @return The parsed PKCS10CertificationRequest.
 */
fun String.toPKCS10CertificationRequest(): PKCS10CertificationRequest {
  return CertificateUtils.parseCsrPem(this).first()
}

/**
 * Converts a PEM encoded string to a list of PKCS10CertificationRequests.
 *
 * @return A list of parsed PKCS10CertificationRequests.
 */
fun String.toPKCS10CertificationRequests(): List<PKCS10CertificationRequest> {
  return CertificateUtils.parseCsrPem(this)
}

/**
 * Checks if the PKCS10CertificationRequest is valid.
 *
 * @return True if the CSR is valid, false otherwise.
 */
fun PKCS10CertificationRequest.isCsrValid(): Boolean {
  return CertificateUtils.isCsrValid(this)
}

/**
 * Converts a PEM encoded string to a PrivateKey.
 *
 * @return The parsed PrivateKey.
 */
fun String.toPrivateKey(): PrivateKey {
  return CertificateUtils.parsePrivateKeyPem(this).first()
}

/**
 * Converts a PEM encoded string to a list of PrivateKeys.
 *
 * @return A list of parsed PrivateKeys.
 */
fun String.toPrivateKeys(): List<PrivateKey> {
  return CertificateUtils.parsePrivateKeyPem(this)
}

/**
 * Converts a PEM encoded string to an encrypted PrivateKey using a passphrase.
 *
 * @param passphrase The passphrase used for decryption.
 * @return The decrypted PrivateKey.
 */
fun String.toEncryptedPrivateKey(passphrase: CharArray): PrivateKey {
  return CertificateUtils.parsePrivateKeyPem(this, passphrase).first()
}

/**
 * Converts a PEM encoded string to a list of encrypted PrivateKeys using a passphrase.
 *
 * @param passphrase The passphrase used for decryption.
 * @return A list of decrypted PrivateKeys.
 */
fun String.toEncryptedPrivateKeys(passphrase: CharArray): List<PrivateKey> {
  return CertificateUtils.parsePrivateKeyPem(this, passphrase)
}

/**
 * Converts a PEM encoded string to a PublicKey.
 *
 * @return The parsed PublicKey.
 */
fun String.toPublicKey(): PublicKey {
  return CertificateUtils.parsePublicKeyPem(this).first()
}

/**
 * Converts a PEM encoded string to a list of PublicKeys.
 *
 * @return A list of parsed PublicKeys.
 */
fun String.toPublicKeys(): List<PublicKey> {
  return CertificateUtils.parsePublicKeyPem(this)
}

// X509Certificate Extensions

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

// PrivateKey Extensions

/**
 * Retrieves the algorithm name of the PrivateKey.
 *
 * @return The algorithm name as a String.
 */
fun PrivateKey.getAlgorithmName(): String {
  return this.algorithm
}

/**
 * Extension function to retrieve the name of the elliptic curve for an EC private key.
 *
 * This function checks if the private key is of type ECPrivateKey, and if so, it retrieves
 * the curve name using the method defined in CertificateUtils. If the private key is of
 * a different type, it returns null.
 *
 * @return The name of the elliptic curve as a String, or null if the private key is not an ECPrivateKey.
 */
fun PrivateKey.getCurveName(): ECCurve? {
  return when (this) {
    is ECPrivateKey -> {
      // Use the existing getCurveName method in CertificateUtils
      CertificateUtils.getCurveNameFromSpec(this.params)
    }
    else -> null // Return null if it's not an ECPrivateKey
  }
}

/**
 * Checks if the PrivateKey is generated from the Android Keystore.
 *
 * @return True if the algorithm is "AndroidKeyStore", false otherwise.
 */
fun PrivateKey.isFromAndroidKeystore(): Boolean {
  return this.algorithm == "AndroidKeyStore"
}

/**
 * Converts the PrivateKey to PEM format.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return The PEM formatted string representation of the PrivateKey.
 */
fun PrivateKey.toPem(passphrase: CharArray? = null): String {
  return CertificateUtils.getPrivateKeyPem(this, passphrase)
}

// List<X509Certificate> Extensions

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
  return this.joinToString("\n") { CertificateUtils.getCertificatePem(it) }
}

/**
 * Converts the valid X509Certificates in the list to a PEM formatted string.
 *
 * @return A PEM formatted string representation of valid certificates.
 */
fun List<X509Certificate>.toPemForValidCertificates(): String {
  return this.filter { it.isValid() }.toPem()
}

// List<PrivateKey> Extensions

/**
 * Converts the list of PrivateKeys to a PEM formatted string.
 *
 * @param passphrase Optional passphrase for encrypted keys.
 * @return A PEM formatted string representation of the private keys.
 */
fun List<PrivateKey>.toPem(passphrase: CharArray? = null): String {
  return this.joinToString("\n") { it.toPem(passphrase) }
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
 * Checks if all certificates in the list are trusted according to the provided trusted roots.
 *
 * @param trustedRoots The list of trusted root certificates.
 * @return True if all certificates are trusted, false otherwise.
 */
fun List<X509Certificate>.areAllCertificatesTrusted(trustedRoots: List<X509Certificate>): Boolean {
  return this.all { cert -> trustedRoots.any { it.getDigest(DigestAlgorithm.SHA256) == cert.getDigest(
    DigestAlgorithm.SHA256
  ) } }
}

/**
 * Converts any supported type to its PEM representation.
 *
 * @return The PEM formatted string of the provided type.
 * @throws IllegalArgumentException if the type is unsupported for PEM conversion.
 */
fun Any.toPem(): String {
  return when (this) {
    is X509Certificate -> CertificateUtils.getCertificatePem(this)
    is PrivateKey -> this.toPem()
    else -> throw IllegalArgumentException("Unsupported type for PEM conversion: ${this::class.java}")
  }
}

/**
 * Checks if the PrivateKey is in PKCS#8 format.
 *
 * @return True if the format is PKCS#8, false otherwise.
 */
fun PrivateKey.isPkcs8(): Boolean {
  return this.format == "PKCS#8"
}

/**
 * Checks if the PrivateKey is in PKCS#1 format.
 *
 * @return True if the format is PKCS#1, false otherwise.
 */
fun PrivateKey.isPkcs1(): Boolean {
  return this.format == "PKCS#1"
}
