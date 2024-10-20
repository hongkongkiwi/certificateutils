package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.AndroidKeyStoreUtils
import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils.DH_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.DSA_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.EC_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.ED25519_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.ED448_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.GENERIC_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.RSA_ENCRYPTED_PRIVATE_KEY_MARKERS
import com.github.hongkongkiwi.certificateutils.PEMUtils.X25519_ENCRYPTED_PRIVATE_KEY_MARKERS
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Checks if the string is in PEM format for a certificate.
 *
 * @return True if the string contains generic certificate markers, false otherwise.
 */
fun String.isCertificatePem(): Boolean {
  return this.contains(PEMUtils.GENERIC_CERTIFICATE_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a private key.
 *
 * @return True if the string contains any known private key markers, false otherwise.
 */
fun String.isPrivateKeyPem(): Boolean {
  return this.contains(PEMUtils.GENERIC_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.RSA_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.EC_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DSA_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED25519_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED448_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.X25519_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DH_PRIVATE_KEY_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a private key.
 *
 * @return True if the string contains any known private key markers, false otherwise.
 */
fun String.isEncryptedPrivateKeyPem(): Boolean {
  return this.contains(PEMUtils.GENERIC_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.EC_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.RSA_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DSA_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED25519_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED448_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.X25519_ENCRYPTED_PRIVATE_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DH_ENCRYPTED_PRIVATE_KEY_MARKERS.first)
}

/**
 * Checks if the string has keystore alias PEM markers.
 * This is a simple custom format that was just made up to store a PEM style marker and keystore alias name.
 *
 * @return True if the string contains any known keystore alias markers, false otherwise.
 */
fun String.isKeyStorePem(): Boolean {
  return this.contains(AndroidKeyStoreUtils.KEYSTORE_ALIAS_MARKERS.first) && this.contains(AndroidKeyStoreUtils.KEYSTORE_ALIAS_MARKERS.second)
}

/**
 * Checks if the string is in PEM format for a public key.
 *
 * @return True if the string contains any known public key markers, false otherwise.
 */
fun String.isPublicKeyPem(): Boolean {
  return this.contains(PEMUtils.RSA_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.EC_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DSA_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED25519_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.ED448_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.X25519_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.DH_PUBLIC_KEY_MARKERS.first) ||
    this.contains(PEMUtils.GENERIC_PUBLIC_KEY_MARKERS.first)
}

/**
 * Checks if the string is in PEM format for a certificate signing request (CSR).
 *
 * @return True if the string contains any CSR markers, false otherwise.
 */
fun String.isCsrPem(): Boolean {
  return this.contains(PEMUtils.CERTIFICATE_REQUEST_MARKERS.first) ||
    this.contains(PEMUtils.NEW_CERTIFICATE_REQUEST_MARKERS.first)
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
  return PEMUtils.parseCertificatePem(this, allowExpired).first()
}

/**
 * Converts a PEM encoded string to a list of X509Certificates.
 *
 * @param allowExpired If true, allows expired certificates.
 * @return A list of parsed X509Certificates.
 */
fun String.toX509Certificates(allowExpired: Boolean = false): List<X509Certificate> {
  return PEMUtils.parseCertificatePem(this, allowExpired)
}

/**
 * Converts a PEM encoded string to a PKCS10CertificationRequest.
 *
 * @return The parsed PKCS10CertificationRequest.
 */
fun String.toPKCS10CertificationRequest(): PKCS10CertificationRequest {
  return PEMUtils.parseCsrPem(this).first()
}

/**
 * Converts a PEM encoded string to a list of PKCS10CertificationRequests.
 *
 * @return A list of parsed PKCS10CertificationRequests.
 */
fun String.toPKCS10CertificationRequests(): List<PKCS10CertificationRequest> {
  return PEMUtils.parseCsrPem(this)
}

/**
 * Converts a PEM encoded string to a PrivateKey.
 *
 * @return The parsed PrivateKey.
 */
fun String.toPrivateKey(passphrase: CharArray? = null): PrivateKey {
  return PEMUtils.parsePrivateKeyPem(this, passphrase).first()
}

/**
 * Converts a PEM encoded string to a list of PrivateKeys.
 *
 * @return A list of parsed PrivateKeys.
 */
fun String.toPrivateKeys(passphrase: CharArray? = null): List<PrivateKey> {
  return PEMUtils.parsePrivateKeyPem(this, passphrase)
}

/**
 * Converts a PEM encoded string to an encrypted PrivateKey using a passphrase.
 *
 * @param passphrase The passphrase used for decryption.
 * @return The decrypted PrivateKey.
 */
fun String.toEncryptedPrivateKey(passphrase: CharArray): PrivateKey {
  return PEMUtils.parsePrivateKeyPem(this, passphrase).first()
}

/**
 * Converts a PEM encoded string to a list of encrypted PrivateKeys using a passphrase.
 *
 * @param passphrase The passphrase used for decryption.
 * @return A list of decrypted PrivateKeys.
 */
fun String.toEncryptedPrivateKeys(passphrase: CharArray): List<PrivateKey> {
  return PEMUtils.parsePrivateKeyPem(this, passphrase)
}

/**
 * Converts a PEM encoded string to a PublicKey.
 *
 * @return The parsed PublicKey.
 */
fun String.toPublicKey(): PublicKey {
  return PEMUtils.parsePublicKeyPem(this).first()
}

/**
 * Converts a PEM encoded string to a list of PublicKeys.
 *
 * @return A list of parsed PublicKeys.
 */
fun String.toPublicKeys(): List<PublicKey> {
  return PEMUtils.parsePublicKeyPem(this)
}

/**
 * Extension function to check if a string is valid Base64-encoded.
 *
 * @return true if the string is valid Base64, false otherwise.
 */
fun String.isBase64Encoded(): Boolean {
  return try {
    // Try to decode the string using Base64 decoder
    Base64.getDecoder().decode(this)
    true // If decoding succeeds, it's a valid Base64 string
  } catch (e: IllegalArgumentException) {
    false // If decoding fails, it's not a valid Base64 string
  }
}

/**
 * Extension function to decode a Base64-encoded string.
 *
 * @return The decoded byte array.
 * @throws IllegalArgumentException if the string is not valid Base64.
 */
fun String.decodeBase64(): ByteArray {
  return try {
    Base64.getDecoder().decode(this)
  } catch (e: IllegalArgumentException) {
    throw IllegalArgumentException("The string is not valid Base64: ${e.message}", e)
  }
}

/**
 * Converts a hexadecimal string back to a ByteArray.
 *
 * @return The byte array.
 */
fun String.hexToByteArray(): ByteArray {
  return chunked(2)
    .map { it.toInt(16).toByte() }
    .toByteArray()
}

/**
 * Removes all non-Base64 characters from the input string.
 *
 * Valid Base64 characters include:
 * - Uppercase letters (A-Z)
 * - Lowercase letters (a-z)
 * - Digits (0-9)
 * - Plus sign (+) and forward slash (/)
 * - Equals sign (=) used for padding
 *
 * Any character not in this set will be removed, including whitespace,
 * special characters, newlines, and tabs.
 *
 * @return A new string containing only valid Base64 characters.
 */
fun String.stripNonBase64Chars(): String {
  // Replace all characters in the input that are NOT Base64 characters with an empty string
  return this.replace(Regex("[^A-Za-z0-9+/=]"), "")
}
