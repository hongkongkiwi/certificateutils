package com.github.hongkongkiwi.certificateutils.extensions

import com.github.hongkongkiwi.certificateutils.CertificateUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.security.PublicKey

/**
 * Checks if the PKCS10CertificationRequest is valid.
 *
 * @return True if the CSR is valid, false otherwise.
 */
fun PKCS10CertificationRequest.isCsrValid(): Boolean {
  return CertificateUtils.isCsrValid(this)
}

/**
 * Converts PKCS10CertificationRequest to its PEM representation.
 *
 * @return The PEM formatted string of the PKCS10CertificationRequest object.
 */
fun PKCS10CertificationRequest.toPem(): String {
  return PEMUtils.getCsrPem(this)
}

/**
 * Extracts the Common Name (CN) from the PKCS10CertificationRequest's subject.
 *
 * @return The Common Name as a String, or null if not found.
 */
fun PKCS10CertificationRequest.getCommonName(): String? {
  val x500Name: X500Name = this.subject
  val cnAttribute = x500Name.getRDNs(BCStyle.CN).firstOrNull()
  return cnAttribute?.first?.value?.toString()
}

/**
 * Extracts the PublicKey from the PKCS10CertificationRequest.
 *
 * @return The PublicKey embedded in the CSR.
 */
fun PKCS10CertificationRequest.getPublicKey(): PublicKey {
  val subjectPublicKeyInfo: SubjectPublicKeyInfo = this.subjectPublicKeyInfo
  return JcaPEMKeyConverter().getPublicKey(subjectPublicKeyInfo)
}

/**
 * Verifies the signature of the PKCS10CertificationRequest.
 *
 * @return True if the signature is valid, false otherwise.
 */
fun PKCS10CertificationRequest.isSignatureValid(): Boolean {
  return try {
    // Extract the public key from the CSR using JcaPEMKeyConverter
    val publicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

    // Build a verifier provider using the extracted public key
    val verifierProvider = JcaContentVerifierProviderBuilder().build(publicKey)

    // Verify the CSR signature using the verifier provider
    this.isSignatureValid(verifierProvider)
  } catch (e: Exception) {
    // Catch any exception and return false if verification fails
    false
  }
}

/**
 * Extracts the subject information (Distinguished Name) from the CSR.
 *
 * @return A map of Distinguished Name attributes (e.g., CN, O, C) and their values.
 */
fun PKCS10CertificationRequest.getSubjectInfo(): Map<String, String> {
  val subject: X500Name = this.subject
  val subjectInfo = mutableMapOf<String, String>()

  // Loop through all RDNs (Relative Distinguished Names)
  subject.rdNs.forEach { rdn: RDN ->
    // Retrieve the attribute type (e.g., CN, O, C) and value
    val type = BCStyle.INSTANCE.oidToDisplayName(rdn.first.type)
    val value = rdn.first.value.toString()

    // Add the attribute to the map
    subjectInfo[type] = value
  }

  return subjectInfo
}

/**
 * Extension function for [PKCS10CertificationRequest] that converts the certification request
 * to a DER-encoded byte array.
 *
 * DER (Distinguished Encoding Rules) is a binary encoding format commonly used for
 * certificates and public/private keys. This function converts the PKCS#10 certificate signing
 * request into its DER-encoded byte array representation.
 *
 * @return A byte array containing the DER-encoded representation of the PKCS#10 certification request.
 *
 * @throws IllegalArgumentException if the certification request cannot be encoded.
 */
fun PKCS10CertificationRequest.toDer(): ByteArray {
  return this.encoded ?: throw IllegalArgumentException("Failed to encode PKCS10CertificationRequest to DER format.")
}

/**
 * Checks if the CSR's key is using RSA algorithm.
 *
 * @return True if the CSR's key is RSA, false otherwise.
 */
fun PKCS10CertificationRequest.isRsaKey(): Boolean {
  // Extract the PublicKey from the CSR using JcaPEMKeyConverter
  val publicKey: PublicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

  // Check if the extracted PublicKey is using the RSA algorithm
  return publicKey.algorithm.equals("RSA", ignoreCase = true)
}

/**
 * Checks if the CSR's key is using EC algorithm.
 *
 * @return True if the CSR's key is EC, false otherwise.
 */
fun PKCS10CertificationRequest.isEcKey(): Boolean {
  // Extract the PublicKey from the CSR using JcaPEMKeyConverter
  val publicKey: PublicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

  // Check if the extracted PublicKey is using the EC algorithm
  return publicKey.algorithm.equals("EC", ignoreCase = true)
}

/**
 * Checks if the CSR's key is using DSA algorithm.
 *
 * @return True if the CSR's key is DSA, false otherwise.
 */
fun PKCS10CertificationRequest.isDsaKey(): Boolean {
  // Extract the PublicKey from the CSR using JcaPEMKeyConverter
  val publicKey: PublicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

  // Check if the extracted PublicKey is using the DSA algorithm
  return publicKey.algorithm.equals("DSA", ignoreCase = true)
}

/**
 * Checks if the CSR's key is using EdDSA algorithm.
 *
 * @return True if the CSR's key is EdDSA, false otherwise.
 */
fun PKCS10CertificationRequest.isEdDsaKey(): Boolean {
  // Extract the PublicKey from the CSR using JcaPEMKeyConverter
  val publicKey: PublicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

  // Check if the extracted PublicKey is using the EdDSA algorithm
  return publicKey.algorithm.equals("EdDSA", ignoreCase = true)
}

/**
 * Retrieves the key size from the CSR's public key.
 *
 * @return The key size in bits.
 */
fun PKCS10CertificationRequest.getKeySize(): Int {
  // Extract the PublicKey from the CSR using JcaPEMKeyConverter
  val publicKey: PublicKey = JcaPEMKeyConverter().getPublicKey(this.subjectPublicKeyInfo)

  // Determine the key size based on the type of public key
  return when (publicKey) {
    is java.security.interfaces.RSAPublicKey -> publicKey.modulus.bitLength()
    is java.security.interfaces.ECPublicKey -> publicKey.params.curve.field.fieldSize
    is java.security.interfaces.DSAPublicKey -> publicKey.params.p.bitLength()
    else -> throw IllegalArgumentException("Unsupported public key algorithm: ${publicKey.algorithm}")
  }
}




