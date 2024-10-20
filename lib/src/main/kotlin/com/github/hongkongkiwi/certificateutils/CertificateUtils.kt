package com.github.hongkongkiwi.certificateutils

import android.annotation.SuppressLint
import android.util.Log
import com.github.hongkongkiwi.certificateutils.builders.*
import com.github.hongkongkiwi.certificateutils.enums.*
import com.github.hongkongkiwi.certificateutils.exceptions.*
import com.github.hongkongkiwi.certificateutils.extensions.getPublicKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.spec.ECPoint as JavaECPoint
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

@Suppress("unused", "MemberVisibilityCanBePrivate")
object CertificateUtils {

  internal val TAG = CertificateUtils::class.java.simpleName

  init {
    ensureBouncyCastleProvider()
  }

  fun ensureBouncyCastleProvider() {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  // OID defnitions
  const val OID_SHA256_RSA = "1.2.840.113549.1.1.11" // SHA-256 with RSA
  const val OID_SHA256_ECDSA = "1.2.840.10045.4.3.2" // SHA-256 with ECDSA

  /**
   * Generates a self-signed X.509 certificate using the provided private key.
   *
   * @param privateKey The private key used to sign the certificate (e.g., RSA, EC).
   * @param subjectName The subject name for the certificate.
   * @param serialNumber The serial number for the certificate.
   * @param validUntil The expiration date of the certificate.
   * @return The self-signed X.509 certificate.
   * @throws SelfSignedCertificateGenerationException If there is an error during certificate generation.
   */
  fun generateSelfSignedCertificate(
    privateKey: PrivateKey,
    subjectName: X500Name = X500Name("CN=Self-Signed"),
    serialNumber: BigInteger = BigInteger.valueOf(System.currentTimeMillis()),
    validUntil: Date = Date.from(
      LocalDateTime.now()
        .plusYears(1)  // Add 1 year
        .toInstant(ZoneOffset.UTC)  // Convert back to Instant
    ),
    signatureAlgorithm: String = "SHA256"
  ): X509Certificate {
    try {
      require(signatureAlgorithm.isNotBlank()) { "Signature algorithm cannot be blank."}

      val keyFactoryAlgo = if (privateKey.algorithm === "ECDSA") {
        "EC"
      } else {
        privateKey.algorithm
      }

      // Extract the public key from the provided private key
      val publicKey = privateKey.getPublicKey()

      // Create the certificate builder with subject and issuer as "Self-Signed"
      val certBuilder = JcaX509v3CertificateBuilder(
        subjectName,                 // Issuer (self-signed)
        serialNumber,                // Serial number
        Date(System.currentTimeMillis()), // Start date
        validUntil,                  // End date
        subjectName,                 // Subject
        publicKey                    // Public key
      )

      val sigAlgo = if (!signatureAlgorithm.contains("with", ignoreCase = true)) {
        if (CryptographicAlgorithm.EC.matches(privateKey.algorithm)) {
          "${signatureAlgorithm.uppercase()}withECDSA"
        } else {
          "${signatureAlgorithm.uppercase()}with${privateKey.algorithm}"
        }
      } else {
        signatureAlgorithm.replace("with", "with", ignoreCase = true)
      }

      // Sign the certificate using the private key
      val signer: ContentSigner = JcaContentSignerBuilder(sigAlgo).build(privateKey)

      // Convert and return the generated certificate
      return JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))
    } catch (e: Exception) {
      throw SelfSignedCertificateGenerationException("Failed to generate self-signed certificate: ${e.message}", e)
    }
  }

  /**
   * Ensures the provided X509Certificate and PrivateKey form a matching key pair.
   *
   * @param certificate The X509Certificate to compare.
   * @param privateKey The PrivateKey to compare.
   * @return True if the private key matches the public key from the certificate.
   * @throws KeyPairMismatchException If the private key does not match the certificate's public key.
   * @throws UnsupportedKeyAlgorithmException If the private key algorithm is unsupported or not available in the current SDK version.
   */
  @SuppressLint("ObsoleteSdkInt")
  @JvmStatic
  @Throws(
    KeyPairMismatchException::class,
    UnsupportedKeyAlgorithmException::class
  )
  fun isCertificateSignedByPrivateKey(
    certificate: X509Certificate,
    privateKey: PrivateKey
  ): Boolean {
    val publicKeyFromCertificate = certificate.publicKey
    val publicKeyFromPrivateKey = KeyUtils.getPublicKey(privateKey)
    return if (publicKeyFromCertificate == publicKeyFromPrivateKey) {
      true
    } else {
      throw KeyPairMismatchException("The provided certificate and private key do not match.")
    }
  }

  /**
   * Creates a PKCS#10 Certification Request (CSR) using the provided private key and subject distinguished name (DN).
   *
   * This method takes a private key and a SubjectDNBuilder instance, builds the subject DN string,
   * and then creates the CSR based on the given private key and subject DN.
   *
   * @param privateKey The private key to be used for signing the CSR.
   * @param subjectDNBuilder An instance of SubjectDNBuilder that provides the attributes for the subject DN.
   * @return The constructed PKCS10CertificationRequest object.
   */
  fun generateCertificateSigningRequest(
    privateKey: PrivateKey,
    subjectDNBuilder: CsrSubjectDNBuilder
  ): PKCS10CertificationRequest {
    // Build the subject DN string from the SubjectDNBuilder instance
    return generateCertificateSigningRequest(privateKey, subjectDNBuilder.build())
  }

  /**
   * Generates a Certificate Signing Request (CSR) using the provided private key and subject distinguished name (DN).
   *
   * @param privateKey The PrivateKey object.
   * @param subjectDN The subject distinguished name (DN) string.
   * @return The generated CSR as a PEM-formatted string.
   * @throws InvalidPrivateKeyPemException If the private key is invalid.
   * @throws UnsupportedKeyAlgorithmException If the private key algorithm is unsupported.
   */
  @JvmStatic
  @Throws(
    InvalidPrivateKeyPemException::class,
    UnsupportedKeyAlgorithmException::class
  )
  fun generateCertificateSigningRequest(
    privateKey: PrivateKey,
    subjectDN: String,
    signatureAlgorithm: String = "SHA256",
  ): PKCS10CertificationRequest {
    require(subjectDN.isNotBlank()) { "Subject DN cannot be empty." }

    val publicKey = KeyUtils.getPublicKey(privateKey)

    val keyPair = KeyPair(publicKey, privateKey)
    val subject = X500Principal(subjectDN)

    return try {
      val csrBuilder = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
      val sigAlgo = if (!signatureAlgorithm.contains("with", ignoreCase = true)) {
        if (CryptographicAlgorithm.EC.matches(privateKey.algorithm)) {
          "${signatureAlgorithm.uppercase()}withECDSA"
        } else {
          "${signatureAlgorithm.uppercase()}with${privateKey.algorithm}"
        }
      } else {
        signatureAlgorithm.replace("with", "with", ignoreCase = true)
      }
      val sigAlgoName = SignatureAlgorithm.fromString(sigAlgo)
      requireNotNull(sigAlgoName) { "Unsupported signature algorithm: $signatureAlgorithm" }
      val signer: ContentSigner = JcaContentSignerBuilder(sigAlgoName.toString())
        .build(privateKey)

      csrBuilder.build(signer)
    } catch (e: OperatorCreationException) {
      throw InvalidPrivateKeyPemException("Failed to create content signer: ${e.message}.", e)
    } catch (e: IOException) {
      throw InvalidPrivateKeyPemException("Failed to encode CSR: ${e.message}.", e)
    }
  }

  /**
   * Generates an MD5 hash of the given X509 certificate.
   *
   * @param certificate The X509Certificate object.
   * @return The MD5 hash as a hex string.
   * @throws NoSuchAlgorithmException If MD5 algorithm is not available.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class)
  fun getCertificateMd5Digest(certificate: X509Certificate): String {
    return getCertificateFingerprint(certificate, DigestAlgorithm.MD5)
  }

  /**
   * Generates a SHA-256 hash of the given X509 certificate.
   *
   * @param certificate The X509Certificate object.
   * @return The SHA-256 hash as a hex string.
   * @throws NoSuchAlgorithmException If SHA-256 algorithm is not available.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class)
  fun getCertificateSha256Digest(certificate: X509Certificate): String {
    return getCertificateFingerprint(certificate, DigestAlgorithm.SHA256)
  }

  /**
   * Generates a SHA-512 hash of the given X509 certificate.
   *
   * @param certificate The X509Certificate object.
   * @return The SHA-512 hash as a hex string.
   * @throws NoSuchAlgorithmException If SHA-512 algorithm is not available.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class)
  fun getCertificateSha512Digest(certificate: X509Certificate): String {
    return getCertificateFingerprint(certificate, DigestAlgorithm.SHA512)
  }

  /**
   * Checks if the provided X.509 certificate is self-signed.
   *
   * A self-signed certificate is one where the subject and issuer distinguished names (DNs)
   * are the same, indicating that the certificate was signed by itself rather than a trusted CA.
   *
   * @param certificate The X509Certificate to check for self-signing.
   * @return True if the certificate is self-signed; false otherwise.
   */
  fun isCertificateSelfSigned(certificate: X509Certificate): Boolean {
    // Check if issuer and subject DNs are equal
    if (certificate.subjectX500Principal != certificate.issuerX500Principal) {
      return false
    }

    // Try to verify the certificate's signature with its own public key
    return try {
      certificate.verify(certificate.publicKey)
      true
    } catch (e: Exception) {
      false
    }
  }

  /**
   * Loads the set of trusted X.509 certificates from the default trust store.
   *
   * This method initializes a TrustManagerFactory with the default algorithm,
   * retrieves the trust managers, and extracts the accepted issuers (trusted certificates).
   *
   * @return A set of X509Certificate objects representing the trusted certificates from the default trust store.
   * @throws IllegalStateException If no X509TrustManager is found in the trust managers.
   */
  fun getSystemTrustedCertificate(): Set<X509Certificate> {
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?) // Passing null loads the default trust store

    val trustManagers = tmf.trustManagers
    val x509TrustManager = trustManagers
      .filterIsInstance<X509TrustManager>()
      .firstOrNull() ?: throw IllegalStateException("No X509TrustManager found")

    return x509TrustManager.acceptedIssuers.toSet()
  }

  /**
   * Checks if the provided certificate is trusted by comparing it against a set of trusted certificates.
   *
   * This method iterates through the provided set of trusted certificates to determine
   * if the given certificate matches any of them based on content equality.
   *
   * @param certificate The X509Certificate to check for trust.
   * @param trustedCertificates A set of trusted X509Certificate objects to compare against.
   *                            If null, the method will load trusted certificates from a predefined source.
   * @return True if the certificate is found in the set of trusted certificates; false otherwise.
   */
  fun isCertificateTrusted(
    certificate: X509Certificate,
    trustedCertificates: Set<X509Certificate>? = null
  ): Boolean {
    // Load trusted certificates if the provided set is null
    val effectiveTrustedCertificates = trustedCertificates ?: getSystemTrustedCertificate()

    // Iterate through the trusted certificates and check for a match
    for (trustedCert in effectiveTrustedCertificates) {
      // Use equals to compare the contents of the certificates
      if (certificate == trustedCert) {
        return true // Certificate is trusted
      }
    }
    return false // Certificate is not trusted
  }

  /**
   * Extracts the subject distinguished name (DN) from an X.509 certificate.
   *
   * This method retrieves the subject's distinguished name as a string from the provided
   * X.509 certificate object.
   *
   * @param certificate The X509Certificate object representing the certificate from which
   *                    to extract the subject.
   * @return The subject distinguished name (DN) string extracted from the certificate.
   * @throws InvalidCertificatePemException If the certificate is invalid or cannot be processed.
   */
  @JvmStatic
  @Throws(InvalidCertificatePemException::class)
  fun getCertificateSubjectDN(certificate: X509Certificate): String {
    return certificate.subjectX500Principal.name
  }

  /**
   * Extracts the subject distinguished name (DN) from a Certificate Signing Request (CSR).
   *
   * This method takes a PKCS#10 formatted CSR and returns the subject DN as a string.
   *
   * @param csr The PKCS10CertificationRequest object representing the PEM-formatted CSR.
   * @return The subject distinguished name (DN) string extracted from the CSR.
   * @throws InvalidCsrPemException If the CSR is invalid or cannot be processed.
   */
  @JvmStatic
  @Throws(InvalidCsrPemException::class)
  fun getCSRSubjectDN(csr: PKCS10CertificationRequest): String {
    return csr.subject.toString()
  }

  /**
   * Checks if the provided X.509 certificate is valid and not expired.
   *
   * This method verifies the validity of the certificate by checking its expiration
   * date and whether it is not yet valid. It returns true if the certificate is valid,
   * and false if it has expired or is not yet valid.
   *
   * @param certificate The X509Certificate object representing the certificate to validate.
   * @return True if the certificate is valid; false if it is expired or not yet valid.
   * @throws InvalidCertificatePemException If the certificate cannot be validated due to an invalid format or issue.
   */
  @JvmStatic
  @Throws(InvalidCertificatePemException::class)
  fun isCertificateValid(certificate: X509Certificate): Boolean {
    return try {
      certificate.checkValidity()
      true
    } catch (e: CertificateExpiredException) {
      false
    } catch (e: CertificateNotYetValidException) {
      false
    } catch (e: InvalidCertificatePemException) {
      throw e
    }
  }

  /**
   * Checks if the provided Certificate Signing Request (CSR) is valid.
   *
   * This method verifies the validity of the CSR by ensuring that it can be parsed successfully.
   * It checks that the CSR contains a valid subject distinguished name (DN) and verifies
   * the CSR's signature against the extracted public key.
   *
   * @param csr The PKCS10CertificationRequest object representing the CSR to validate.
   * @return True if the CSR is valid; false if it is not well-formed or has any issues.
   * @throws InvalidCertificatePemException If the CSR cannot be validated due to an invalid format or issue.
   */
  @JvmStatic
  @Throws(InvalidCertificatePemException::class)
  fun isCsrValid(csr: PKCS10CertificationRequest): Boolean {
    return try {
      // Check if the subject DN is valid
      val subjectDN = csr.subject.toString()
      require(subjectDN.isNotBlank()) { "CSR subject DN cannot be empty." }

      // Extract the public key from the CSR
      val publicKeyInfo = csr.subjectPublicKeyInfo
      val publicKey = JcaPEMKeyConverter().getPublicKey(publicKeyInfo)

      // Verify the signature using the public key
      require(verifyCsrSignature(csr, publicKey)) { "CSR signature is invalid." }

      true
    } catch (e: Exception) {
      throw InvalidCertificatePemException("Failed to validate CSR.", e)
    }
  }

  /**
   * Verifies the signature of the CSR.
   *
   * @param csr The PKCS10CertificationRequest to verify.
   * @param publicKey The public key to use for verification.
   * @return True if the signature is valid; false otherwise.
   */
  private fun verifyCsrSignature(csr: PKCS10CertificationRequest, publicKey: PublicKey): Boolean {
    return try {
      val signer = JcaContentVerifierProviderBuilder()
        .build(publicKey)

      csr.isSignatureValid(signer)
    } catch (e: Exception) {
      false
    }
  }

  /**
   * Generates a certificate fingerprint for the given data using the specified fingerprint algorithm.
   *
   * @param certificateData The data to generate a fingerprint for.
   * @param digestAlgorithm The fingerprint algorithm to use.
   * @return The generated fingerprint as a hex string.
   * @throws CertificateFingerprintException If the digest algorithm is not available or an error occurs during processing.
   */
  fun getCertificateFingerprint(
    certificateData: ByteArray,
    digestAlgorithm: DigestAlgorithm
  ): String {
    return try {
      val messageDigest = MessageDigest.getInstance(digestAlgorithm.digest)
      val digest = messageDigest.digest(certificateData)
      digest.joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
      throw CertificateFingerprintException("Failed to generate fingerprint using algorithm: ${digestAlgorithm.digest}", e)
    }
  }

  /**
   * Generates a fingerprint for the given X509Certificate using the specified fingerprint algorithm.
   *
   * @param certificate The X509Certificate to generate a fingerprint for.
   * @param digestAlgorithm The fingerprint algorithm to use.
   * @return The generated fingerprint as a hex string.
   * @throws CertificateFingerprintException If the digest algorithm is not available or an error occurs during processing.
   */
  fun getCertificateFingerprint(
    certificate: X509Certificate,
    digestAlgorithm: DigestAlgorithm
  ): String {
    return try {
      val encodedCertificate = certificate.encoded
      getCertificateFingerprint(encodedCertificate, digestAlgorithm)
    } catch (e: Exception) {
      throw CertificateFingerprintException("Failed to generate fingerprint for certificate using algorithm: ${digestAlgorithm.digest}", e)
    }
  }
}
