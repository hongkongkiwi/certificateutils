package com.github.hongkongkiwi.certificateutils

import com.github.hongkongkiwi.certificateutils.CertificateUtils.OID_SHA256_ECDSA
import com.github.hongkongkiwi.certificateutils.CertificateUtils.OID_SHA256_RSA
import com.github.hongkongkiwi.certificateutils.enums.CryptographicAlgorithm
import com.github.hongkongkiwi.certificateutils.enums.EncryptionAlgorithm
import com.github.hongkongkiwi.certificateutils.exceptions.ExpiredCertificateException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCertificatePemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCsrPemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPrivateKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPublicKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.UntrustedCertificateException
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import com.github.hongkongkiwi.certificateutils.extensions.stripNonBase64Chars
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.operator.OutputEncryptor
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPrivateKeySpec
import java.util.Base64
import kotlin.math.min

@Suppress("unused", "MemberVisibilityCanBePrivate")
object PEMUtils {
  internal val TAG = PEMUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  // Individual Pair Definitions
  // Certificate markers
  val GENERIC_CERTIFICATE_MARKERS = Pair("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
  val PKCS7_MARKERS = Pair("-----BEGIN PKCS7-----", "-----END PKCS7-----")
  val TRUSTED_CERTIFICATE_MARKERS =
    Pair("-----BEGIN TRUSTED CERTIFICATE-----", "-----END TRUSTED CERTIFICATE-----")
  val ATTRIBUTE_CERTIFICATE_MARKERS =
    Pair("-----BEGIN ATTRIBUTE CERTIFICATE-----", "-----END ATTRIBUTE CERTIFICATE-----")

  // Key markers
  val GENERIC_PRIVATE_KEY_MARKERS = Pair("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
  val GENERIC_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----")

  val EC_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----")
  val EC_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED EC PRIVATE KEY-----", "-----END ENCRYPTED EC PRIVATE KEY-----")

  val RSA_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
  val RSA_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED RSA PRIVATE KEY-----", "-----END ENCRYPTED RSA PRIVATE KEY-----")

  val DSA_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----")
  val DSA_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED DSA PRIVATE KEY-----", "-----END ENCRYPTED DSA PRIVATE KEY-----")

  val ED25519_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ED25519 PRIVATE KEY-----", "-----END ED25519 PRIVATE KEY-----")
  val ED25519_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair(
    "-----BEGIN ENCRYPTED ED25519 PRIVATE KEY-----",
    "-----END ENCRYPTED ED25519 PRIVATE KEY-----"
  )

  val ED448_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ED448 PRIVATE KEY-----", "-----END ED448 PRIVATE KEY-----")
  val ED448_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED ED448 PRIVATE KEY-----", "-----END ENCRYPTED ED448 PRIVATE KEY-----")

  val X25519_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN X25519 PRIVATE KEY-----", "-----END X25519 PRIVATE KEY-----")
  val X25519_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair(
    "-----BEGIN ENCRYPTED X25519 PRIVATE KEY-----",
    "-----END ENCRYPTED X25519 PRIVATE KEY-----"
  )

  val DH_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN DH PRIVATE KEY-----", "-----END DH PRIVATE KEY-----")
  val DH_ENCRYPTED_PRIVATE_KEY_MARKERS =
    Pair("-----BEGIN ENCRYPTED DH PRIVATE KEY-----", "-----END ENCRYPTED DH PRIVATE KEY-----")

  // Public key markers
  val RSA_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")
  val EC_PUBLIC_KEY_MARKERS = Pair("-----BEGIN EC PUBLIC KEY-----", "-----END EC PUBLIC KEY-----")
  val DSA_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN DSA PUBLIC KEY-----", "-----END DSA PUBLIC KEY-----")
  val ED25519_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN ED25519 PUBLIC KEY-----", "-----END ED25519 PUBLIC KEY-----")
  val ED448_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN ED448 PUBLIC KEY-----", "-----END ED448 PUBLIC KEY-----")
  val X25519_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN X25519 PUBLIC KEY-----", "-----END X25519 PUBLIC KEY-----")
  val DH_PUBLIC_KEY_MARKERS = Pair("-----BEGIN DH PUBLIC KEY-----", "-----END DH PUBLIC KEY-----")
  val GENERIC_PUBLIC_KEY_MARKERS =
    Pair("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----") // Generic public key marker

  // CSR markers
  val CERTIFICATE_REQUEST_MARKERS =
    Pair("-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
  val NEW_CERTIFICATE_REQUEST_MARKERS =
    Pair("-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----")

  // Lists of markers for easy access
  // Key markers
  val PRIVATE_KEY_MARKERS = listOf(
    GENERIC_PRIVATE_KEY_MARKERS,
    EC_PRIVATE_KEY_MARKERS,
    RSA_PRIVATE_KEY_MARKERS,
    DSA_PRIVATE_KEY_MARKERS,
    ED25519_PRIVATE_KEY_MARKERS,
    ED448_PRIVATE_KEY_MARKERS,
    X25519_PRIVATE_KEY_MARKERS,
    DH_PRIVATE_KEY_MARKERS
  )

  // Encrypted Key markers
  val ENCRYPTED_PRIVATE_KEY_MARKERS = listOf(
    GENERIC_ENCRYPTED_PRIVATE_KEY_MARKERS,
    EC_ENCRYPTED_PRIVATE_KEY_MARKERS,
    RSA_ENCRYPTED_PRIVATE_KEY_MARKERS,
    DSA_ENCRYPTED_PRIVATE_KEY_MARKERS,
    ED25519_ENCRYPTED_PRIVATE_KEY_MARKERS,
    ED448_ENCRYPTED_PRIVATE_KEY_MARKERS,
    X25519_ENCRYPTED_PRIVATE_KEY_MARKERS,
    DH_ENCRYPTED_PRIVATE_KEY_MARKERS,
  )

  // Public Key markers
  val PUBLIC_KEY_MARKERS = listOf(
    RSA_PUBLIC_KEY_MARKERS,
    EC_PUBLIC_KEY_MARKERS,
    DSA_PUBLIC_KEY_MARKERS,
    ED25519_PUBLIC_KEY_MARKERS,
    ED448_PUBLIC_KEY_MARKERS,
    X25519_PUBLIC_KEY_MARKERS,
    GENERIC_PUBLIC_KEY_MARKERS // Added generic public key marker
  )

  // Certificate markers
  val CERTIFICATE_MARKERS = listOf(
    GENERIC_CERTIFICATE_MARKERS,
    PKCS7_MARKERS,
    TRUSTED_CERTIFICATE_MARKERS,
    ATTRIBUTE_CERTIFICATE_MARKERS
  )

  // CSR markers
  val CSR_MARKERS = listOf(
    CERTIFICATE_REQUEST_MARKERS,
    NEW_CERTIFICATE_REQUEST_MARKERS
  )

  /**
   * Checks the format of the given byte array to determine if it represents a PKCS#1 or PKCS#8 private key,
   * a public key, a certificate (X.509), or a certificate signing request (CSR).
   *
   * The method uses the first byte to determine the type of data:
   * - PKCS#1 private key: starts with 0x30 (ASN.1 sequence)
   * - PKCS#8 private key: starts with 0x30 (ASN.1 sequence)
   * - Public key (SubjectPublicKeyInfo): starts with 0x30 (ASN.1 sequence)
   * - X.509 Certificate: starts with 0x30 (ASN.1 sequence)
   * - CSR (Certificate Signing Request): starts with 0x30 (ASN.1 sequence)
   *
   * @param keyBytes The byte array containing the key, certificate, or CSR data to check.
   * @return A string indicating the detected format: "PKCS#1 Private Key", "PKCS#8 Private Key",
   * "Public Key", "X.509 Certificate", "CSR", or "Unknown Format".
   */
  private fun detectKeyFormat(keyBytes: ByteArray): String {
    if (keyBytes.isEmpty()) {
      return "Empty Data"
    }

    // Common ASN.1 sequence identifier (0x30) for all formats
    if (keyBytes[0] != 0x30.toByte()) {
      return "Unknown Format"
    }

    return try {
      // Detect based on specific ASN.1 structures for each type
      when {
        isPKCS1PrivateKey(keyBytes) -> "PKCS#1 Private Key"
        isPKCS8PrivateKey(keyBytes) -> "PKCS#8 Private Key"
        isPublicKey(keyBytes) -> "Public Key"
        isX509Certificate(keyBytes) -> "X.509 Certificate"
        isCSR(keyBytes) -> "CSR (Certificate Signing Request)"
        else -> "Unknown Format"
      }
    } catch (e: Exception) {
      "Unknown Format"
    }
  }

  // Helper method to check if the byte array represents a PKCS#1 formatted private key
  private fun isPKCS1PrivateKey(keyBytes: ByteArray): Boolean {
    // PKCS#1 private key should start with 0x30 and include an INTEGER for version
    return keyBytes.isNotEmpty() && keyBytes[0] == 0x30.toByte() && keyBytes.contains(0x02.toByte()) // INTEGER tag
  }

  // Helper method to check if the byte array represents a PKCS#8 formatted private key
  private fun isPKCS8PrivateKey(keyBytes: ByteArray): Boolean {
    // PKCS#8 private key starts with 0x30 and contains the OID for privateKeyInfo (1.2.840.113549.1.5.3)
    val pkcs8Header = byteArrayOf(0x30.toByte(), 0x82.toByte())
    return keyBytes.isNotEmpty() && keyBytes.sliceArray(0 until 2).contentEquals(pkcs8Header)
  }

  // Helper method to check if the byte array represents a public key (SubjectPublicKeyInfo)
  private fun isPublicKey(keyBytes: ByteArray): Boolean {
    // Public key (SubjectPublicKeyInfo) starts with 0x30 and contains the OID for rsaEncryption (1.2.840.113549.1.1.1)
    val rsaPublicKeyOid = byteArrayOf(
      0x30.toByte(),
      0x0d.toByte(),
      0x06.toByte(),
      0x09.toByte(),
      0x2a.toByte(),
      0x86.toByte(),
      0x48.toByte(),
      0x86.toByte(),
      0xf7.toByte(),
      0x0d.toByte(),
      0x01.toByte(),
      0x01.toByte(),
      0x01.toByte()
    ) // OID for rsaEncryption
    return keyBytes.isNotEmpty() && keyBytes.sliceArray(rsaPublicKeyOid.indices)
      .contentEquals(rsaPublicKeyOid)
  }

  // Helper method to check if the byte array represents an X.509 certificate
  private fun isX509Certificate(keyBytes: ByteArray): Boolean {
    // X.509 certificate starts with 0x30 and contains the OID for X.509 certificates (1.2.840.10045.4.3.2)
    return keyBytes.isNotEmpty() && keyBytes[0] == 0x30.toByte() && keyBytes.contains(0x03.toByte()) // BIT STRING tag
  }

  // Helper method to check if the byte array represents a CSR (PKCS#10)
  private fun isCSR(keyBytes: ByteArray): Boolean {
    // CSR starts with 0x30 and contains the OID for PKCS#10 certificationRequest (1.2.840.113549.1.9.14)
    val csrHeader = byteArrayOf(0x30.toByte(), 0x82.toByte())
    return keyBytes.isNotEmpty() && keyBytes.sliceArray(0 until 2).contentEquals(csrHeader)
  }

  /**
   * Converts a PKCS#1 formatted RSA private key to PKCS#8 format.
   *
   * This method takes a byte array representing a PKCS#1 formatted key and converts it to
   * PKCS#8 format using Bouncy Castle. The PKCS#8 format is a more modern and flexible
   * format for private keys.
   *
   * @param pkcs1Bytes The byte array containing the PKCS#1 formatted key data.
   * @return A byte array representing the PKCS#8 encoded private key.
   * @throws GeneralSecurityException If there is an issue generating the private key or converting formats.
   */
  private fun convertPKCS1ToPKCS8(pkcs1Bytes: ByteArray): ByteArray {
    // Convert the PKCS#1 formatted key to PKCS#8 format using Bouncy Castle
    val pkcs1KeySpec = RSAPrivateKeySpec(
      BigInteger(1, pkcs1Bytes),
      BigInteger.valueOf(65537)
    ) // Adjust according to the key
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(pkcs1KeySpec)

    // Generate the PKCS#8 encoded format
    return privateKey.encoded // PKCS#8 format is usually obtained from the private key
  }


  /**
   * Determines the appropriate PEM markers based on the X.509 Certificate type.
   *
   * This method checks the type of Certificate (e.g., CA, organizational, common name)
   * and returns the correct PEM begin and end markers for the certificate type.
   *
   * @param certificate The X509Certificate object to determine the PEM type for.
   * @return A pair of strings representing the PEM begin and end markers for the certificate type.
   */
  private fun getCertificatePemMarkers(certificate: X509Certificate): Pair<String, String> {
    val certificateType = when {
      certificate.basicConstraints != -1 -> "CA"
      certificate.subjectDN.name.contains("O=") -> "Organizational"
      certificate.subjectDN.name.contains("CN=") -> "Common Name"
      else -> "Generic"
    }

    return when (certificateType) {
      "CA" -> TRUSTED_CERTIFICATE_MARKERS
      "Organizational" -> GENERIC_CERTIFICATE_MARKERS
      "Common Name" -> GENERIC_CERTIFICATE_MARKERS
      else -> GENERIC_CERTIFICATE_MARKERS // Default to generic certificate markers
    }
  }

  /**
   * Determines the appropriate PEM markers based on the CSR type.
   *
   * This method checks the signature algorithm of the CSR and returns the correct PEM
   * begin and end markers for the type.
   *
   * @param csr The PKCS10CertificationRequest object to determine the PEM type for.
   * @return A pair of strings representing the PEM begin and end markers for the CSR type.
   */
  private fun getCsrPemMarkers(csr: PKCS10CertificationRequest): Pair<String, String> {
    return when (csr.signatureAlgorithm.algorithm.id) {
      OID_SHA256_RSA -> CERTIFICATE_REQUEST_MARKERS // SHA256 with RSA
      OID_SHA256_ECDSA -> NEW_CERTIFICATE_REQUEST_MARKERS // SHA256 with ECDSA
      else -> CERTIFICATE_REQUEST_MARKERS // Default to generic CSR markers
    }
  }

  /**
   * Determines the appropriate PEM markers based on the PrivateKey type.
   *
   * This method checks the algorithm of the PrivateKey (e.g., RSA, EC, DSA, Ed25519, Ed448, etc.)
   * and returns the correct PEM begin and end markers for the key type.
   *
   * @param privateKey The PrivateKey object to determine the PEM type for.
   * @return A pair of strings representing the PEM begin and end markers for the key type.
   */
  fun getPrivateKeyPemMarkers(privateKey: PrivateKey): Pair<String, String> {
    require(privateKey.algorithm != "AndroidKeyStore") { "Android Keystore keys cannot be extracted into PEM." }

    return try {
      // Use the Algorithm enum to map the private key algorithm to the corresponding PEM markers
      when (CryptographicAlgorithm.fromString(privateKey.algorithm)) {
        CryptographicAlgorithm.RSA -> RSA_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.EC -> EC_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.DSA -> DSA_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.Ed25519 -> ED25519_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.Ed448 -> ED448_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.X25519 -> X25519_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.DH -> DH_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.ECDSA -> EC_PRIVATE_KEY_MARKERS // ECDSA uses EC PEM markers
      }
    } catch (e: IllegalArgumentException) {
      // Handle unsupported algorithm by returning generic markers or throwing an exception
      GENERIC_PRIVATE_KEY_MARKERS // You can choose to return generic markers or throw an exception
    }
  }

  /**
   * Determines the appropriate PEM markers based on the PublicKey type.
   *
   * This method checks the algorithm of the PublicKey (e.g., RSA, EC, DSA, Ed25519, Ed448, etc.)
   * and returns the correct PEM begin and end markers for the key type.
   *
   * @param publicKey The PublicKey object to determine the PEM type for.
   * @return A pair of strings representing the PEM begin and end markers for the key type.
   */
  fun getPublicKeyPemMarkers(publicKey: PublicKey): Pair<String, String> {
    require(publicKey.algorithm != "AndroidKeyStore") { "Android Keystore keys cannot be extracted into PEM." }

    return try {
      // Use the Algorithm enum to map the private key algorithm to the corresponding PEM markers
      when (CryptographicAlgorithm.fromString(publicKey.algorithm)) {
        CryptographicAlgorithm.RSA -> RSA_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.EC -> EC_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.DSA -> DSA_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.Ed25519 -> ED25519_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.Ed448 -> ED448_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.X25519 -> X25519_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.DH -> DH_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.ECDSA -> EC_PUBLIC_KEY_MARKERS // ECDSA uses EC PEM markers
      }
    } catch (e: IllegalArgumentException) {
      // Handle unsupported algorithm by returning generic markers or throwing an exception
      GENERIC_PRIVATE_KEY_MARKERS // You can choose to return generic markers or throw an exception
    }
  }

  /**
   * Extracts the PEM content from the provided string using pairs of begin and end markers.
   *
   * This method filters to extract only the required PEM content (certificates, keys, etc.)
   * from a potentially mixed PEM-formatted string. It utilizes regular expressions to find
   * the specified content based on the provided marker pairs.
   *
   * @param pem The PEM-formatted string containing various types of content.
   * @param markerPairs The list of pairs containing the begin and end markers for the required types.
   * @return A list of pairs, where each pair contains the start and end markers found,
   *         and the extracted base64-encoded content.
   * @throws IllegalArgumentException If no valid PEM content is found between the specified markers.
   *
   * Example:
   * val pemContents = extractPemContent(pemString, requiredMarkerPairs)
   */
  private fun extractPemContent(
    pem: String,
    markerPairs: List<Pair<String, String>>
  ): List<Pair<Pair<String, String>, String>> {
    // Ensure the provided PEM string is not empty
    require(pem.isNotBlank()) { "PEM cannot be empty." }
    // Ensure the list of marker pairs is not empty
    require(markerPairs.isNotEmpty()) { "Marker pairs cannot be empty." }
    // Ensure all marker pairs contain non-empty strings
    require(markerPairs.all { it.first.isNotBlank() && it.second.isNotBlank() }) { "Marker pairs cannot be empty strings." }

    // List to hold the extracted contents along with their markers
    val extractedContents = mutableListOf<Pair<Pair<String, String>, String>>()

    // Iterate through each pair of begin and end markers
    for ((begin, end) in markerPairs) {
      // Create a regex pattern to match the content between the markers
      val regexPattern = "$begin\\s*(.*?)\\s*$end".toRegex(RegexOption.DOT_MATCHES_ALL)
      val matches = regexPattern.findAll(pem) // Find all matches for the current marker pair

      // Process each match found
      for (match in matches) {
        // Get the extracted content and trim any whitespace
        val content = match.groupValues[1].trim().stripNonBase64Chars()
        if (content.isEmpty()) {
          continue
        }
        // Add the found markers and the content as a pair to the list
        extractedContents.add(Pair(Pair(begin, end), content))
      }
    }

    // Throw an exception if no content was found after processing all marker pairs
    if (extractedContents.isEmpty()) {
      throw IllegalArgumentException("No valid PEM content found between the specified markers: $markerPairs. Actual content: $pem")
    }

    // Return an immutable copy of the extracted contents list
    return extractedContents.toList()
  }

  /**
   * Converts a list of PKCS10CertificationRequest objects to a single PEM-formatted string.
   *
   * This method iterates over each CSR in the list and uses the getCsrPem method
   * to convert each request to its PEM format.
   *
   * @param csrs The list of PKCS10CertificationRequest objects to be converted.
   * @return The concatenated PEM-formatted CSRs string, with each CSR separated by newlines.
   */
  @JvmStatic
  fun getCsrsPem(csrs: List<PKCS10CertificationRequest>): String {
    val pemStringBuilder = StringBuilder()

    for (csr in csrs) {
      // Get the PEM-formatted string for each CSR
      val pem = getCsrPem(csr)
      pemStringBuilder.append(pem).append("\n") // Append each CSR's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

  /**
   * Converts a PKCS10CertificationRequest to a PEM-formatted string.
   *
   * @param csr The PKCS10CertificationRequest to be converted to PEM format.
   * @return The PEM-formatted CSR string.
   */
  fun getCsrPem(
    csr: PKCS10CertificationRequest
  ): String {
    // Create a writer for the PEM output
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)

    // Write the CSR as a PEM-formatted object
    pemWriter.writeObject(csr)

    // Close the writer and return the PEM string
    pemWriter.close()
    return writer.toString()
  }




  /**
   * Converts an X509Certificate to PEM format.
   *
   * @param certificate The X509Certificate object.
   * @return The PEM-formatted certificate string with appropriate markers based on the certificate type.
   */
  @JvmStatic
  fun getCertificatePem(certificate: X509Certificate): String {
    // Get the encoded form of the certificate
    val encoded = certificate.encoded

    // Determine the appropriate PEM markers based on the certificate type
    val (beginMarker, endMarker) = when (certificate.type) {
      "X.509" -> GENERIC_CERTIFICATE_MARKERS
      "PKCS7" -> PKCS7_MARKERS
      "TRUSTED" -> TRUSTED_CERTIFICATE_MARKERS
      "ATTRIBUTE" -> ATTRIBUTE_CERTIFICATE_MARKERS
      // Add other certificate types and their corresponding markers if necessary
      else -> GENERIC_CERTIFICATE_MARKERS // Default to generic markers if type is unknown
    }

    // Initialize a StringBuilder for the PEM string
    val pemString = StringBuilder()
    pemString.append("$beginMarker\n")

    // Convert the encoded certificate to Base64
    val base64Encoded = Base64.getEncoder().encodeToString(encoded)

    // Insert line breaks every 64 characters for formatting
    for (i in base64Encoded.indices step 64) {
      pemString.append(base64Encoded.substring(i, min(i + 64, base64Encoded.length))).append("\n")
    }

    // Append the end marker
    pemString.append("$endMarker\n")

    return pemString.toString()
  }

  /**
   * Converts a list of X509Certificates to a single PEM-formatted string.
   *
   * This method iterates over each certificate in the list and uses the
   * getCertificatePem method to convert each certificate to its PEM format.
   *
   * @param certificates The list of X509Certificate objects.
   * @return The concatenated PEM-formatted certificates string, with each certificate separated by newlines.
   */
  @JvmStatic
  fun getCertificatesPem(certificates: List<X509Certificate>): String {
    val pemStringBuilder = StringBuilder()

    for (certificate in certificates) {
      // Get the PEM-formatted string for each certificate
      val pem = getCertificatePem(certificate)
      pemStringBuilder.append(pem).append("\n") // Append each certificate's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

  /**
   * Converts a PublicKey to a PEM-formatted string.
   *
   * @param publicKey The PublicKey to be converted to PEM format.
   * @param format The format of the public key. Can be "X.509" or "OpenSSH" (default is "X.509").
   * @return The PEM-formatted public key string.
   * @throws IllegalArgumentException If the format is unsupported or if the public key format does not match the requested format.
   */
  fun getPublicKeyPem(
    publicKey: PublicKey,
    format: String = "X.509"  // Default to X.509 format
  ): String {
    // Check if the key is from the Android Keystore
    require(!publicKey.isFromAndroidKeyStore()) { "Android Keystore keys cannot be extracted into PEM." }

    // Create a writer for the PEM output
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)

    when (format) {
      "X.509" -> pemWriter.writeObject(publicKey)  // X.509 is the default format for public keys
      "OpenSSH" -> {
        require(publicKey.algorithm == "RSA" || publicKey.algorithm == "EC") {
          "OpenSSH format only supports RSA or EC keys."
        }
        pemWriter.writeObject(PEMUtils.getOpenSSHPem(publicKey))  // Handle OpenSSH format via PEMUtils
      }
      else -> throw IllegalArgumentException("Unsupported public key format: $format")
    }

    // Close the writer and return the PEM string
    pemWriter.close()
    return writer.toString()
  }

  /**
   * Converts a list of PrivateKeys to a single PEM-formatted string.
   *
   * This method iterates over each private key in the list and uses the
   * getPrivateKeyPem method to convert each key to its PEM format.
   *
   * @param privateKeys The list of PrivateKey objects to be converted.
   * @param passphrase The passphrase used to encrypt the private keys (as CharArray). If null, the keys will not be encrypted.
   * @param encryptionAlgorithm The encryption algorithm to use (default is AES-256-CBC).
   * @return The concatenated PEM-formatted private keys string, with each key separated by newlines.
   */
  @JvmStatic
  fun getPrivateKeysPem(
    privateKeys: List<PrivateKey>,
    passphrase: CharArray? = null,
    encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
    format: String = "PKCS#8"
  ): String {
    val pemStringBuilder = StringBuilder()

    for (privateKey in privateKeys) {
      // Get the PEM-formatted string for each private key
      val pem = getPrivateKeyPem(privateKey, passphrase, encryptionAlgorithm, format)
      pemStringBuilder.append(pem).append("\n") // Append each private key's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

  /**
   * Converts a PrivateKey to an encrypted or unencrypted PEM-formatted string.
   *
   * @param privateKey The PrivateKey to be converted to PEM format.
   * @param passphrase The passphrase used to encrypt the private key (as CharArray). If null, the key will not be encrypted.
   * @param encryptionAlgorithm The encryption algorithm to use (default is AES-256-CBC).
   * @param format The format of the private key. Can be "PKCS#1" or "PKCS#8" (default is PKCS#8).
   * @return The PEM-formatted private key string, encrypted if a passphrase is provided.
   * @throws IllegalArgumentException If the passphrase is empty when encryption is requested.
   */
  fun getPrivateKeyPem(
    privateKey: PrivateKey,
    passphrase: CharArray? = null,
    encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
    format: String = "PKCS#8"  // Default to PKCS#8 format
  ): String {
    // Check if the key is from the Android Keystore
    require(!privateKey.isFromAndroidKeyStore()) { "Android Keystore keys cannot be extracted into PEM." }

    // Create a writer for the PEM output
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)

    // If a passphrase is provided, encrypt the private key
    if (passphrase != null && passphrase.isNotEmpty()) {
      // Configure the encryptor with the selected encryption algorithm
      val encryptorBuilder = JceOpenSSLPKCS8EncryptorBuilder(encryptionAlgorithm.oid)
        .setPassword(passphrase)
      val encryptor: OutputEncryptor = encryptorBuilder.build()

      // Create the appropriate generator based on the format
      val generator = when (format) {
        "PKCS1", "PKCS#1" -> throw IllegalArgumentException("Encryption for PKCS#1 format is not supported.") // PKCS#1 does not support encrypted private keys
        "PKCS8", "PKCS#8" -> JcaPKCS8Generator(privateKey, encryptor)  // Use PKCS#8 generator for encryption
        else -> throw IllegalArgumentException("Unsupported format: $format")
      }

      // Write the encrypted private key
      pemWriter.writeObject(generator)
    } else {
      // If no passphrase is provided, write the unencrypted private key based on the format
      when (format) {
        "PKCS1", "PKCS#1" -> {
          require(privateKey.algorithm == "RSA") { "PKCS#1 format only supports RSA keys." }
          // Ensure the PrivateKey is a RSAPrivateCrtKey
          require(privateKey is RSAPrivateCrtKey) { "PKCS#1 format only supports RSAPrivateCrtKey keys." }
          pemWriter.writeObject(convertToPKCS1(privateKey))
        } // Convert to PKCS#1
        "PKCS8", "PKCS#8" -> pemWriter.writeObject(privateKey) // Use the default PKCS#8 format
        else -> throw IllegalArgumentException("Unsupported format: $format")
      }
    }

    // Close the writer and return the PEM string
    pemWriter.close()
    return writer.toString()
  }

  /**
   * Converts a list of PublicKeys to a single PEM-formatted string.
   *
   * This method iterates over each public key in the list and uses the
   * getPublicKeyPem method to convert each key to its PEM format.
   *
   * @param publicKeys The list of PublicKey objects to be converted.
   * @return The concatenated PEM-formatted public keys string, with each key separated by newlines.
   */
  @JvmStatic
  fun getPublicKeysPem(
    publicKeys: List<PublicKey>,
    format: String = "X.509"  // Default to X.509 format
  ): String {
    val pemStringBuilder = StringBuilder()

    for (publicKey in publicKeys) {
      // Get the PEM-formatted string for each public key
      val pem = getPublicKeyPem(publicKey, format)
      pemStringBuilder.append(pem).append("\n") // Append each public key's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

  /**
   * Parses a PEM-formatted X.509 certificate(s) and returns a list of corresponding X509Certificate objects.
   *
   * This method extracts the base64-encoded certificate content from the provided PEM string,
   * decodes it, and generates a list of X509Certificates. It can also validate the certificates'
   * expiration status based on the provided parameter.
   *
   * @param certificatePem The PEM-formatted certificate string to parse.
   * @param allowExpired A boolean indicating whether to allow expired certificates.
   *                     If false, an exception will be thrown for expired certificates.
   * @return A list of parsed X509Certificate objects.
   * @throws InvalidCertificatePemException If the PEM content is invalid or cannot be extracted.
   * @throws ExpiredCertificateException If any of the certificates has expired and expiration checking is enabled.
   * @throws UntrustedCertificateException If any certificate is not trusted based on your trust policy.
   */
  @JvmStatic
  @Throws(
    InvalidCertificatePemException::class,
    ExpiredCertificateException::class,
    UntrustedCertificateException::class
  )
  fun parseCertificatePem(
    certificatePem: String,
    allowExpired: Boolean = true
  ): List<X509Certificate> {
    // Validate that the provided certificate PEM string is not empty
    require(certificatePem.isNotBlank()) { "Certificate PEM cannot be empty." }

    // Attempt to extract PEM content using specified markers
    val pemContent = try {
      extractPemContent(certificatePem, CERTIFICATE_MARKERS)
    } catch (e: IllegalArgumentException) {
      throw InvalidCertificatePemException(
        "Failed to extract PEM content. Ensure the certificate is correctly formatted.",
        e
      )
    }

    val certificates = mutableListOf<X509Certificate>()

    // Iterate through the extracted PEM contents to parse each certificate
    for ((_, content) in pemContent) {
      try {
        // Decode the base64-encoded PEM content into a byte array
        val decoded = Base64.getDecoder().decode(content)

        // Create a CertificateFactory instance for X.509 certificates
        val certFactory = CertificateFactory.getInstance("X.509")

        // Generate the X509Certificate from the decoded byte array
        val certificate =
          certFactory.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate

        // Check for certificate validity if expiration is not allowed
        if (!allowExpired) {
          certificate.checkValidity() // This will throw an exception if the certificate is expired or not yet valid
        }

        // Add the valid certificate to the list
        certificates.add(certificate)
      } catch (e: CertificateExpiredException) {
        throw ExpiredCertificateException("Certificate has expired. Cert content: $content", e)
      } catch (e: CertificateNotYetValidException) {
        throw ExpiredCertificateException("Certificate is not yet valid. Cert content: $content", e)
      } catch (e: CertificateException) {
        throw InvalidCertificatePemException(
          "Failed to parse certificate. Cert content: $content",
          e
        )
      }
    }

    // Return the list of successfully parsed certificates
    return certificates
  }

  /**
   * Parses a PEM-formatted Certificate Signing Request (CSR) and returns all found requests.
   *
   * @param csrPem The PEM-formatted CSR string.
   * @return A list of parsed PKCS10CertificationRequest objects.
   * @throws InvalidCsrPemException If the CSR PEM is invalid or no valid CSRs are found.
   */
  @JvmStatic
  @Throws(InvalidCsrPemException::class)
  fun parseCsrPem(csrPem: String): List<PKCS10CertificationRequest> {
    require(csrPem.isNotBlank()) { "CSR PEM cannot be empty." }

    // Extract the PEM content for the CSR
    val pemContents = extractPemContent(csrPem, CSR_MARKERS)

    // Check if any PEM contents were found
    if (pemContents.isEmpty()) {
      throw InvalidCsrPemException("No valid CSR content found.")
    }

    val requests = mutableListOf<PKCS10CertificationRequest>()

    // Process each CSR content found
    for ((markers, content) in pemContents) {
      try {
        // Decode the base64-encoded content
        val decoded = Base64.getDecoder().decode(content)
        // Construct the PKCS10CertificationRequest from the decoded byte array
        requests.add(PKCS10CertificationRequest(decoded))
      } catch (e: IOException) {
        throw InvalidCsrPemException(
          "Failed to parse CSR from markers: ${markers.first} and ${markers.second}",
          e
        )
      } catch (e: PKCSException) {
        throw InvalidCsrPemException(
          "Invalid CSR format from markers: ${markers.first} and ${markers.second}",
          e
        )
      }
    }

    return requests // Return the list of all found requests
  }

  /**
   * Parses PEM-formatted private keys.
   *
   * If any of the PEMs are encrypted (i.e., they start with "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
   * a passphrase must be provided to decrypt the keys.
   *
   * @param privateKeyPem The PEM-formatted private key string, potentially containing multiple keys.
   * @param passphrase Optional passphrase used to decrypt the private keys if they are encrypted.
   *
   * @return A list of parsed `PrivateKey` objects.
   *
   * @throws InvalidPrivateKeyPemException If the private key PEM is invalid or decryption fails.
   */
  @JvmStatic
  @Throws(InvalidPrivateKeyPemException::class)
  fun parsePrivateKeyPem(privateKeyPem: String, passphrase: CharArray? = null): List<PrivateKey> {
    require(privateKeyPem.isNotBlank()) { "Private key PEM cannot be empty." }

    val privateKeys = mutableListOf<PrivateKey>()

    try {
      val reader = StringReader(privateKeyPem)
      val pemParser = PEMParser(reader)
      val converter = JcaPEMKeyConverter()
        // Must set provider here to support various key types
        .setProvider(BouncyCastleProvider())

      var obj: Any?
      while (true) {
        obj = pemParser.readObject() ?: break

        // Handle encrypted keys
        when (obj) {
          is PEMEncryptedKeyPair -> {
            if (passphrase == null) {
              throw InvalidPrivateKeyPemException("Passphrase required to decrypt the private key.")
            }
            val decryptorProvider = JcePEMDecryptorProviderBuilder().build(passphrase)
            val keyPair = obj.decryptKeyPair(decryptorProvider)
            privateKeys.add(converter.getKeyPair(keyPair).private)
          }
          // Handle unencrypted PEM keys
          is PEMKeyPair -> privateKeys.add(converter.getKeyPair(obj).private)
          is PrivateKeyInfo -> {
            try {
              privateKeys.add(converter.getPrivateKey(obj))
            } catch (e: Exception) {
              throw InvalidPrivateKeyPemException(
                "Failed to convert PrivateKeyInfo to PrivateKey: ${e.message}.",
                e
              )
            }
          }

          else -> throw InvalidPrivateKeyPemException("Unsupported key format or invalid key content.")
        }
      }
    } catch (e: Exception) {
      throw InvalidPrivateKeyPemException("Failed to parse private key: ${e.message}.", e)
    }

    return privateKeys
  }


  /**
   * Parses PEM-formatted public keys.
   *
   * @param publicKeyPem The PEM-formatted public key string, potentially containing multiple keys.
   * @return A list of parsed `PublicKey` objects.
   * @throws InvalidPublicKeyPemException If the public key PEM is invalid or cannot be parsed.
   */
  @JvmStatic
  @Throws(InvalidPublicKeyPemException::class)
  fun parsePublicKeyPem(publicKeyPem: String): List<PublicKey> {
    require(publicKeyPem.isNotBlank()) { "Public key PEM cannot be empty." }

    val publicKeys = mutableListOf<PublicKey>()

    try {
      val reader = StringReader(publicKeyPem)
      val pemParser = PEMParser(reader)
      val converter = JcaPEMKeyConverter()

      var obj: Any?
      while (true) {
        obj = pemParser.readObject() ?: break

        // Read and accumulate public key objects from the PEM
        when (obj) {
          is PEMKeyPair -> publicKeys.add(converter.getKeyPair(obj).public) // Handle PEMKeyPair (though not typical for public keys)
          is SubjectPublicKeyInfo -> publicKeys.add(converter.getPublicKey(obj)) // Handle SubjectPublicKeyInfo
          else -> throw InvalidPublicKeyPemException("Unsupported key format or invalid key content.")
        }
      }
    } catch (e: Exception) {
      throw InvalidPublicKeyPemException("Failed to parse public key.", e)
    }

    return publicKeys
  }

  /**
   * Converts a PrivateKey to the OpenSSH private key format.
   *
   * @param privateKey The PrivateKey to be converted to OpenSSH format.
   * @return The OpenSSH-formatted private key string.
   * @throws IllegalArgumentException If the key type is unsupported.
   */
  fun getOpenSSHPem(privateKey: PrivateKey): String {
    val writer = StringWriter()
    val pemWriter = PemWriter(writer)

    // Determine the type of private key and convert to OpenSSH format
    when (privateKey) {
      is RSAPrivateKey -> {
        // RSA Private Key in OpenSSH format
        val openSSHPemObject = convertRSAToOpenSSH(privateKey)
        pemWriter.writeObject(openSSHPemObject)
      }
      is ECPrivateKey -> {
        // ECDSA Private Key in OpenSSH format
        val openSSHPemObject = convertECToOpenSSH(privateKey)
        pemWriter.writeObject(openSSHPemObject)
      }
      else -> throw IllegalArgumentException("Unsupported key type: ${privateKey.algorithm}")
    }

    pemWriter.close()
    return writer.toString()
  }

  /**
   * Converts a KeyPair (both PrivateKey and PublicKey) to OpenSSH PEM format.
   *
   * @param keyPair The KeyPair to be converted to OpenSSH format.
   * @return The OpenSSH-formatted private and public key strings.
   * @throws IllegalArgumentException If the key type is unsupported.
   */
  fun getOpenSSHPem(keyPair: KeyPair): Pair<String, String> {
    val privateKeyPem = getOpenSSHPem(keyPair.private)
    val publicKeyPem = getOpenSSHPem(keyPair.public)

    return Pair(privateKeyPem, publicKeyPem)
  }

  /**
   * Converts a PublicKey to OpenSSH PEM format.
   *
   * @param publicKey The PublicKey to be converted to OpenSSH format.
   * @return The OpenSSH-formatted public key string.
   * @throws IllegalArgumentException If the key type is unsupported.
   */
  fun getOpenSSHPem(publicKey: PublicKey): String {
    val writer = StringWriter()
    val pemWriter = PemWriter(writer)

    when (publicKey) {
      is RSAPublicKey -> {
        val openSSHPemObject = convertRSAToOpenSSH(publicKey)
        pemWriter.writeObject(openSSHPemObject)
      }
      is ECPublicKey -> {
        val openSSHPemObject = convertECToOpenSSH(publicKey)
        pemWriter.writeObject(openSSHPemObject)
      }
      else -> throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
    }

    pemWriter.close()
    return writer.toString()
  }

  /**
   * Converts an RSAPublicKey to an OpenSSH PemObject.
   *
   * OpenSSH public keys are typically represented in a single-line format with the key type
   * and base64-encoded key data. This function converts the given RSAPublicKey into the OpenSSH format.
   *
   * @param publicKey The RSAPublicKey to be converted.
   * @return A PemObject representing the OpenSSH public key.
   */
  private fun convertRSAToOpenSSH(publicKey: RSAPublicKey): PemObject {
    // Retrieve the public key's encoded byte array in X.509 format
    // You may need to perform additional encoding or base64 processing here
    val rsaPublicKeyBytes = publicKey.encoded

    // Create a PemObject with the "OPENSSH PUBLIC KEY" label and the public key bytes
    return PemObject("OPENSSH PUBLIC KEY", rsaPublicKeyBytes)
  }

  /**
   * Converts an RSAPrivateKey to an OpenSSH PemObject.
   *
   * OpenSSH private keys are stored in a PEM format with the label "OPENSSH PRIVATE KEY".
   * This function converts the RSAPrivateKey into this format.
   *
   * @param privateKey The RSAPrivateKey to be converted.
   * @return A PemObject representing the OpenSSH private key.
   */
  private fun convertRSAToOpenSSH(privateKey: RSAPrivateKey): PemObject {
    // Retrieve the private key's encoded byte array in PKCS#8 format
    // OpenSSH may require additional processing for compatibility with its format
    val rsaPrivateKeyBytes = privateKey.encoded

    // Create a PemObject with the "OPENSSH PRIVATE KEY" label and the private key bytes
    return PemObject("OPENSSH PRIVATE KEY", rsaPrivateKeyBytes)
  }

  /**
   * Converts an ECPrivateKey to an OpenSSH PemObject.
   *
   * @param privateKey The ECPrivateKey to be converted.
   * @return A PemObject representing the OpenSSH private key.
   */
  private fun convertECToOpenSSH(privateKey: ECPrivateKey): PemObject {
    // Your conversion logic to create the OpenSSH formatted EC key
    val ecKeyBytes = privateKey.encoded // You may need custom encoding for OpenSSH format
    return PemObject("OPENSSH PRIVATE KEY", ecKeyBytes)
  }

  /**
   * Converts an ECPublicKey to an OpenSSH PemObject.
   *
   * OpenSSH public keys for elliptic curve cryptography (ECDSA) are represented in a single-line format
   * with the key type and base64-encoded key data. This function converts the ECPublicKey into the OpenSSH format.
   *
   * @param publicKey The ECPublicKey to be converted.
   * @return A PemObject representing the OpenSSH public key.
   */
  private fun convertECToOpenSSH(publicKey: ECPublicKey): PemObject {
    // Retrieve the public key's encoded byte array in X.509 format
    // You may need custom encoding for OpenSSH format, typically OpenSSH public keys are base64-encoded
    val ecPublicKeyBytes = publicKey.encoded

    // Create a PemObject with the "OPENSSH PUBLIC KEY" label and the public key bytes
    return PemObject("OPENSSH PUBLIC KEY", ecPublicKeyBytes)
  }

  /**
   * Converts an RSAPrivateKey to PKCS#1 format.
   *
   * @param privateKey The RSAPrivateCrtKey to be converted.
   * @return A string containing the PKCS#1-formatted private key in PEM format.
   */
  fun convertToPKCS1(privateKey: RSAPrivateCrtKey): String {
    // Create the ASN.1 structure for PKCS#1 from the private key's components
    val rsaPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey(
      privateKey.modulus,                // n
      privateKey.publicExponent,         // e (public exponent)
      privateKey.privateExponent,        // d (private exponent)
      privateKey.primeP,                 // p (prime 1)
      privateKey.primeQ,                 // q (prime 2)
      privateKey.primeExponentP,         // d mod (p-1) (exponent1)
      privateKey.primeExponentQ,         // d mod (q-1) (exponent2)
      privateKey.crtCoefficient          // (inverse of q) mod p (coefficient)
    )

    // Serialize the ASN.1 structure to PEM format using JcaPEMWriter
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)
    pemWriter.writeObject(rsaPrivateKey)
    pemWriter.close()

    return writer.toString()
  }
}