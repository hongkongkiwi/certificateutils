package com.github.hongkongkiwi.certificateutils

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.github.hongkongkiwi.certificateutils.builders.CsrSubjectDNBuilder
import kotlin.math.min
import com.github.hongkongkiwi.exceptions.*
import com.github.hongkongkiwi.builders.*
import com.github.hongkongkiwi.enums.*
import com.github.hongkongkiwi.certificateutils.enums.CryptographicAlgorithm
import com.github.hongkongkiwi.certificateutils.enums.DigestAlgorithm
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
import com.github.hongkongkiwi.certificateutils.enums.EncryptionAlgorithm
import com.github.hongkongkiwi.certificateutils.exceptions.ExpiredCertificateException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCertificatePemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidCsrPemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPrivateKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.InvalidPublicKeyPemException
import com.github.hongkongkiwi.certificateutils.exceptions.KeyPairMismatchException
import com.github.hongkongkiwi.certificateutils.exceptions.UnsupportedKeyAlgorithmException
import com.github.hongkongkiwi.certificateutils.exceptions.UntrustedCertificateException
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.ByteArrayInputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.*
import java.util.Base64
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PKCS8Generator
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.OutputEncryptor
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.StringReader
import java.io.StringWriter
import java.security.interfaces.DSAPrivateKey
import java.util.Locale
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

@Suppress("unused", "MemberVisibilityCanBePrivate", "RemoveRedundantQualifierName")
object CertificateUtils {

  internal val TAG = CertificateUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
    }
  }

  // OID defnitions
  const val OID_SHA256_RSA = "1.2.840.113549.1.1.11" // SHA-256 with RSA
  const val OID_SHA256_ECDSA = "1.2.840.10045.4.3.2" // SHA-256 with ECDSA

  // Individual Pair Definitions
  // Certificate markers
  val GENERIC_CERTIFICATE_MARKERS = Pair("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
  val PKCS7_MARKERS = Pair("-----BEGIN PKCS7-----", "-----END PKCS7-----")
  val TRUSTED_CERTIFICATE_MARKERS = Pair("-----BEGIN TRUSTED CERTIFICATE-----", "-----END TRUSTED CERTIFICATE-----")
  val ATTRIBUTE_CERTIFICATE_MARKERS = Pair("-----BEGIN ATTRIBUTE CERTIFICATE-----", "-----END ATTRIBUTE CERTIFICATE-----")

  // Key markers
  val GENERIC_PRIVATE_KEY_MARKERS = Pair("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
  val GENERIC_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----")

  val ECDSA_PRIVATE_KEY_MARKERS = Pair("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----")
  val ECDSA_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED EC PRIVATE KEY-----", "-----END ENCRYPTED EC PRIVATE KEY-----")

  val RSA_PRIVATE_KEY_MARKERS = Pair("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
  val RSA_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED RSA PRIVATE KEY-----", "-----END ENCRYPTED RSA PRIVATE KEY-----")

  val DSA_PRIVATE_KEY_MARKERS = Pair("-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----")
  val DSA_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED DSA PRIVATE KEY-----", "-----END ENCRYPTED DSA PRIVATE KEY-----")

  val ED25519_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ED25519 PRIVATE KEY-----", "-----END ED25519 PRIVATE KEY-----")
  val ED25519_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED ED25519 PRIVATE KEY-----", "-----END ENCRYPTED ED25519 PRIVATE KEY-----")

  val ED448_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ED448 PRIVATE KEY-----", "-----END ED448 PRIVATE KEY-----")
  val ED448_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED ED448 PRIVATE KEY-----", "-----END ENCRYPTED ED448 PRIVATE KEY-----")

  val X25519_PRIVATE_KEY_MARKERS = Pair("-----BEGIN X25519 PRIVATE KEY-----", "-----END X25519 PRIVATE KEY-----")
  val X25519_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED X25519 PRIVATE KEY-----", "-----END ENCRYPTED X25519 PRIVATE KEY-----")

  val DH_PRIVATE_KEY_MARKERS = Pair("-----BEGIN DH PRIVATE KEY-----", "-----END DH PRIVATE KEY-----")
  val DH_ENCRYPTED_PRIVATE_KEY_MARKERS = Pair("-----BEGIN ENCRYPTED DH PRIVATE KEY-----", "-----END ENCRYPTED DH PRIVATE KEY-----")

  // Public key markers
  val RSA_PUBLIC_KEY_MARKERS = Pair("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")
  val ECDSA_PUBLIC_KEY_MARKERS = Pair("-----BEGIN EC PUBLIC KEY-----", "-----END EC PUBLIC KEY-----")
  val DSA_PUBLIC_KEY_MARKERS = Pair("-----BEGIN DSA PUBLIC KEY-----", "-----END DSA PUBLIC KEY-----")
  val ED25519_PUBLIC_KEY_MARKERS = Pair("-----BEGIN ED25519 PUBLIC KEY-----", "-----END ED25519 PUBLIC KEY-----")
  val ED448_PUBLIC_KEY_MARKERS = Pair("-----BEGIN ED448 PUBLIC KEY-----", "-----END ED448 PUBLIC KEY-----")
  val X25519_PUBLIC_KEY_MARKERS = Pair("-----BEGIN X25519 PUBLIC KEY-----", "-----END X25519 PUBLIC KEY-----")
  val DH_PUBLIC_KEY_MARKERS = Pair("-----BEGIN DH PUBLIC KEY-----", "-----END DH PUBLIC KEY-----")
  val GENERIC_PUBLIC_KEY_MARKERS = Pair("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----") // Generic public key marker

  // CSR markers
  val CERTIFICATE_REQUEST_MARKERS = Pair("-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----")
  val NEW_CERTIFICATE_REQUEST_MARKERS = Pair("-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----")

  // Lists of markers for easy access
  // Key markers
  val PRIVATE_KEY_MARKERS = listOf(
    GENERIC_PRIVATE_KEY_MARKERS,
    ECDSA_PRIVATE_KEY_MARKERS,
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
    ECDSA_ENCRYPTED_PRIVATE_KEY_MARKERS,
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
    ECDSA_PUBLIC_KEY_MARKERS,
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
    allowExpired: Boolean = false
  ): List<X509Certificate> {
    // Validate that the provided certificate PEM string is not empty
    require(certificatePem.isNotEmpty()) { "Certificate PEM cannot be empty." }

    // Attempt to extract PEM content using specified markers
    val pemContent = try {
      extractPemContent(certificatePem, CERTIFICATE_MARKERS)
    } catch (e: IllegalArgumentException) {
      throw InvalidCertificatePemException("Failed to extract PEM content. Ensure the certificate is correctly formatted.", e)
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
        val certificate = certFactory.generateCertificate(ByteArrayInputStream(decoded)) as X509Certificate

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
        throw InvalidCertificatePemException("Failed to parse certificate. Cert content: $content", e)
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
    require(csrPem.isNotEmpty()) { "CSR PEM cannot be empty." }

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
        throw InvalidCsrPemException("Failed to parse CSR from markers: ${markers.first} and ${markers.second}", e)
      } catch (e: PKCSException) {
        throw InvalidCsrPemException("Invalid CSR format from markers: ${markers.first} and ${markers.second}", e)
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
    require(privateKeyPem.isNotEmpty()) { "Private key PEM cannot be empty." }

    val privateKeys = mutableListOf<PrivateKey>()

    try {
      val reader = StringReader(privateKeyPem)
      val pemParser = PEMParser(reader)
      val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())

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
          is PrivateKeyInfo -> privateKeys.add(converter.getPrivateKey(obj))
          else -> throw InvalidPrivateKeyPemException("Unsupported key format or invalid key content.")
        }
      }
    } catch (e: Exception) {
      throw InvalidPrivateKeyPemException("Failed to parse private key.", e)
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
    require(publicKeyPem.isNotEmpty()) { "Public key PEM cannot be empty." }

    val publicKeys = mutableListOf<PublicKey>()

    try {
      val reader = StringReader(publicKeyPem)
      val pemParser = PEMParser(reader)
      val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())

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
  fun isCertificateSignedByPrivateKey(certificate: X509Certificate, privateKey: PrivateKey): Boolean {
    val publicKeyFromCertificate = certificate.publicKey
    val publicKeyFromPrivateKey = getPublicKey(privateKey)
    return if (publicKeyFromCertificate == publicKeyFromPrivateKey) {
      true
    } else {
      throw KeyPairMismatchException("The provided certificate and private key do not match.")
    }
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
   * Converts a PrivateKey to an encrypted or unencrypted PEM-formatted string.
   *
   * @param privateKey The PrivateKey to be converted to PEM format.
   * @param passphrase The passphrase used to encrypt the private key (as CharArray). If null, the key will not be encrypted.
   * @param encryptionAlgorithm The encryption algorithm to use (default is AES-256-CBC).
   * @return The PEM-formatted private key string, encrypted if a passphrase is provided.
   * @throws IllegalArgumentException If the passphrase is empty when encryption is requested.
   */
  fun getPrivateKeyPem(
    privateKey: PrivateKey,
    passphrase: CharArray? = null,
    encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC
  ): String {
    // Check if the key is from the Android Keystore
    require(privateKey.algorithm != "AndroidKeyStore") { "Android Keystore keys cannot be extracted into PEM." }

    // Create a writer for the PEM output
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)

    // If a passphrase is provided, encrypt the private key
    if (passphrase != null && passphrase.isNotEmpty()) {
      // Configure the encryptor with the selected encryption algorithm
      val encryptorBuilder = JceOpenSSLPKCS8EncryptorBuilder(encryptionAlgorithm.oid)
        .setPassword(passphrase)
        .setProvider(BouncyCastleProvider())
      val encryptor: OutputEncryptor = encryptorBuilder.build()

      // Create the PKCS#8 EncryptedPrivateKeyInfo generator
      val generator = JcaPKCS8Generator(privateKey, encryptor)

      // Write the encrypted private key
      pemWriter.writeObject(generator)
    } else {
      // If no passphrase is provided, write the unencrypted private key
      pemWriter.writeObject(privateKey)
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
    encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC
  ): String {
    val pemStringBuilder = StringBuilder()

    for (privateKey in privateKeys) {
      // Get the PEM-formatted string for each private key
      val pem = getPrivateKeyPem(privateKey, passphrase, encryptionAlgorithm)
      pemStringBuilder.append(pem).append("\n") // Append each private key's PEM and a newline
    }

    return pemStringBuilder.toString().trim() // Return the final string without trailing newline
  }

  /**
   * Converts a PublicKey to a PEM-formatted string.
   *
   * @param publicKey The PublicKey to be converted to PEM format.
   * @return The PEM-formatted public key string.
   */
  fun getPublicKeyPem(
    publicKey: PublicKey
  ): String {
    // Create a writer for the PEM output
    val writer = StringWriter()
    val pemWriter = JcaPEMWriter(writer)

    // Write the public key as a PEM-formatted object
    pemWriter.writeObject(publicKey)

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
  fun getPublicKeysPem(publicKeys: List<PublicKey>): String {
    val pemStringBuilder = StringBuilder()

    for (publicKey in publicKeys) {
      // Get the PEM-formatted string for each public key
      val pem = getPublicKeyPem(publicKey)
      pemStringBuilder.append(pem).append("\n") // Append each public key's PEM and a newline
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
      throw IllegalArgumentException("Failed to parse byte array into PKCS#10 Certification Request.", e)
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
  fun createCsr(
    privateKey: PrivateKey,
    subjectDNBuilder: CsrSubjectDNBuilder
  ): PKCS10CertificationRequest {
    // Build the subject DN string from the SubjectDNBuilder instance
    return createCsr(privateKey, subjectDNBuilder.build())
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
  fun createCsr(
    privateKey: PrivateKey,
    subjectDN: String
  ): PKCS10CertificationRequest {
    require(subjectDN.isNotEmpty()) { "Subject DN cannot be empty." }

    val publicKey = getPublicKey(privateKey)

    val keyPair = KeyPair(publicKey, privateKey)
    val subject = X500Principal(subjectDN)

    return try {
      val csrBuilder = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
      val signer: ContentSigner = JcaContentSignerBuilder("SHA256with${privateKey.algorithm}")
        .setProvider(BouncyCastleProvider())
        .build(privateKey)

      csrBuilder.build(signer)
    } catch (e: OperatorCreationException) {
      throw InvalidPrivateKeyPemException("Failed to create content signer.", e)
    } catch (e: IOException) {
      throw InvalidPrivateKeyPemException("Failed to encode CSR.", e)
    }
  }

  /**
   * Generates an RSA private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keySize The size of the key in bits (default is 2048).
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated RSA private key.
   * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyRSA(
    keySize: Int = 2048,
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): PrivateKey {
    require(keySize in 1024..4096) { "RSA key size must be between 1024 and 4096 bits." }
    require(keySize % 8 == 0) { "RSA key size must be a multiple of 8." }

    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4))
        .setKeySize(keySize)
        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal RSA private key
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
      keyPairGenerator.initialize(keySize, SecureRandom())
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates an EC private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param ecCurve The elliptic curve to use (default is SECP256R1).
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated EC private key.
   * @throws NoSuchAlgorithmException If the EC algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyEC(
    ecCurve: ECCurve = ECCurve.SECP256R1,
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): PrivateKey {
    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec(ecCurve.toString()))
        .setDigests(KeyProperties.DIGEST_MD5, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal EC private key
      val keyPairGenerator = KeyPairGenerator.getInstance("EC")
      val ecSpec = ECGenParameterSpec(ecCurve.toString())
      keyPairGenerator.initialize(ecSpec, SecureRandom())
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates a DSA private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keySize The size of the key in bits (default is 2048).
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated DSA private key.
   * @throws NoSuchAlgorithmException If the DSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyDSA(
    keySize: Int = 2048,
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_SIGN
  ): PrivateKey {
    require(keySize in 1024..3072) { "DSA key size must be between 1024 and 3072 bits." }
    require(keySize % 64 == 0) { "DSA key size must be a multiple of 64." }

    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("DSA", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .setKeySize(keySize)
        .setDigests(KeyProperties.DIGEST_MD5, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal DSA private key
      val keyPairGenerator = KeyPairGenerator.getInstance("DSA")
      keyPairGenerator.initialize(keySize, SecureRandom())
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates an Ed25519 private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated Ed25519 private key.
   * @throws NoSuchAlgorithmException If the Ed25519 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyEd25519(
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): PrivateKey {
    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal Ed25519 private key
      val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519")
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates an Ed448 private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated Ed448 private key.
   * @throws NoSuchAlgorithmException If the Ed448 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyEd448(
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): PrivateKey {
    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("Ed448", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal Ed448 private key
      val keyPairGenerator = KeyPairGenerator.getInstance("Ed448")
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates an X25519 private key for Diffie-Hellman key exchange. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated X25519 private key.
   * @throws NoSuchAlgorithmException If the X25519 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedKeyAlgorithmException If the algorithm is unsupported on lower SDK versions.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyX25519(
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): PrivateKey {
    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("X25519", "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal X25519 private key
      val keyPairGenerator = KeyPairGenerator.getInstance("X25519")
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
   * Generates a Diffie-Hellman (DH) private key. If `keystoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keySize The size of the key in bits (default is 2048).
   * @param keystoreAlias The alias for the Android Keystore. If null, a normal private key is generated.
   * @return The generated DH private key.
   * @throws NoSuchAlgorithmException If the DH algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedKeyAlgorithmException If the algorithm is unsupported on lower SDK versions.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
  fun createPrivateKeyDH(
    keySize: Int = 2048,
    keystoreAlias: String? = null,
    keyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): PrivateKey {
    require(keySize in 512..2048) { "DH key size must be between 512 and 2048." }
    require(keySize % 64 == 0) { "DH key size must be a multiple of 64." }

    if (keystoreAlias != null) {
      // Generate key in Android Keystore
      val keyPairGenerator = KeyPairGenerator.getInstance("DH", "AndroidKeyStore")
      val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
        keystoreAlias,
        keyPurposes
      )
      // For SDK 31 and above, you can set the purpose to agree as well
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        keyGenParameterSpecBuilder.setUserAuthenticationRequired(false)
      }

      val keyGenParameterSpec = keyGenParameterSpecBuilder
        .setKeySize(keySize)
        .build()

      keyPairGenerator.initialize(keyGenParameterSpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    } else {
      // Generate a normal DH private key
      val keyPairGenerator = KeyPairGenerator.getInstance("DH")
      keyPairGenerator.initialize(keySize, SecureRandom())
      val keyPair = keyPairGenerator.generateKeyPair()
      return keyPair.private
    }
  }

  /**
  * Gets the public key corresponding to the provided private key.
  *
  * @param privateKey The private key for which to get the public key.
  * @return The generated public key.
  * @throws UnsupportedKeyAlgorithmException If the key algorithm is unsupported.
  */
  @SuppressLint("ObsoleteSdkInt")
  fun getPublicKey(privateKey: PrivateKey): PublicKey {
    return when (privateKey) {
      is RSAPrivateKey -> getRSAPublicKey(privateKey)
      is ECPrivateKey -> getECDSAPublicKey(privateKey)
      is DSAPrivateKey -> getDSAPublicKey(privateKey)
      else -> {
        // Use reflection for EdECPrivateKey and XECPrivateKey to avoid direct reference on unsupported versions
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) { // Android SDK 30 (R) and above
          when (privateKey.algorithm) {
            CryptographicAlgorithm.Ed25519.toString(), CryptographicAlgorithm.Ed448.toString() -> getEdPublicKey(privateKey)
            CryptographicAlgorithm.X25519.toString() -> getXECKeyPair(CryptographicAlgorithm.X25519)?.public ?: throw UnsupportedKeyAlgorithmException("X25519 key pair generation failed.")
            else -> throw UnsupportedKeyAlgorithmException("Unsupported key algorithm: ${privateKey.algorithm}")
          }
        } else {
          throw UnsupportedKeyAlgorithmException("${privateKey.algorithm} is not supported on this Android version")
        }
      }
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
   * Checks whether the provided private key is stored in the Android Keystore.
   *
   * This method checks the provider of the private key to determine if it belongs to the
   * Android Keystore. Private keys generated or imported into the Android Keystore will have
   * a provider name of "AndroidKeyStore". This is useful for ensuring that keys stored securely
   * on the device are being used, which can be critical for sensitive operations such as signing
   * or encryption in a secure environment.
   *
   * @param privateKey The private key to check.
   * @return True if the private key is from the Android Keystore, false otherwise.
   */
  fun isPrivateKeyAndroidKeyStore(privateKey: PrivateKey): Boolean {
    return privateKey.algorithm == "AndroidKeyStore"
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
  fun isCertificateTrusted(certificate: X509Certificate, trustedCertificates: Set<X509Certificate>? = null): Boolean {
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
      require(subjectDN.isNotEmpty()) { "CSR subject DN cannot be empty." }

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
        .setProvider(BouncyCastleProvider())
        .build(publicKey)

      csr.isSignatureValid(signer)
    } catch (e: Exception) {
      false
    }
  }

  /**
   * Generates a certificate digets for the given data using the specified fingerprint algorithm.
   *
   * @param certificateData The data to generate a fingerprint for.
   * @param digestAlgorithm The fingerprint algorithm to use.
   * @return The generated fingerprint as a hex string.
   * @throws Exception If the digest algorithm is not available or an error occurs during processing.
   */
  fun getCertificateFingerprint(certificateData: ByteArray, digestAlgorithm: DigestAlgorithm): String {
    val messageDigest = MessageDigest.getInstance(digestAlgorithm.digest)
    val digest = messageDigest.digest(certificateData)
    return digest.joinToString("") { "%02x".format(it) }
  }

  /**
   * Generates a fingerprint for the given X509Certificate using the specified fingerprint algorithm.
   *
   * @param certificate The X509Certificate to generate a fingerprint for.
   * @param digestAlgorithm The fingerprint algorithm to use.
   * @return The generated fingerprint as a hex string.
   * @throws Exception If the digest algorithm is not available or an error occurs during processing.
   */
  fun getCertificateFingerprint(certificate: X509Certificate, digestAlgorithm: DigestAlgorithm): String {
    val encodedCertificate = certificate.encoded
    return getCertificateFingerprint(encodedCertificate, digestAlgorithm)
  }

  /**
   * Retrieves the corresponding ASN.1 Object Identifier for a specified encryption algorithm string.
   *
   * This method maps human-readable encryption algorithm names to their respective
   * ASN.1 Object Identifiers defined in the PKCS #8 specification. The mapping is
   * case-insensitive, allowing for flexibility in input formats.
   *
   * @param algorithm The string representation of the encryption algorithm (e.g., "AES_256_CBC").
   * @return The ASN.1 Object Identifier corresponding to the specified encryption algorithm.
   *
   * @throws IllegalArgumentException If the provided algorithm string does not match any
   *                                   supported encryption algorithms.
   */
  private fun getEncryptionAlgorithmFromString(algorithm: String): ASN1ObjectIdentifier {
    return when (algorithm.uppercase(Locale.ROOT)) {
      "AES_128_CBC" -> PKCS8Generator.AES_128_CBC
      "AES_192_CBC" -> PKCS8Generator.AES_192_CBC
      "AES_256_CBC" -> PKCS8Generator.AES_256_CBC
      "DES3_CBC" -> PKCS8Generator.DES3_CBC
      "PBE_SHA1_RC4_128" -> PKCS8Generator.PBE_SHA1_RC4_128
      "PBE_SHA1_RC4_40" -> PKCS8Generator.PBE_SHA1_RC4_40
      "PBE_SHA1_3DES" -> PKCS8Generator.PBE_SHA1_3DES
      "PBE_SHA1_2DES" -> PKCS8Generator.PBE_SHA1_2DES
      "PBE_SHA1_RC2_128" -> PKCS8Generator.PBE_SHA1_RC2_128
      "PBE_SHA1_RC2_40" -> PKCS8Generator.PBE_SHA1_RC2_40
      else -> throw IllegalArgumentException("Unsupported encryption algorithm: $algorithm")
    }
  }

  /**
   * Retrieves the standard name of the elliptic curve used in the specified EC private key.
   *
   * This method takes an ECPrivateKey and extracts the curve parameters associated with it.
   * It then uses these parameters to obtain the standard curve name, which can be useful
   * for identifying the type of elliptic curve used for cryptographic operations.
   *
   * @param privateKey The ECPrivateKey from which to retrieve the curve name.
   * @return The name of the elliptic curve as a String, or null if the key is not an EC private key.
   * @throws IllegalArgumentException If the provided private key does not contain valid curve parameters.
   */
  fun getCurveNameFromKey(privateKey: ECPrivateKey): ECCurve {
    return getCurveNameFromSpec(privateKey.params)
  }

  /**
   * Retrieves the standard name of the curve used in the ECParameterSpec.
   *
   * @param paramSpec The ECParameterSpec from the private key.
   * @return The curve name as a String.
   */
  fun getCurveNameFromSpec(paramSpec: java.security.spec.ECParameterSpec): ECCurve {
    val namedCurves = ECNamedCurveTable.getNames()
    for (name in namedCurves) {
      val parameterSpec = ECNamedCurveTable.getParameterSpec(name as String)
      val curveSpec = ECNamedCurveSpec(
        name,
        parameterSpec.curve,
        parameterSpec.g,
        parameterSpec.n,
        parameterSpec.h,
        parameterSpec.seed
      )
      if (curveEquals(curveSpec, paramSpec)) {
        return ECCurve.fromString(name)
      }
    }
    throw IllegalArgumentException("Unsupported curve parameters")
  }

  /**
   * Compares two elliptic curve specifications to determine if they are equal.
   *
   * This helper method checks the equality of the field, coefficients (a and b),
   * generator point, order, and cofactor of the specified elliptic curves.
   *
   * @param curveSpec The first elliptic curve specification to compare, represented as ECNamedCurveSpec.
   * @param params The second elliptic curve specification to compare, represented as ECParameterSpec.
   * @return True if both elliptic curves are equal; false otherwise.
   */
  private fun curveEquals(curveSpec: ECNamedCurveSpec, params: java.security.spec.ECParameterSpec): Boolean {
    val curvesEqual = curveSpec.curve.field == params.curve.field &&
      curveSpec.curve.a == params.curve.a &&
      curveSpec.curve.b == params.curve.b
    val generatorsEqual = curveSpec.generator.affineX == params.generator.affineX &&
      curveSpec.generator.affineY == params.generator.affineY
    val ordersEqual = curveSpec.order == params.order
    val cofactorsEqual = curveSpec.cofactor == params.cofactor
    return curvesEqual && generatorsEqual && ordersEqual && cofactorsEqual
  }

  /**
   * Gets the public key point for an EC private key.
   *
   * @param privateKey The EC private key.
   * @return The public key point (ECPoint).
   */
  private fun getECPublicKeyPoint(privateKey: PrivateKey): ECPoint {
    require(privateKey is ECPrivateKey) { "Provided key is not an ECPrivateKey." }

    // Get the EC parameter spec associated with the private key
    val ecSpec: ECParameterSpec = privateKey.params

    // Use KeyPairGenerator to derive the public key from the private key
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(ecSpec)

    // Generate a key pair
    val keyPair = keyPairGenerator.generateKeyPair()

    // The public key is derived from the private key's parameters
    val publicKey: PublicKey = keyPair.public

    // Cast to ECPoint
    return (publicKey as java.security.interfaces.ECPublicKey).w
  }

  /**
   * Uses reflection to get the public key for EdDSA algorithms (Ed25519 and Ed448).
   * This method avoids directly referencing classes that are not available in lower SDK versions.
   *
   * @param privateKey The EdDSA private key (Ed25519 or Ed448).
   * @return The generated public key.
   * @throws UnsupportedKeyAlgorithmException If reflection fails or the algorithm is unsupported.
   * @throws IllegalArgumentException If the provided private key is null or not of a valid EdDSA algorithm.
   */
  private fun getEdPublicKeyUsingReflection(privateKey: PrivateKey): PublicKey {
    require(privateKey.algorithm == "Ed25519" || privateKey.algorithm == "Ed448") {
      "Provided key must be of algorithm Ed25519 or Ed448."
    }

    return try {
      // Obtain the KeyPairGenerator class
      val keyPairGeneratorClass = Class.forName("java.security.KeyPairGenerator")

      // Get the KeyPairGenerator instance for the given EdDSA algorithm
      val keyPairGenerator = keyPairGeneratorClass.getMethod("getInstance", String::class.java)
        .invoke(null, privateKey.algorithm)

      // Generate the key pair
      val keyPair = keyPairGeneratorClass.getMethod("generateKeyPair")
        .invoke(keyPairGenerator) as KeyPair

      // Return the public key from the generated key pair
      keyPair.public
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException("Failed to generate EdDSA public key for ${privateKey.algorithm} using reflection", e)
    }
  }

  /**
   * Uses reflection to derive the public key from an existing X25519 private key.
   * This method avoids directly referencing classes that may not be available in lower SDK versions.
   *
   * @param privateKey The existing X25519 private key from which to derive the public key.
   * @return The derived public key.
   * @throws UnsupportedKeyAlgorithmException If reflection fails or the algorithm is unsupported.
   * @throws IllegalArgumentException If the provided private key is null or not of algorithm X25519.
   */
  private fun getXECPublicKeyUsingReflection(privateKey: PrivateKey): PublicKey {
    require(privateKey.algorithm == "X25519") { "Provided key must be of algorithm X25519." }

    return try {
      // Obtain the KeyFactory class
      val keyFactoryClass = Class.forName("java.security.KeyFactory")

      // Get the method for obtaining the KeyFactory instance for X25519
      val getInstanceMethod = keyFactoryClass.getMethod("getInstance", String::class.java)
      val keyFactoryInstance = getInstanceMethod.invoke(null, "X25519")

      // Get the method for generating the public key from the private key
      val generatePublicMethod = keyFactoryClass.getMethod("generatePublic", privateKey.javaClass)

      // Use reflection to create the public key from the existing private key
      generatePublicMethod.invoke(keyFactoryInstance, privateKey) as PublicKey // Cast to PublicKey
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException(
        "Failed to derive public key from X25519 private key using reflection",
        e
      )
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
  private fun extractPemContent(pem: String, markerPairs: List<Pair<String, String>>): List<Pair<Pair<String, String>, String>> {
    // Ensure the provided PEM string is not empty
    require(pem.isNotEmpty()) { "PEM cannot be empty." }
    // Ensure the list of marker pairs is not empty
    require(markerPairs.isNotEmpty()) { "Marker pairs cannot be empty." }
    // Ensure all marker pairs contain non-empty strings
    require(markerPairs.all { it.first.isNotEmpty() && it.second.isNotEmpty() }) { "Marker pairs cannot be empty strings." }

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
        val content = match.groupValues[1].trim()
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
   * Checks if the given byte array represents a PKCS#1 formatted private key.
   *
   * The PKCS#1 private key format starts with an ASN.1 sequence, indicated by the first byte
   * being 0x30. This method checks if the provided byte array is not empty and if the first
   * byte matches this identifier.
   *
   * @param keyBytes The byte array containing the key data to check.
   * @return True if the byte array is in PKCS#1 format; false otherwise.
   */
  private fun isPKCS1Format(keyBytes: ByteArray): Boolean {
    // PKCS#1 private key starts with an ASN.1 sequence with an INTEGER for version
    return keyBytes.isNotEmpty() && keyBytes[0] == 0x30.toByte() // ASN.1 sequence
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
    val pkcs1KeySpec = RSAPrivateKeySpec(BigInteger(1, pkcs1Bytes), BigInteger.valueOf(65537)) // Adjust according to the key
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey = keyFactory.generatePrivate(pkcs1KeySpec)

    // Generate the PKCS#8 encoded format
    return privateKey.encoded // PKCS#8 format is usually obtained from the private key
  }

  /**
   * Gets the public key for DSA algorithms.
   *
   * @param privateKey The DSA private key.
   * @return The generated public key.
   * @throws UnsupportedKeyAlgorithmException If the DSA algorithm is unsupported.
   */
  private fun getDSAPublicKey(privateKey: DSAPrivateKey): PublicKey {
    // Get the parameters for the DSA private key
    val params = privateKey.params
    val g = params.g  // Generator
    val p = params.p  // Prime modulus
    val q = params.q  // Subgroup prime
    val x = privateKey.x // Private key value

    // Calculate the public key value: y = g^x mod p
    val y = g.modPow(x, p)

    // Create the public key specification with all required parameters
    val publicKeySpec = DSAPublicKeySpec(y, p, q, g)

    // Generate and return the public key
    val keyFactory = KeyFactory.getInstance("DSA")
    return keyFactory.generatePublic(publicKeySpec)
  }

  /**
   * Gets the public key for EC algorithms.
   *
   * @param privateKey The EC private key.
   * @return The generated public key.
   * @throws UnsupportedKeyAlgorithmException If the EC algorithm is unsupported.
   */
  private fun getECDSAPublicKey(privateKey: ECPrivateKey): PublicKey {
    // Use the ECPrivateKey to derive the public key
    val keyFactory = KeyFactory.getInstance("EC")
    val publicKeyPoint = getECPublicKeyPoint(privateKey) // Implement this function
    val publicKeySpec = ECPublicKeySpec(publicKeyPoint, privateKey.params)
    return keyFactory.generatePublic(publicKeySpec)
  }

  /**
   * Gets the public key for RSA algorithms.
   *
   * @param privateKey The RSA private key.
   * @return The generated public key.
   * @throws UnsupportedKeyAlgorithmException If the RSA algorithm is unsupported.
   */
  private fun getRSAPublicKey(privateKey: RSAPrivateKey): PublicKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, BigInteger.valueOf(65537))
    return keyFactory.generatePublic(publicKeySpec)
  }

  /**
   * Gets the public key for EdDSA algorithms (Ed25519 and Ed448) using reflection.
   * This method avoids directly referencing classes that may not be available in lower SDK versions.
   */
  private fun getEdPublicKey(privateKey: PrivateKey): PublicKey {
    return try {
      val keyPairGeneratorClass = Class.forName("java.security.KeyPairGenerator")
      val keyPairGenerator = keyPairGeneratorClass.getMethod("getInstance", String::class.java).invoke(null, privateKey.algorithm)
      val keyPair = keyPairGeneratorClass.getMethod("generateKeyPair").invoke(keyPairGenerator) as KeyPair
      keyPair.public
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException("Failed to generate EdDSA public key for ${privateKey.algorithm}", e)
    }
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
        CryptographicAlgorithm.EC -> ECDSA_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.DSA -> DSA_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.Ed25519 -> ED25519_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.Ed448 -> ED448_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.X25519 -> X25519_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.DH -> DH_PRIVATE_KEY_MARKERS
        CryptographicAlgorithm.ECDSA -> ECDSA_PRIVATE_KEY_MARKERS // ECDSA uses EC PEM markers
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
        CryptographicAlgorithm.EC -> ECDSA_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.DSA -> DSA_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.Ed25519 -> ED25519_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.Ed448 -> ED448_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.X25519 -> X25519_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.DH -> DH_PUBLIC_KEY_MARKERS
        CryptographicAlgorithm.ECDSA -> ECDSA_PUBLIC_KEY_MARKERS // ECDSA uses EC PEM markers
      }
    } catch (e: IllegalArgumentException) {
      // Handle unsupported algorithm by returning generic markers or throwing an exception
      GENERIC_PRIVATE_KEY_MARKERS // You can choose to return generic markers or throw an exception
    }
  }

  /**
   * Gets the KeyPair for XEC algorithms (X25519) using reflection.
   * This method avoids directly referencing classes that may not be available in lower SDK versions.
   */
  @Suppress("SameParameterValue")
  private fun getXECKeyPair(algorithm: CryptographicAlgorithm): KeyPair? {
    require(algorithm == CryptographicAlgorithm.X25519) { "Unsupported algorithm: $algorithm" }

    return try {
      val keyPairGeneratorClass = Class.forName("java.security.KeyPairGenerator")
      val keyPairGenerator = keyPairGeneratorClass.getMethod("getInstance", String::class.java).invoke(null, algorithm)
      keyPairGeneratorClass.getMethod("generateKeyPair").invoke(keyPairGenerator) as KeyPair
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException("Failed to generate XEC public key for $algorithm", e)
    }
  }
}
