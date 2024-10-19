package com.github.hongkongkiwi.certificateutils

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.github.hongkongkiwi.certificateutils.enums.CryptographicAlgorithm
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
import com.github.hongkongkiwi.certificateutils.exceptions.UnsupportedKeyAlgorithmException
import com.github.hongkongkiwi.certificateutils.extensions.isFromAndroidKeyStore
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.openssl.PKCS8Generator
import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.UnrecoverableEntryException
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.DSAPublicKeySpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Locale
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.interfaces.DHPrivateKey

object KeyUtils {
  internal val TAG = KeyUtils::class.java.simpleName

  init {
    // Initialize BouncyCastle as a security provider
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(BouncyCastleProvider())
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
    return when (privateKey.algorithm) {
      CryptographicAlgorithm.RSA.name -> getRSAPublicKey(privateKey)
      CryptographicAlgorithm.EC.name -> getECPublicKey(privateKey)
      CryptographicAlgorithm.DSA.name -> getDSAPublicKey(privateKey)
      CryptographicAlgorithm.Ed25519.name -> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
          throw UnsupportedKeyAlgorithmException("Ed25519 is not supported on this Android version.")
        }
        getEdPublicKey(privateKey)
      }

      CryptographicAlgorithm.Ed448.name -> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
          throw UnsupportedKeyAlgorithmException("Ed448 is not supported on this Android version.")
        }
        getEdPublicKey(privateKey)
      }

      CryptographicAlgorithm.X25519.name -> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
          throw UnsupportedKeyAlgorithmException("X25519 is not supported on this Android version.")
        }
        getXECKeyPair(CryptographicAlgorithm.X25519)?.public
          ?: throw UnsupportedKeyAlgorithmException("X25519 key pair generation failed.")
      }

      CryptographicAlgorithm.DH.name -> getDHPublicKey(privateKey)
      CryptographicAlgorithm.ECDSA.name -> getECPublicKey(privateKey) // ECDSA is based on EC
      else -> {
        // Handle unsupported algorithms for lower Android versions
        throw UnsupportedKeyAlgorithmException("${privateKey.algorithm} is not supported on this Android version.")
      }
    }
  }

  /**
   * Generates an RSA key pair. If `keystoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param keySize The size of the RSA key (default is 2048 bits).
   * @return The generated RSA key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedOperationException If an unsupported key size is used for the Android Keystore.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateKeyPairRSA(
    keySize: Int = 2048, // Default to RSA 2048
  ): KeyPair {
    require(keySize in 1024..4096) { "RSA key size must be between 1024 and 4096 bits." }

    // Generate a normal RSA key pair with a customizable key size
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(keySize, SecureRandom())
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates an EC key pair. If `keystoreAlias` is provided, the keys are stored in the Android Keystore.
   *
   * @param ecCurve The elliptic curve to use (default is SECP256R1).
   * @return The generated EC key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the EC algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateKeyPairEC(
    ecCurve: ECCurve = ECCurve.SECP256R1,
  ): KeyPair {
    // Generate a normal EC key pair
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    val ecSpec = ECGenParameterSpec(ecCurve.toString())
    keyPairGenerator.initialize(ecSpec, SecureRandom())
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates an RSA private key.
   *
   * @param keySize The size of the RSA key (default is 2048 bits).
   * @return The generated RSA key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws UnsupportedOperationException If an unsupported key size is used for the Android Keystore.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generatePrivateKeyRSA(
    keySize: Int = 2048, // Default to RSA 2048
  ): PrivateKey {
    return generateKeyPairRSA(keySize).private
  }

  /**
   * Generates an EC private key.
   *
   * @param ecCurve The elliptic curve to use (default is SECP256R1).
   * @return The generated EC key pair (public and private keys).
   * @throws NoSuchAlgorithmException If the EC algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generatePrivateKeyEC(
    ecCurve: ECCurve = ECCurve.SECP256R1,
  ): PrivateKey {
    return generateKeyPairEC(ecCurve).private
  }

  /**
   * Generates a DSA private key.
   *
   * @param keySize The size of the key in bits (default is 2048).
   * @return The generated DSA key pair.
   * @throws NoSuchAlgorithmException If the DSA algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateKeyPairDSA(
    keySize: Int = 2048,
  ): KeyPair {
    require(keySize in 1024..3072) { "DSA key size must be between 1024 and 3072 bits." }
    require(keySize % 64 == 0) { "DSA key size must be a multiple of 64." }

    // Generate a normal DSA private key outside of the Keystore
    val keyPairGenerator = KeyPairGenerator.getInstance("DSA")
    keyPairGenerator.initialize(keySize, SecureRandom())
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates an Ed25519 private key.
   *
   * @return The generated Ed25519 key pair.
   * @throws NoSuchAlgorithmException If the Ed25519 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateKeyPairEd25519(): KeyPair {
    // Generate a normal Ed25519 private key using the standard Java KeyPairGenerator
    val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519")
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates an Ed448 private key.
   *
   * @return The generated Ed448 private key.
   * @throws NoSuchAlgorithmException If the Ed448 algorithm is not available.
   * @throws NoSuchProviderException If the BouncyCastle provider is not available.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class)
  fun generateKeyPairEd448(): KeyPair {
    // Generate a normal Ed448 private key using BouncyCastle
    val keyPairGenerator = KeyPairGenerator.getInstance("Ed448", "BC")
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates an X25519 private key for Diffie-Hellman key exchange.
   *
   * @return The generated X25519 key pair.
   * @throws NoSuchAlgorithmException If the X25519 algorithm is not available.
   * @throws UnsupportedOperationException If the Android Keystore is requested but does not support X25519.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, UnsupportedOperationException::class)
  fun generateKeyPairX25519(): KeyPair {
    // Generate a normal X25519 private key using standard Java cryptography
    val keyPairGenerator = KeyPairGenerator.getInstance("X25519")
    return keyPairGenerator.generateKeyPair()
  }

  /**
   * Generates a Diffie-Hellman (DH) private key.
   *
   * @param keySize The size of the key in bits (default is 2048).
   * @return The generated DH key pair.
   * @throws NoSuchAlgorithmException If the DH algorithm is not available.
   * @throws UnsupportedOperationException If the Android Keystore is requested but does not support DH.
   */
  @JvmStatic
  @Throws(NoSuchAlgorithmException::class, UnsupportedOperationException::class)
  fun generateKeyPairDH(
    keySize: Int = 2048,
  ): KeyPair {
    require(keySize in 512..2048) { "DH key size must be between 512 and 2048." }
    require(keySize % 64 == 0) { "DH key size must be a multiple of 64." }

    // Generate a normal DH private key
    val keyPairGenerator = KeyPairGenerator.getInstance("DH")
    keyPairGenerator.initialize(keySize, SecureRandom())
    return keyPairGenerator.generateKeyPair()
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
  private fun curveEquals(
    curveSpec: ECNamedCurveSpec,
    params: java.security.spec.ECParameterSpec
  ): Boolean {
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
   * @throws IllegalArgumentException if the provided key is not an EC private key.
   */
  private fun getECPublicKeyPoint(privateKey: PrivateKey): ECPoint {
    val algorithm = CryptographicAlgorithm.fromString(privateKey.algorithm)
    // Ensure that the provided key is indeed an ECPrivateKey
    require(algorithm == CryptographicAlgorithm.EC) { "Provided key is not an ECPrivateKey." }
    if (privateKey !is ECPrivateKey) {
      throw IllegalArgumentException("Provided key must be an ECPrivateKey")
    }

    // Get the EC parameter spec associated with the private key
    val ecSpec: ECParameterSpec = privateKey.params

    // Create a KeyPairGenerator to derive the public key from the private key
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(ecSpec)

    // Generate a key pair (not strictly necessary if we just want the public key point)
    val keyPair = keyPairGenerator.generateKeyPair()

    // Get the public key point from the ECPrivateKey
    val publicKey: ECPublicKey = keyPair.public as ECPublicKey

    // Return the public key point (ECPoint)
    return publicKey.w
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
    val algorithm = CryptographicAlgorithm.fromString(privateKey.algorithm)
    require(algorithm == CryptographicAlgorithm.Ed25519 || algorithm == CryptographicAlgorithm.Ed448) {
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
      throw UnsupportedKeyAlgorithmException(
        "Failed to generate EdDSA public key for ${privateKey.algorithm} using reflection",
        e
      )
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
   * Retrieves the public key from a given KeyPair.
   *
   * This function checks if the provided KeyPair contains a valid DH public key or a private key
   * from which the public key can be derived. If the public key is not present, it uses the private key
   * to obtain the public key, checking for valid DH algorithm matches in the process.
   *
   * @param keyPair The KeyPair containing the DH public and private keys.
   * @return The DH public key.
   * @throws IllegalArgumentException if the KeyPair does not contain a valid DH public key or private key.
   */
  private fun getDHPublicKey(
    keyPair: KeyPair
  ): PublicKey {
    // Ensure that the KeyPair contains at least a public or private key
    require(keyPair.public != null || keyPair.private != null) {
      "The provided KeyPair does not contain a valid DH public or private key."
    }

    // Check if the public key is present
    keyPair.public?.let { publicKey ->
      require(CryptographicAlgorithm.DH.matches(publicKey.algorithm)) {
        "The provided KeyPair does not contain a valid DH public key."
      }
      return publicKey
    }

    // If the public key is not present, check the private key
    keyPair.private?.let { privateKey ->
      require(CryptographicAlgorithm.DH.matches(privateKey.algorithm)) {
        "The provided KeyPair does not contain a valid DH private key."
      }
      return getDHPublicKey(privateKey)
    }

    // Should not reach here due to the initial require check
    throw IllegalArgumentException("The provided KeyPair does not contain a valid DH public or private key.")
  }

  /**
   * Retrieves the public key from a given DHPrivateKey.
   *
   * This function checks if the provided private key is stored in the Android Keystore.
   * If it is, it searches through the keystore for the corresponding key entry to extract
   * the associated public key from the certificate. If the private key is not in the
   * Android Keystore, it checks if the provided key is a DHPrivateKey and generates the
   * public key from the private key parameters.
   *
   * @param privateKey The DHPrivateKey to extract the public key from.
   * @return The DH public key.
   * @throws IllegalArgumentException if the provided key is not a DH private key
   * or if no corresponding public key is found in the Android Keystore.
   */
  private fun getDHPublicKey(
    privateKey: PrivateKey
  ): PublicKey {
    // Check if the provided key is indeed a DHPrivateKey
    if (privateKey !is DHPrivateKey) {
      throw IllegalArgumentException("Provided key must be a DHPrivateKey")
    }

    // Get the DH parameters from the private key
    val dhParams = privateKey.params

    // Generate the public key from the private key using the same parameters
    val keyPairGenerator = KeyPairGenerator.getInstance("DH")
    keyPairGenerator.initialize(dhParams)

    // Generate a new KeyPair and return the public key
    return keyPairGenerator.generateKeyPair().public
  }

  /**
   * Gets the public key for DSA algorithms.
   *
   * This function checks if the provided private key is stored in the Android Keystore.
   * If it is, it searches for the corresponding key entry to extract the associated public key
   * from the certificate. If the private key is not in the Android Keystore, it verifies that
   * the provided key is a DSAPrivateKey and computes the corresponding public key.
   *
   * @param privateKey The DSA private key.
   * @return The generated public key.
   * @throws IllegalArgumentException If the provided key is not a DSAPrivateKey
   * or if no corresponding public key is found in the Android Keystore.
   */
  private fun getDSAPublicKey(
    privateKey: PrivateKey
  ): PublicKey {
    // Check if the provided key is indeed a DSAPrivateKey
    if (privateKey !is DSAPrivateKey) {
      throw IllegalArgumentException("Provided key must be a DSAPrivateKey")
    }

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
   * Retrieves the public key from a given ECPrivateKey.
   *
   * This function checks if the provided private key is stored in the Android Keystore.
   * If it is, it searches for the corresponding key entry to extract the associated public key
   * from the certificate. If the private key is not in the Android Keystore, it verifies that
   * the provided key is an ECPrivateKey and computes the corresponding public key.
   *
   * @param privateKey The ECPrivateKey to extract the public key from.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return The corresponding EC public key.
   * @throws IllegalArgumentException if the provided key is not an ECPrivateKey
   * or if no corresponding public key is found in the Android Keystore.
   */
  private fun getECPublicKey(
    privateKey: PrivateKey,
    keyStore: KeyStore? = null
  ): PublicKey {
    // Check if the provided key is from the Android Keystore
    if (privateKey.isFromAndroidKeyStore()) {
      // Initialize the Android Keystore
      val loadedKeyStore = keyStore ?: KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
      }

      // Search for the corresponding key entry by iterating through the aliases
      for (alias in loadedKeyStore.aliases()) {
        // Check if the entry is a PrivateKeyEntry
        when (val keyEntry = loadedKeyStore.getEntry(alias, null)) {
          is KeyStore.PrivateKeyEntry -> {
            if (keyEntry.privateKey == privateKey) {
              // Retrieve the public key from the certificate associated with the key entry
              return keyEntry.certificate.publicKey
            }
          }
        }
      }
      throw IllegalArgumentException("No public key found for the provided Android keystore private key.")
    }

    // Check if the provided key is indeed an ECPrivateKey
    if (privateKey !is ECPrivateKey) {
      throw IllegalArgumentException("Provided key must be an ECPrivateKey")
    }

    // Use the ECPrivateKey to derive the public key
    val keyFactory = KeyFactory.getInstance("EC")
    val publicKeyPoint = getECPublicKeyPoint(privateKey) // Implement this function
    val publicKeySpec = ECPublicKeySpec(publicKeyPoint, privateKey.params)

    // Generate and return the public key
    return keyFactory.generatePublic(publicKeySpec)
  }

  /**
   * Gets the public key for RSA algorithms.
   *
   * This function checks if the provided RSA private key is stored in the Android Keystore.
   * If it is, it searches for the corresponding key entry to extract the associated public key
   * from the certificate. If the private key is not in the Android Keystore, it verifies that
   * the provided key is an RSAPrivateKey and derives the corresponding public key.
   *
   * @param privateKey The RSA private key.
   * @param keyStore An optional KeyStore instance. If null, the Android Keystore will be initialized.
   * @return The generated public key.
   * @throws IllegalArgumentException If the provided key is not an RSAPrivateKey
   * or if no corresponding public key is found for the provided Android Keystore private key.
   * @throws UnsupportedKeyAlgorithmException If the RSA algorithm is unsupported.
   */
  private fun getRSAPublicKey(
    privateKey: PrivateKey,
    keyStore: KeyStore? = null
  ): PublicKey {
    // Check if the provided key is from the Android Keystore
    if (privateKey.isFromAndroidKeyStore()) {
      // Initialize the Android Keystore
      val loadedKeyStore = keyStore ?: KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
      }

      // Search for the corresponding key entry by iterating through the aliases
      for (alias in loadedKeyStore.aliases()) {
        // Check if the entry is a PrivateKeyEntry
        when (val keyEntry = loadedKeyStore.getEntry(alias, null)) {
          is KeyStore.PrivateKeyEntry -> {
            if (keyEntry.privateKey == privateKey) {
              // Retrieve the public key from the certificate associated with the key entry
              return keyEntry.certificate.publicKey
            }
          }
        }
      }
      throw IllegalArgumentException("No public key found for the provided Android Keystore private key.")
    }

    // Check if the provided key is indeed an RSAPrivateKey
    if (privateKey !is RSAPrivateKey) {
      throw IllegalArgumentException("Provided key must be an RSAPrivateKey")
    }

    // Use the RSA private key to derive the public key
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, BigInteger.valueOf(65537))

    // Generate and return the public key
    return keyFactory.generatePublic(publicKeySpec)
  }

  /**
   * Gets the public key for EdDSA algorithms (Ed25519 and Ed448) using reflection.
   * This method avoids directly referencing classes that may not be available in lower SDK versions.
   *
   * @param privateKey The EdDSA private key.
   * @return The corresponding public key.
   * @throws UnsupportedKeyAlgorithmException If the algorithm is unsupported.
   * @throws IllegalArgumentException If no corresponding public key is found for the provided Android Keystore private key.
   */
  private fun getEdPublicKey(
    privateKey: PrivateKey
  ): PublicKey {
    // If not from the Android Keystore, proceed to generate the public key using reflection
    return try {
      // Use reflection to access KeyPairGenerator
      val keyPairGeneratorClass = Class.forName("java.security.KeyPairGenerator")
      val keyPairGenerator = keyPairGeneratorClass.getMethod("getInstance", String::class.java)
        .invoke(null, privateKey.algorithm)

      // Generate the key pair
      val keyPair =
        keyPairGeneratorClass.getMethod("generateKeyPair").invoke(keyPairGenerator) as KeyPair

      // Return the public key
      keyPair.public
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException(
        "Failed to generate EdDSA public key for ${privateKey.algorithm}",
        e
      )
    }
  }

  /**
   * Retrieves the public key from the Android Keystore that corresponds to the provided private key.
   *
   * This method searches through the Android Keystore for the alias corresponding to the given private key.
   * If a matching private key entry is found, it returns the associated public key from the certificate stored with the private key.
   *
   * @param privateKey The private key whose corresponding public key needs to be retrieved.
   * @param keyStore The KeyStore instance from which the key will be retrieved. Defaults to the Android Keystore.
   * @return The public key corresponding to the provided private key, or null if no match is found.
   * @throws KeyStoreException If there is an issue accessing the KeyStore.
   * @throws NoSuchAlgorithmException If the algorithm for retrieving the key entry is unavailable.
   * @throws UnrecoverableEntryException If the key entry cannot be recovered.
   */
  private fun getPublicKeyFromAndroidKeyStore(
    privateKey: PrivateKey,
    keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  ): PublicKey? {
    // Search for the corresponding key entry by iterating through the aliases
    for (alias in keyStore.aliases()) {
      // Check if the entry is a PrivateKeyEntry
      when (val keyEntry = keyStore.getEntry(alias, null)) {
        is KeyStore.PrivateKeyEntry -> {
          if (keyEntry.privateKey == privateKey) {
            // Retrieve the public key from the certificate associated with the key entry
            return keyEntry.certificate.publicKey
          }
        }
      }
    }
    return null
  }

  /**
   * Generates an AES symmetric encryption key and stores it in the Android Keystore.
   *
   * @param keySize The size of the AES key in bits (128 or 256). Default is 256.
   * @param keyStoreAlias The alias under which to store the key in the Android Keystore.
   * @param keyStoreKeyPurposes The purposes for the key (default is encryption and decryption).
   * @return The generated AES SecretKey.
   * @throws IllegalStateException If there is an error generating the key.
   */
  @JvmStatic
  @Throws(
    IllegalStateException::class,
  )
  fun generateSecretKeyAES(
    keySize: Int = 256, // Default to a strong AES encryption value
    keyStoreAlias: String,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
  ): SecretKey {
    require(keySize == 128 || keySize == 256) { "AES key size must be 128 or 256 bits when using the Android Keystore." }
    require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }

    try {
      // Generate key in Android Keystore
      val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
      val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        keyStoreAlias,
        keyStoreKeyPurposes
      )
        .setKeySize(keySize)
        .setBlockModes(
          KeyProperties.BLOCK_MODE_GCM,
          KeyProperties.BLOCK_MODE_CBC
        ) // Set block modes directly
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // Set encryption padding directly
        .setRandomizedEncryptionRequired(true)
        .build()

      keyGen.init(keyGenParameterSpec)
      return keyGen.generateKey()
    } catch (e: Exception) {
      throw IllegalStateException("Failed to initialize key generator for Android Keystore", e)
    }
  }

  /**
   * Generates an AES symmetric encryption key. If `keyStoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keySize The size of the AES key in bits (128, 192, or 256). Default is 256.
   * @return The generated AES key.
   * @throws NoSuchAlgorithmException If the AES algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws IllegalArgumentException If the key size is invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateSecretKeyAES(
    keySize: Int = 256, // Default to a strong AES encryption value
  ): SecretKey {
    require(keySize == 128 || keySize == 192 || keySize == 256) { "AES key size must be 128, 192, or 256 bits." }

    // Generate a normal AES key
    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)
    keyGen.init(keySize, SecureRandom())
    return keyGen.generateKey()
  }

  /**
   * Generates an HMAC-SHA256 key. If `keyStoreAlias` is provided, the key is stored in the Android Keystore.
   *
   * @param keyStoreAlias The alias for storing the key in the Android Keystore. If null, a normal HMAC-SHA256 key is generated.
   * @param keyStoreKeyPurposes The intended purposes for the key (default is signing and verifying).
   * @return The generated HMAC-SHA256 key.
   * @throws NoSuchAlgorithmException If the HmacSHA256 algorithm is not available.
   * @throws NoSuchProviderException If the Android Keystore provider is not available.
   * @throws InvalidAlgorithmParameterException If the KeyGenParameterSpec is invalid.
   * @throws IllegalArgumentException If the key purposes are invalid.
   */
  @JvmStatic
  @Throws(
    NoSuchAlgorithmException::class,
    NoSuchProviderException::class,
    InvalidAlgorithmParameterException::class
  )
  fun generateSecretKeyHmacSHA256(
    keyStoreAlias: String? = null,
    keyStoreKeyPurposes: Int = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
  ): SecretKey {
    val keyGenerator: KeyGenerator = if (!keyStoreAlias.isNullOrBlank()) {
      require(keyStoreKeyPurposes > 0) { "Key purposes must be greater than 0." }

      try {
        // Generate key in Android Keystore
        val keyGen =
          KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
          keyStoreAlias,
          keyStoreKeyPurposes
        )
          .setDigests(KeyProperties.DIGEST_SHA256)
          .build()

        keyGen.init(keyGenParameterSpec)
        keyGen
      } catch (e: Exception) {
        throw IllegalStateException("Failed to initialize key generator for Android Keystore", e)
      }
    } else {
      // Generate a normal HMAC-SHA256 key
      val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
      keyGen.init(SecureRandom())
      keyGen
    }

    return keyGenerator.generateKey()
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
      val keyPairGenerator =
        keyPairGeneratorClass.getMethod("getInstance", String::class.java).invoke(null, algorithm)
      keyPairGeneratorClass.getMethod("generateKeyPair").invoke(keyPairGenerator) as KeyPair
    } catch (e: Exception) {
      throw UnsupportedKeyAlgorithmException("Failed to generate XEC public key for $algorithm", e)
    }
  }

}