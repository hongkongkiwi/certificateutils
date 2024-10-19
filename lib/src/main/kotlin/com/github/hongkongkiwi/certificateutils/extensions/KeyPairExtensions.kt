package com.github.hongkongkiwi.certificateutils.extensions

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.DSAPublicKey
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter
import java.nio.charset.Charset

/**
 * Retrieves the public key from the KeyPair.
 *
 * @return The PublicKey from the KeyPair.
 */
fun KeyPair.getPublicKey(): PublicKey {
  return this.public
}

/**
 * Retrieves the private key from the KeyPair.
 *
 * @return The PrivateKey from the KeyPair.
 */
fun KeyPair.getPrivateKey(): PrivateKey {
  return this.private
}

/**
 * Checks if the public key in the KeyPair uses the specified algorithm.
 *
 * @param algorithm The algorithm to check (e.g., "RSA", "EC").
 * @return True if the public key uses the specified algorithm, false otherwise.
 */
fun KeyPair.isPublicKeyAlgorithm(algorithm: String): Boolean {
  return this.public.algorithm.equals(algorithm, ignoreCase = true)
}

/**
 * Converts the KeyPair to a PEM formatted string.
 *
 * @return The PEM formatted string representation of the KeyPair.
 */
fun KeyPair.toPem(): String {
  val writer = StringWriter()
  JcaPEMWriter(writer).use { pemWriter ->
    pemWriter.writeObject(this)
  }
  return writer.toString()
}

/**
 * Extension function for [KeyPair] that converts the private and public keys of the key pair
 * to a combined PEM-encoded byte array.
 *
 * This function first checks whether the private key or public key in the key pair is `null`.
 * If the private key is not `null`, it ensures that it is not stored in the Android Keystore,
 * since keys from the Android Keystore cannot be exported as PEM. The same check is done for the public key.
 * If either key is from the Android Keystore, an [IllegalArgumentException] is thrown.
 *
 * The function then converts both the private key and public key (if present) into PEM format strings,
 * combines them, and encodes the result into a byte array using the specified [charset].
 *
 * @param charset The [Charset] to be used for encoding the combined PEM string into a byte array.
 * Defaults to [Charsets.UTF_8].
 *
 * @return A byte array containing the combined PEM-encoded representation of the private and public keys,
 * if both are present.
 *
 * @throws IllegalArgumentException if either the private or public key is from the Android Keystore.
 */
fun KeyPair.toPemByteArray(charset: Charset = Charsets.UTF_8): ByteArray {
  if (this.private != null) {
    require(!this.private.isFromAndroidKeyStore()) { "Private key must not be from Android Keystore" }
  }
  if (this.public != null) {
    require(!this.public.isFromAndroidKeyStore()) { "Public key must not be from Android Keystore" }
  }
  return this.toPem().toByteArray(charset)
}

/**
 * Checks if the KeyPair is valid (both public and private keys are not null).
 *
 * @return True if both keys are present, false otherwise.
 */
fun KeyPair.isValid(): Boolean {
  return this.public != null && this.private != null
}

/**
 * Retrieves the size of the public key in bits.
 *
 * @return The key size in bits.
 * @throws IllegalArgumentException if the public key algorithm is unsupported.
 */
fun KeyPair.getPublicKeySize(): Int {
  return when (val publicKey = this.public) {
    is RSAPublicKey -> publicKey.modulus.bitLength()
    is ECPublicKey -> publicKey.params.curve.field.fieldSize
    is DSAPublicKey -> publicKey.params.p.bitLength()
    else -> throw IllegalArgumentException("Unsupported public key algorithm: ${publicKey.algorithm}")
  }
}

/**
 * Retrieves the type of the public key in the KeyPair.
 *
 * @return The type of the public key (e.g., "RSA", "EC", "DSA").
 */
fun KeyPair.getKeyType(): String {
  return this.public.algorithm
}

/**
 * Extension function for [KeyPair] that converts both the private and public keys
 * to a combined DER-encoded byte array.
 *
 * This function checks if both the private and public keys are not null and
 * then converts them to their respective DER-encoded byte arrays.
 *
 * The DER (Distinguished Encoding Rules) is a binary encoding format for X.509 certificates
 * and public/private keys. This function combines both DER-encoded representations of
 * the private and public keys into a single byte array.
 *
 * @return A byte array containing the combined DER-encoded representations of
 * the private and public keys.
 *
 * @throws IllegalArgumentException if the private or public key cannot be encoded.
 */
fun KeyPair.toDer(): ByteArray {
  if (this.private != null) {
    require(!this.private.isFromAndroidKeyStore()) { "Private key must not be from Android Keystore" }
  }
  if (this.public != null) {
    require(!this.public.isFromAndroidKeyStore()) { "Public key must not be from Android Keystore" }
  }

  val privateDer = this.private?.encoded
    ?: throw IllegalArgumentException("Failed to encode private key to DER format.")

  val publicDer = this.public?.encoded
    ?: throw IllegalArgumentException("Failed to encode public key to DER format.")

  // Combine both DER-encoded keys into a single byte array
  return privateDer + publicDer
}