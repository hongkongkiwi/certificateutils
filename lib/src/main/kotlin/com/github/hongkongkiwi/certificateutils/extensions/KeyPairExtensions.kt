import com.github.hongkongkiwi.certificateutils.extensions.getPublicKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.DSAPublicKey
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter

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

