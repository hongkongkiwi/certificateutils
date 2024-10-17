package com.github.hongkongkiwi.certificateutils.models

import kotlinx.serialization.Serializable
import java.security.PrivateKey
import java.util.Objects

/**
 * A wrapper for a PrivateKey with an alias. This class is used to store the alias
 * of a key from Android Keystore along with the wrapped PrivateKey.
 *
 * @property alias The alias of the key in the Android Keystore.
 * @property wrappedKey The actual PrivateKey that this class wraps.
 */
@Serializable
class PrivateKeyWithAlias(
  val alias: String?,
  private val wrappedKey: PrivateKey
) {

  /**
   * Returns the wrapped PrivateKey.
   */
  fun getWrappedKey(): PrivateKey = wrappedKey

  // Override equals to ensure equality checks take alias and key into account
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PrivateKeyWithAlias) return false
    return alias == other.alias && wrappedKey == other.wrappedKey
  }

  // Override hashCode to include both alias and key
  override fun hashCode(): Int = Objects.hash(alias, wrappedKey)

  // Override toString for debugging purposes
  override fun toString(): String = "PrivateKeyWithAlias(alias='$alias', wrappedKey=${wrappedKey.algorithm})"
}
