package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a provided PrivateKey does not exist in our KeyStore.
 */
class AndroidKeyStoreException(message: String?, cause: Throwable? = null) :
  Exception(message, cause)
