package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a certificate and a private key do not form a valid key pair.
 */
class KeyPairMismatchException(message: String?, cause: Throwable? = null) : Exception(message, cause)
