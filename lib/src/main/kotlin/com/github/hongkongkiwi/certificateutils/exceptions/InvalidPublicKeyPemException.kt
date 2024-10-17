package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a provided public key PEM string is invalid or cannot be parsed.
 */
class InvalidPublicKeyPemException(message: String?, cause: Throwable? = null) : Exception(message, cause)
