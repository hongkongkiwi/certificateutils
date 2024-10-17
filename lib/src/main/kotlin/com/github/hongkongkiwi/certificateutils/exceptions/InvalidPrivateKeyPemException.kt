package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a provided private key PEM string is invalid or cannot be parsed.
 */
class InvalidPrivateKeyPemException(message: String?, cause: Throwable? = null) : Exception(message, cause)
