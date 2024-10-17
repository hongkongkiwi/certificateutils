package com.github.hongkongkiwi.exceptions

/**
 * Thrown when a provided certificate PEM string is invalid or cannot be parsed.
 */
class InvalidCertificatePemException(message: String?, cause: Throwable? = null) : Exception(message, cause)