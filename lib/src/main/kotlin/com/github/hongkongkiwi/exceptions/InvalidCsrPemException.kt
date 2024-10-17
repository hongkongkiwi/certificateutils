package com.github.hongkongkiwi.exceptions

/**
 * Thrown when a provided Certificate Signing Request (CSR) PEM string is invalid or cannot be parsed.
 */
class InvalidCsrPemException(message: String?, cause: Throwable? = null) : Exception(message, cause)
