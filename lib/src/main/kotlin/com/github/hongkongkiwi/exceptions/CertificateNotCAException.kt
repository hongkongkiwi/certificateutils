package com.github.hongkongkiwi.exceptions

/**
 * Thrown when a certificate is expected to be a Certificate Authority (CA) but is not.
 */
class CertificateNotCAException(message: String?, cause: Throwable? = null) : Exception(message, cause)