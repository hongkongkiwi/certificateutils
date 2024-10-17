package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a certificate is expired and expired certificates are not allowed.
 */
class ExpiredCertificateException(message: String?, cause: Throwable? = null) : Exception(message, cause)
