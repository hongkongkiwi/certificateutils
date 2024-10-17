package com.github.hongkongkiwi.exceptions

/**
 * Thrown when a self-signed certificate is provided but self-signed certificates are not allowed.
 */
class SelfSignedCertificateException(message: String?, cause: Throwable? = null) : Exception(message, cause)
