package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Exception class for handling failures during self-signed certificate generation.
 */
class SelfSignedCertificateGenerationException(message: String, cause: Throwable? = null) : Exception(message, cause)
