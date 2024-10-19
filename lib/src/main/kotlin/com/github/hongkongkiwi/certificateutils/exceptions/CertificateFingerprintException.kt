package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Exception class for handling failures during certificate fingerprint generation.
 */
class CertificateFingerprintException(message: String, cause: Throwable? = null) : Exception(message, cause)
