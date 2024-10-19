package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Exception class for handling failures during CA certificate updates in the Android Keystore.
 */
class CACertificateUpdateException(message: String, cause: Throwable? = null) : Exception(message, cause)
