package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Exception class for handling failures during public key import to the Android Keystore.
 */
class PublicKeyImportException(message: String, cause: Throwable? = null) : Exception(message, cause)
