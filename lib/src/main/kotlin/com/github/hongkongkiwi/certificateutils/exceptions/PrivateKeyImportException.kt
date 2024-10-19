package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Exception class for handling failures during private key import into the Android Keystore.
 */
class PrivateKeyImportException(message: String, cause: Throwable? = null) : Exception(message, cause)
