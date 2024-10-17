package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a key algorithm is unsupported or unrecognized.
 */
class UnsupportedKeyAlgorithmException(message: String?, cause: Throwable? = null) : Exception(message, cause)
