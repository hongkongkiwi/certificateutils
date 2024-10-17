package com.github.hongkongkiwi.exceptions

/**
 * Exception thrown when a PEM string is invalid or cannot be parsed.
 *
 * This exception provides information about the nature of the parsing error
 * and can be used to indicate issues with the format or content of the PEM string.
 *
 * @property message A detailed message about the error.
 * @property cause The underlying throwable cause of this exception, if any.
 */
class InvalidPemFormatException(
  message: String,
  cause: Throwable? = null
) : Exception(message, cause)