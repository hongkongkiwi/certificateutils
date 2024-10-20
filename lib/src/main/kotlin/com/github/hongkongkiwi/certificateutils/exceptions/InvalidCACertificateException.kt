package com.github.hongkongkiwi.certificateutils.exceptions

/**
 * Thrown when a certificate is expected to be a Certificate Authority (CA) but is not.
 */
class InvalidCACertificateException(message: String?, cause: Throwable? = null) :
  Exception(message, cause)