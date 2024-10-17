package com.github.hongkongkiwi.certificateutils.builders

/**
 * Builder class for constructing a subject distinguished name (DN) string for an X.509 certificate.
 */
class CsrSubjectDNBuilder {
  private var country: String? = null
  private var state: String? = null
  private var locality: String? = null
  private var organization: String? = null
  private var organizationalUnit: String? = null
  private var commonName: String? = null
  private var streetAddress: String? = null
  private var domainComponent: String? = null
  private var userId: String? = null
  private var serialNumber: String? = null
  private var emailAddress: String? = null

  /**
   * Sets the country name (C). This is a required attribute.
   */
  fun country(country: String) = apply { this.country = country }

  /**
   * Sets the state or province name (ST). Optional.
   */
  fun state(state: String?) = apply { this.state = state }

  /**
   * Sets the locality name (L). Optional.
   */
  fun locality(locality: String?) = apply { this.locality = locality }

  /**
   * Sets the organization name (O). Optional.
   */
  fun organization(organization: String?) = apply { this.organization = organization }

  /**
   * Sets the organizational unit name (OU). Optional.
   */
  fun organizationalUnit(organizationalUnit: String?) = apply { this.organizationalUnit = organizationalUnit }

  /**
   * Sets the common name (CN). Optional.
   */
  fun commonName(commonName: String?) = apply { this.commonName = commonName }

  /**
   * Sets the street address (STREET). Optional.
   */
  fun streetAddress(streetAddress: String?) = apply { this.streetAddress = streetAddress }

  /**
   * Sets the domain component (DC). Optional.
   */
  fun domainComponent(domainComponent: String?) = apply { this.domainComponent = domainComponent }

  /**
   * Sets the user ID (UID). Optional.
   */
  fun userId(userId: String?) = apply { this.userId = userId }

  /**
   * Sets the serial number (SN). Optional.
   */
  fun serialNumber(serialNumber: String?) = apply { this.serialNumber = serialNumber }

  /**
   * Sets the email address (EMAILADDRESS). Optional.
   */
  fun emailAddress(emailAddress: String?) = apply { this.emailAddress = emailAddress }

  /**
   * Builds the subject DN string using the set attributes.
   *
   * @return The constructed subject DN string.
   * @throws IllegalArgumentException If the required attributes are not set (e.g., country).
   */
  fun build(): String {
    // Ensure that the required attribute is set
    requireNotNull(country) { "Country (C) is required." }

    val parts = mutableListOf("C=$country")
    state?.let { parts.add("ST=$it") }
    locality?.let { parts.add("L=$it") }
    organization?.let { parts.add("O=$it") }
    organizationalUnit?.let { parts.add("OU=$it") }
    commonName?.let { parts.add("CN=$it") }
    streetAddress?.let { parts.add("STREET=$it") }
    domainComponent?.let { parts.add("DC=$it") }
    userId?.let { parts.add("UID=$it") }
    serialNumber?.let { parts.add("SN=$it") }
    emailAddress?.let { parts.add("EMAILADDRESS=$it") }

    return parts.joinToString(", ")
  }
}