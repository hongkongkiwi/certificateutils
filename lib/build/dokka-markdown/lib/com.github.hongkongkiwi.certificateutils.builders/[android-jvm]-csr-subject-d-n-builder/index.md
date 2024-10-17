//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils.builders](../index.md)/[[androidJvm]CsrSubjectDNBuilder](index.md)

# CsrSubjectDNBuilder

[androidJvm]\
class [CsrSubjectDNBuilder](index.md)

Builder class for constructing a subject distinguished name (DN) string for an X.509 certificate.

## Constructors

| | |
|---|---|
| [CsrSubjectDNBuilder](-csr-subject-d-n-builder.md) | [androidJvm]<br>constructor() |

## Functions

| Name | Summary |
|---|---|
| [build](build.md) | [androidJvm]<br>fun [build](build.md)(): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)<br>Builds the subject DN string using the set attributes. |
| [commonName](common-name.md) | [androidJvm]<br>fun [commonName](common-name.md)(commonName: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the common name (CN). Optional. |
| [country](country.md) | [androidJvm]<br>fun [country](country.md)(country: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [CsrSubjectDNBuilder](index.md)<br>Sets the country name (C). This is a required attribute. |
| [domainComponent](domain-component.md) | [androidJvm]<br>fun [domainComponent](domain-component.md)(domainComponent: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the domain component (DC). Optional. |
| [emailAddress](email-address.md) | [androidJvm]<br>fun [emailAddress](email-address.md)(emailAddress: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the email address (EMAILADDRESS). Optional. |
| [locality](locality.md) | [androidJvm]<br>fun [locality](locality.md)(locality: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the locality name (L). Optional. |
| [organization](organization.md) | [androidJvm]<br>fun [organization](organization.md)(organization: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the organization name (O). Optional. |
| [organizationalUnit](organizational-unit.md) | [androidJvm]<br>fun [organizationalUnit](organizational-unit.md)(organizationalUnit: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the organizational unit name (OU). Optional. |
| [serialNumber](serial-number.md) | [androidJvm]<br>fun [serialNumber](serial-number.md)(serialNumber: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the serial number (SN). Optional. |
| [state](state.md) | [androidJvm]<br>fun [state](state.md)(state: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the state or province name (ST). Optional. |
| [streetAddress](street-address.md) | [androidJvm]<br>fun [streetAddress](street-address.md)(streetAddress: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the street address (STREET). Optional. |
| [userId](user-id.md) | [androidJvm]<br>fun [userId](user-id.md)(userId: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)?): [CsrSubjectDNBuilder](index.md)<br>Sets the user ID (UID). Optional. |
