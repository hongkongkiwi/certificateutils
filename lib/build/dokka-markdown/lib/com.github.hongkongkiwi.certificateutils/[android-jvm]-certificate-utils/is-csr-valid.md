//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isCsrValid](is-csr-valid.md)

# isCsrValid

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [isCsrValid](is-csr-valid.md)(csr: PKCS10CertificationRequest): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks if the provided Certificate Signing Request (CSR) is valid.

This method verifies the validity of the CSR by ensuring that it can be parsed successfully. It checks that the CSR contains a valid subject distinguished name (DN) and verifies the CSR's signature against the extracted public key.

#### Return

True if the CSR is valid; false if it is not well-formed or has any issues.

#### Parameters

androidJvm

| | |
|---|---|
| csr | The PKCS10CertificationRequest object representing the CSR to validate. |

#### Throws

| | |
|---|---|
| [InvalidCertificatePemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-certificate-pem-exception/index.md) | If the CSR cannot be validated due to an invalid format or issue. |
