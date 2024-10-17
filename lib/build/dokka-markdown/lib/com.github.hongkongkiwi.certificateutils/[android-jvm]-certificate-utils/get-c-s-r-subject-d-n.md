//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCSRSubjectDN](get-c-s-r-subject-d-n.md)

# getCSRSubjectDN

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCSRSubjectDN](get-c-s-r-subject-d-n.md)(csr: PKCS10CertificationRequest): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Extracts the subject distinguished name (DN) from a Certificate Signing Request (CSR).

This method takes a PKCS#10 formatted CSR and returns the subject DN as a string.

#### Return

The subject distinguished name (DN) string extracted from the CSR.

#### Parameters

androidJvm

| | |
|---|---|
| csr | The PKCS10CertificationRequest object representing the PEM-formatted CSR. |

#### Throws

| | |
|---|---|
| [InvalidCsrPemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-csr-pem-exception/index.md) | If the CSR is invalid or cannot be processed. |
