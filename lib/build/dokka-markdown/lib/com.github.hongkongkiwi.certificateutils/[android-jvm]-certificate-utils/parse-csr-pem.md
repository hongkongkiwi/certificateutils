//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[parseCsrPem](parse-csr-pem.md)

# parseCsrPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [parseCsrPem](parse-csr-pem.md)(csrPem: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;PKCS10CertificationRequest&gt;

Parses a PEM-formatted Certificate Signing Request (CSR) and returns all found requests.

#### Return

A list of parsed PKCS10CertificationRequest objects.

#### Parameters

androidJvm

| | |
|---|---|
| csrPem | The PEM-formatted CSR string. |

#### Throws

| | |
|---|---|
| [InvalidCsrPemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-csr-pem-exception/index.md) | If the CSR PEM is invalid or no valid CSRs are found. |
