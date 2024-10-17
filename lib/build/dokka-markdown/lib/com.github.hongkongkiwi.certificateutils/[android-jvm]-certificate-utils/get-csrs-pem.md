//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[getCsrsPem](get-csrs-pem.md)

# getCsrsPem

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [getCsrsPem](get-csrs-pem.md)(csrs: [List](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.collections/-list/index.html)&lt;PKCS10CertificationRequest&gt;): [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)

Converts a list of PKCS10CertificationRequest objects to a single PEM-formatted string.

This method iterates over each CSR in the list and uses the getCsrPem method to convert each request to its PEM format.

#### Return

The concatenated PEM-formatted CSRs string, with each CSR separated by newlines.

#### Parameters

androidJvm

| | |
|---|---|
| csrs | The list of PKCS10CertificationRequest objects to be converted. |
