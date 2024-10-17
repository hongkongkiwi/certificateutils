//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[createCsr](create-csr.md)

# createCsr

[androidJvm]\
fun [createCsr](create-csr.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), subjectDNBuilder: [CsrSubjectDNBuilder](../../com.github.hongkongkiwi.certificateutils.builders/[android-jvm]-csr-subject-d-n-builder/index.md)): PKCS10CertificationRequest

Creates a PKCS#10 Certification Request (CSR) using the provided private key and subject distinguished name (DN).

This method takes a private key and a SubjectDNBuilder instance, builds the subject DN string, and then creates the CSR based on the given private key and subject DN.

#### Return

The constructed PKCS10CertificationRequest object.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The private key to be used for signing the CSR. |
| subjectDNBuilder | An instance of SubjectDNBuilder that provides the attributes for the subject DN. |

[androidJvm]\

@[JvmStatic](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.jvm/-jvm-static/index.html)

fun [createCsr](create-csr.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html), subjectDN: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html)): PKCS10CertificationRequest

Generates a Certificate Signing Request (CSR) using the provided private key and subject distinguished name (DN).

#### Return

The generated CSR as a PEM-formatted string.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The PrivateKey object. |
| subjectDN | The subject distinguished name (DN) string. |

#### Throws

| | |
|---|---|
| [InvalidPrivateKeyPemException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-invalid-private-key-pem-exception/index.md) | If the private key is invalid. |
| [UnsupportedKeyAlgorithmException](../../com.github.hongkongkiwi.certificateutils.exceptions/[android-jvm]-unsupported-key-algorithm-exception/index.md) | If the private key algorithm is unsupported. |
