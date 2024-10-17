# CertificateUtils

**CertificateUtils** is a Kotlin utility library for managing cryptographic keys, certificates, and Certificate Signing Requests (CSRs). It provides extensions for handling PEM formats, public/private keys, X.509 certificates, and more.

## Features

- **Certificate Management**: Parse, validate, and convert X.509 certificates.
- **Private and Public Key Handling**: Support for RSA, EC, DSA, Ed25519, and other key formats.
- **Certificate Signing Requests (CSR)**: Generate and parse CSRs.
- **Android Keystore Support**: Integration with the Android Keystore.
- **PEM Format Utilities**: Convert various cryptographic objects to and from PEM format.
- **Extensions for Ease of Use**: String extensions for PEM format checks, conversions, and key validation.

## Installation

### Gradle

Add the following to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.hongkongkiwi:certificateutils:1.0.0")
}
```

### Jitpack

The easiest way to use the module is through Jitpack.

For setup instructions visit [Jitpack.io](https://jitpack.io/#hongkongkiwi/certificateutils)

## Generating Documentation

To generate the documentation in Markdown format, run the following command:

```bash
./gradlew dokkaGfm
```

This will generate the documentation in the `build/dokka-markdown` directory.

### Viewing the Documentation

After running the command, navigate to the `build/dokka-markdown` directory to view the generated documentation in Markdown format.

```bash
open build/dokka-markdown/index.md
```

The `index.md` file contains the documentation for your project. You can also navigate through the documentation for individual classes, functions, and properties.

## Usage

### PEM Parsing Extensions

You can use string extensions to easily check if a string contains a PEM-formatted certificate, private key, or CSR:

```kotlin
val pemString = "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----"

if (pemString.isCertificatePem()) {
    val certificate = pemString.toX509Certificate()
    Log.d("CertificateUtils", "Parsed Certificate: ${certificate.subjectDN.name}")
}
```

### Working with Private Keys

Convert PEM-formatted private keys:

```kotlin
val privateKeyPem = "-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----"
val privateKey = privateKeyPem.toPrivateKey()
Log.d("CertificateUtils", "Private Key Algorithm: ${privateKey.algorithm}")
```

### CSR (Certificate Signing Request) Parsing

You can also parse CSRs from PEM format:

```kotlin
val csrPem = "-----BEGIN CERTIFICATE REQUEST----- ... -----END CERTIFICATE REQUEST-----"
val csr = csrPem.toPKCS10CertificationRequest()
Log.d("CertificateUtils", "Parsed CSR Subject: ${csr.subject}")
```
