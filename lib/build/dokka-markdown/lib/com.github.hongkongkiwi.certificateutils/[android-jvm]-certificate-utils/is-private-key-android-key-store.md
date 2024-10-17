//[lib](../../../index.md)/[com.github.hongkongkiwi.certificateutils](../index.md)/[[androidJvm]CertificateUtils](index.md)/[isPrivateKeyAndroidKeyStore](is-private-key-android-key-store.md)

# isPrivateKeyAndroidKeyStore

[androidJvm]\
fun [isPrivateKeyAndroidKeyStore](is-private-key-android-key-store.md)(privateKey: [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html)): [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html)

Checks whether the provided private key is stored in the Android Keystore.

This method checks the provider of the private key to determine if it belongs to the Android Keystore. Private keys generated or imported into the Android Keystore will have a provider name of &quot;AndroidKeyStore&quot;. This is useful for ensuring that keys stored securely on the device are being used, which can be critical for sensitive operations such as signing or encryption in a secure environment.

#### Return

True if the private key is from the Android Keystore, false otherwise.

#### Parameters

androidJvm

| | |
|---|---|
| privateKey | The private key to check. |
