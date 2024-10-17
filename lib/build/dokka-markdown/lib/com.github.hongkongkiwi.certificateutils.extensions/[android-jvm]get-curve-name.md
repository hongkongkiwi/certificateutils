//[lib](../../index.md)/[com.github.hongkongkiwi.certificateutils.extensions](index.md)/[[androidJvm]getCurveName]([android-jvm]get-curve-name.md)

# getCurveName

[androidJvm]\
fun [PrivateKey](https://developer.android.com/reference/kotlin/java/security/PrivateKey.html).[getCurveName]([android-jvm]get-curve-name.md)(): [ECCurve](../com.github.hongkongkiwi.certificateutils.enums/[android-jvm]-e-c-curve/index.md)?

Extension function to retrieve the name of the elliptic curve for an EC private key.

This function checks if the private key is of type ECPrivateKey, and if so, it retrieves the curve name using the method defined in CertificateUtils. If the private key is of a different type, it returns null.

#### Return

The name of the elliptic curve as a String, or null if the private key is not an ECPrivateKey.
