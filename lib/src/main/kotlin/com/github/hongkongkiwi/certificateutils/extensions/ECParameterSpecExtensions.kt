package com.github.hongkongkiwi.certificateutils.extensions

import android.util.Log
import com.github.hongkongkiwi.certificateutils.KeyUtils
import com.github.hongkongkiwi.certificateutils.PEMUtils.TAG
import com.github.hongkongkiwi.certificateutils.enums.ECCurve
import java.security.spec.ECParameterSpec

import org.bouncycastle.jce.spec.ECParameterSpec as BCECParameterSpec


/**
 * Extension function for ECParameterSpec to retrieve the curve name.
 * This function uses the existing method from KeyUtils to map the elliptic curve parameters
 * to a standard curve name (e.g., secp256r1, prime256v1).
 *
 * @return The corresponding ECCurve enum, or null if the curve name cannot be determined.
 */
fun ECParameterSpec.getCurveName(): String {
  // Use the existing getCurveName method in CertificateUtils (or KeyUtils)
  return KeyUtils.getCurveNameFromSpec(this)
}

/**
 * Extension function for BCECParameterSpec to retrieve the curve name.
 * This function uses the existing method from KeyUtils to map the Bouncy Castle elliptic curve
 * parameters to a standard curve name (e.g., secp256r1, prime256v1).
 *
 * @return The corresponding ECCurve enum, or null if the curve name cannot be determined.
 */
fun BCECParameterSpec.getCurveName(): String {
  // Use the existing getCurveName method in CertificateUtils (or KeyUtils)
  return KeyUtils.getCurveNameFromSpec(this)
}

/**
 * Extension function for `ECParameterSpec` to generate a formatted log string that provides detailed
 * information about the elliptic curve parameters.
 *
 * This method converts the elliptic curve parameters into a human-readable string format, including the
 * curve name, field size, coefficients, generator point, order, and cofactor, which are essential attributes
 * of elliptic curves.
 *
 * @return A formatted string containing the elliptic curve parameters.
 *         If the curve name cannot be determined, "N/A" will be displayed for the curve name.
 */
fun ECParameterSpec.toDetailedString(): String {
  return """
        Elliptic Curve Parameters:
        Curve Name: ${this.getCurveName() ?: "N/A"}
        Curve Field Size: ${this.curve.field.fieldSize} bits
        Curve A Coefficient: ${this.curve.a}
        Curve B Coefficient: ${this.curve.b}
        Generator Point X: ${this.generator.affineX}
        Generator Point Y: ${this.generator.affineY}
        Order: ${this.order}
        Cofactor: ${this.cofactor}
    """.trimIndent()
}

