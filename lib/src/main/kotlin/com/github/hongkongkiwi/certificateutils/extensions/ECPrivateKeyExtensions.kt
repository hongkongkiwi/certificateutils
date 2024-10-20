package com.github.hongkongkiwi.certificateutils.extensions

import org.bouncycastle.jce.ECNamedCurveTable
import java.security.spec.EllipticCurve
import java.math.BigInteger
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.spec.ECParameterSpec as BCECParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.interfaces.ECPrivateKey
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.ECPoint as BCECPoint

private fun ensureBouncyCastleProvider() {
  if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
    Security.addProvider(BouncyCastleProvider())
  }
}

private fun convertECPointToBouncyCastle(curve: ECCurve, point: java.security.spec.ECPoint): BCECPoint {
  val affineX = point.affineX
  val affineY = point.affineY

  // Use the curve to create the Bouncy Castle ECPoint
  return curve.createPoint(affineX, affineY)
}

fun ECPrivateKey.toBouncyCastleECParameterSpec(): BCECParameterSpec? {
  ensureBouncyCastleProvider()

  return if (this.params is ECNamedCurveSpec) {
    // Handle named curve
    val curveName = (this.params as ECNamedCurveSpec).name
    org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec(curveName)
  } else {
    // Manually convert the curve and parameters to Bouncy Castle
    val ecParams = this.params

    // Convert the Java EllipticCurve to Bouncy Castle ECCurve
    val curve = ecParams.curve.toBouncyCastleCurve()

    // Convert the generator point (ECPoint) to Bouncy Castle ECPoint
    val generator = ecParams.generator
    val g: BCECPoint = convertECPointToBouncyCastle(curve, generator)

    // Get the order and cofactor of the curve
    val n = ecParams.order
    val h = BigInteger.valueOf(ecParams.cofactor.toLong())  // Convert cofactor to BigInteger

    // Return the Bouncy Castle ECParameterSpec
    BCECParameterSpec(curve, g, n, h)
  }
}