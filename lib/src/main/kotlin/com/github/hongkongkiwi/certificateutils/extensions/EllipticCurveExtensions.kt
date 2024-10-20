package com.github.hongkongkiwi.certificateutils.extensions

fun java.security.spec.EllipticCurve.toBouncyCastleCurve(): org.bouncycastle.math.ec.ECCurve {
  val a = this.a
  val b = this.b
  val field = this.field

  // Assuming it's a prime field (Fp), which is typical in most EC curves
  val p = (field as java.security.spec.ECFieldFp).p

  // Return the Bouncy Castle ECCurve object
  return org.bouncycastle.math.ec.ECCurve.Fp(p, a, b)
}