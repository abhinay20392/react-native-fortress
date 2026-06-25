package com.fortress.repackaging

import android.content.pm.PackageManager
import android.os.Build
import com.facebook.react.bridge.ReactApplicationContext
import com.fortress.root.ThreatResult
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object RepackagingDetector {
  private var expectedSha256: String? = null

  fun configure(expectedSha256Hex: String?) {
    expectedSha256 =
      expectedSha256Hex
        ?.trim()
        ?.lowercase()
        ?.replace(":", "")
        ?.takeIf { it.isNotEmpty() }
  }

  fun isEnabled(): Boolean = expectedSha256 != null

  fun runChecks(context: ReactApplicationContext): List<ThreatResult> {
    val expected = expectedSha256 ?: return emptyList()
    val actual = getSigningCertificateSha256(context) ?: return emptyList()

    if (actual.equals(expected, ignoreCase = true)) {
      return emptyList()
    }

    return listOf(
      ThreatResult(
        type = "repackaging",
        severity = "critical",
        message = "App signing certificate does not match the expected release signature",
      )
    )
  }

  private fun getSigningCertificateSha256(context: ReactApplicationContext): String? {
    return try {
      val packageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
          )
        } else {
          @Suppress("DEPRECATION")
          context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNATURES,
          )
        }

      val signatures =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          packageInfo.signingInfo?.apkContentsSigners
        } else {
          @Suppress("DEPRECATION")
          packageInfo.signatures
        } ?: return null

      val signature = signatures.firstOrNull() ?: return null
      val certificateFactory = CertificateFactory.getInstance("X.509")
      val certificate =
        certificateFactory.generateCertificate(ByteArrayInputStream(signature.toByteArray()))
          as X509Certificate

      val digest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
      digest.joinToString("") { byte -> "%02x".format(byte) }
    } catch (_: Exception) {
      null
    }
  }
}
