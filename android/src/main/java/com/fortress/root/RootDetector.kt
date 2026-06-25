package com.fortress.root

import android.os.Build
import com.fortress.ThreatScoring
import java.io.File

object RootDetector {
  private val SU_PATHS =
    listOf(
      "/system/bin/su",
      "/system/xbin/su",
      "/sbin/su",
      "/data/local/xbin/su",
      "/data/local/bin/su",
      "/system/sd/xbin/su",
      "/system/bin/failsafe/su",
      "/data/local/su",
      "/su/bin/su",
      "/magisk/.core/bin/su",
    )

  private val MAGISK_PATHS =
    listOf(
      "/sbin/.magisk",
      "/data/adb/magisk",
      "/data/adb/magisk.img",
      "/cache/.disable_magisk",
      "/data/adb/modules",
    )

  private val ZYGISK_PATHS =
    listOf(
      "/system/lib/libzygisk.so",
      "/system/lib64/libzygisk.so",
      "/data/adb/zygisk",
    )

  fun runChecks(): List<ThreatResult> {
    val threats = mutableListOf<ThreatResult>()

    checkSuBinary()?.let { threats.add(it) }
    checkTestKeys()?.let { threats.add(it) }
    threats.addAll(checkSystemProperties())
    checkMagisk()?.let { threats.add(it) }
    checkZygisk()?.let { threats.add(it) }
    checkSuCommand()?.let { threats.add(it) }

    return threats
  }

  fun isCompromised(threats: List<ThreatResult> = runChecks()): Boolean {
    return ThreatScoring.isCompromised(threats)
  }

  private fun checkSuBinary(): ThreatResult? {
    val found =
      SU_PATHS.filter { path ->
        val file = File(path)
        file.exists() && file.canExecute()
      }

    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "root",
      severity = "high",
      message = "su binary found at: ${found.joinToString(", ")}",
    )
  }

  private fun checkTestKeys(): ThreatResult? {
    val tags = Build.TAGS ?: return null
    if (!tags.contains("test-keys")) {
      return null
    }

    return ThreatResult(
      type = "root",
      severity = "medium",
      message = "Build.TAGS contains test-keys ($tags)",
    )
  }

  private fun checkSystemProperties(): List<ThreatResult> {
    val threats = mutableListOf<ThreatResult>()

    val debuggable = getSystemProperty("ro.debuggable")
    if (debuggable == "1") {
      threats.add(
        ThreatResult(
          type = "root",
          severity = "medium",
          message = "ro.debuggable is enabled",
        )
      )
    }

    val secure = getSystemProperty("ro.secure")
    if (secure == "0") {
      threats.add(
        ThreatResult(
          type = "root",
          severity = "medium",
          message = "ro.secure is disabled",
        )
      )
    }

    return threats
  }

  private fun checkMagisk(): ThreatResult? {
    val found = MAGISK_PATHS.filter { File(it).exists() }
    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "root",
      severity = "high",
      message = "Magisk indicators found: ${found.joinToString(", ")}",
    )
  }

  private fun checkZygisk(): ThreatResult? {
    val found = ZYGISK_PATHS.filter { File(it).exists() }
    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "root",
      severity = "high",
      message = "Zygisk indicators found: ${found.joinToString(", ")}",
    )
  }

  private fun checkSuCommand(): ThreatResult? {
    return try {
      val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
      val output = process.inputStream.bufferedReader().readText().trim()
      process.waitFor()

      if (output.isNotEmpty() && File(output).exists()) {
        ThreatResult(
          type = "root",
          severity = "high",
          message = "su found in PATH at $output",
        )
      } else {
        null
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun getSystemProperty(key: String): String? {
    return try {
      val clazz = Class.forName("android.os.SystemProperties")
      val get = clazz.getMethod("get", String::class.java)
      get.invoke(null, key) as? String
    } catch (_: Exception) {
      null
    }
  }
}
