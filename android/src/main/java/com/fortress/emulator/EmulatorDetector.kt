package com.fortress.emulator

import android.os.Build
import com.fortress.root.ThreatResult
import java.io.File

object EmulatorDetector {
  private val EMULATOR_FILES =
    listOf(
      "/dev/socket/qemud",
      "/dev/qemu_pipe",
      "/system/lib/libc_malloc_debug_qemu.so",
      "/sys/qemu_trace",
      "/system/bin/qemu-props",
      "/dev/socket/genyd",
      "/dev/socket/baseband_genyd",
    )

  fun runChecks(): List<ThreatResult> {
    val signals = mutableListOf<String>()

    checkBuildProps()?.let { signals.addAll(it) }
    checkEmulatorFiles()?.let { signals.add(it) }
    checkEmulatorOperator()?.let { signals.add(it) }

    if (signals.isEmpty()) {
      return emptyList()
    }

    return listOf(
      ThreatResult(
        type = "emulator",
        severity = "medium",
        message = "Emulator / virtual device indicators: ${signals.joinToString("; ")}",
      ),
    )
  }

  private fun checkBuildProps(): List<String>? {
    val hits = mutableListOf<String>()

    fun addIf(condition: Boolean, label: String) {
      if (condition) {
        hits.add(label)
      }
    }

    val fingerprint = Build.FINGERPRINT.lowercase()
    val model = Build.MODEL.lowercase()
    val manufacturer = Build.MANUFACTURER.lowercase()
    val brand = Build.BRAND.lowercase()
    val device = Build.DEVICE.lowercase()
    val product = Build.PRODUCT.lowercase()
    val hardware = Build.HARDWARE.lowercase()
    val board = Build.BOARD.lowercase()

    addIf(
      fingerprint.startsWith("generic") ||
        fingerprint.contains("unknown") ||
        fingerprint.contains("emulator"),
      "fingerprint=$fingerprint",
    )
    addIf(
      model.contains("google_sdk") ||
        model.contains("emulator") ||
        model.contains("android sdk built for"),
      "model=${Build.MODEL}",
    )
    addIf(manufacturer.contains("genymotion"), "manufacturer=${Build.MANUFACTURER}")
    addIf(brand.startsWith("generic") && device.startsWith("generic"), "brand/device=generic")
    addIf(
      product.contains("sdk") ||
        product.contains("google_sdk") ||
        product.contains("sdk_gphone") ||
        product.contains("vbox86p") ||
        product.contains("emulator") ||
        product.contains("simulator"),
      "product=${Build.PRODUCT}",
    )
    addIf(
      hardware.contains("goldfish") ||
        hardware.contains("ranchu") ||
        hardware.contains("vbox86"),
      "hardware=${Build.HARDWARE}",
    )
    addIf(board.contains("unknown") || board.contains("goldfish"), "board=${Build.BOARD}")

    return hits.takeIf { it.isNotEmpty() }
  }

  private fun checkEmulatorFiles(): String? {
    val found = EMULATOR_FILES.filter { File(it).exists() }
    if (found.isEmpty()) {
      return null
    }
    return "files=${found.joinToString(", ")}"
  }

  private fun checkEmulatorOperator(): String? {
    // Common AVD default: "Android" as network operator name via system props.
    val operator =
      try {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        (get.invoke(null, "gsm.operator.alpha") as? String).orEmpty()
      } catch (_: Exception) {
        ""
      }

    if (operator.equals("Android", ignoreCase = true)) {
      return "gsm.operator.alpha=Android"
    }
    return null
  }
}
