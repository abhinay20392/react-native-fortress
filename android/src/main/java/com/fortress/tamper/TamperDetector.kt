package com.fortress.tamper

import android.os.Debug
import com.fortress.ThreatScoring
import com.fortress.root.ThreatResult
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

object TamperDetector {
  private val FRIDA_MAP_SIGNATURES =
    listOf("frida", "gum-js", "linjector", "frida-agent", "frida-gadget")

  private val HOOK_MAP_SIGNATURES =
    listOf("xposed", "lsposed", "edxp", "substrate", "riru", "zygisk")

  private val FRIDA_PORTS = listOf(27042, 27043, 27049)

  private val XPOSED_CLASSES =
    listOf(
      "de.robv.android.xposed.XposedBridge",
      "de.robv.android.xposed.XposedHelpers",
      "org.lsposed.lspd.core.Main",
      "io.github.lsposed.lspd.core.Main",
    )

  fun runChecks(): List<ThreatResult> {
    val threats = mutableListOf<ThreatResult>()

    checkFridaMaps()?.let { threats.add(it) }
    checkFridaPorts()?.let { threats.add(it) }
    checkDebugger()?.let { threats.add(it) }
    checkTracerPid()?.let { threats.add(it) }
    checkHookFrameworks()?.let { threats.add(it) }
    checkHookMaps()?.let { threats.add(it) }

    return threats
  }

  fun isCompromised(threats: List<ThreatResult> = runChecks()): Boolean {
    return ThreatScoring.isCompromised(threats)
  }

  private fun checkFridaMaps(): ThreatResult? {
    val mapsFile = File("/proc/self/maps")
    if (!mapsFile.canRead()) {
      return null
    }

    val found = mutableSetOf<String>()
    mapsFile.forEachLine { line ->
      val lower = line.lowercase()
      for (signature in FRIDA_MAP_SIGNATURES) {
        if (lower.contains(signature)) {
          found.add(signature)
        }
      }
    }

    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "frida",
      severity = "critical",
      message = "Frida indicators in /proc/self/maps: ${found.joinToString(", ")}",
    )
  }

  private fun checkFridaPorts(): ThreatResult? {
    val openPorts = mutableListOf<Int>()

    for (port in FRIDA_PORTS) {
      try {
        Socket().use { socket ->
          socket.connect(InetSocketAddress("127.0.0.1", port), 200)
          openPorts.add(port)
        }
      } catch (_: Exception) {
        // Port closed — expected on clean devices
      }
    }

    if (openPorts.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "frida",
      severity = "high",
      message = "Frida default port(s) open on localhost: ${openPorts.joinToString(", ")}",
    )
  }

  private fun checkDebugger(): ThreatResult? {
    if (!Debug.isDebuggerConnected()) {
      return null
    }

    return ThreatResult(
      type = "debugger",
      severity = "high",
      message = "Debugger is attached (Debug.isDebuggerConnected)",
    )
  }

  private fun checkTracerPid(): ThreatResult? {
    val statusFile = File("/proc/self/status")
    if (!statusFile.canRead()) {
      return null
    }

    BufferedReader(FileReader(statusFile)).use { reader ->
      reader.lineSequence().forEach { line ->
        if (line.startsWith("TracerPid:")) {
          val tracerPid = line.substringAfter(":").trim().toIntOrNull() ?: 0
          if (tracerPid > 0) {
            return ThreatResult(
              type = "debugger",
              severity = "high",
              message = "TracerPid is $tracerPid in /proc/self/status",
            )
          }
        }
      }
    }

    return null
  }

  private fun checkHookFrameworks(): ThreatResult? {
    val found = mutableListOf<String>()

    for (className in XPOSED_CLASSES) {
      try {
        Class.forName(className)
        found.add(className)
      } catch (_: ClassNotFoundException) {
        // Expected on clean devices
      }
    }

    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "hooking",
      severity = "critical",
      message = "Hook framework classes present: ${found.joinToString(", ")}",
    )
  }

  private fun checkHookMaps(): ThreatResult? {
    val mapsFile = File("/proc/self/maps")
    if (!mapsFile.canRead()) {
      return null
    }

    val found = mutableSetOf<String>()
    mapsFile.forEachLine { line ->
      val lower = line.lowercase()
      for (signature in HOOK_MAP_SIGNATURES) {
        if (lower.contains(signature)) {
          found.add(signature)
        }
      }
    }

    if (found.isEmpty()) {
      return null
    }

    return ThreatResult(
      type = "hooking",
      severity = "high",
      message = "Hook framework libraries in memory maps: ${found.joinToString(", ")}",
    )
  }
}
