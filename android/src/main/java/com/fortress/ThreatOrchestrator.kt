package com.fortress

import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.fortress.emulator.EmulatorDetector
import com.fortress.repackaging.RepackagingDetector
import com.fortress.root.RootDetector
import com.fortress.root.ThreatResult
import com.fortress.tamper.TamperDetector

typealias ThreatEmitter = (ThreatResult) -> Unit

class ThreatOrchestrator(
  private val reactContext: ReactApplicationContext,
  private val emitThreat: ThreatEmitter = { threat ->
    reactContext.emitDeviceEvent(EVENT_NAME, threatToMap(reactContext, threat))
  },
) {
  private val handlerThread = HandlerThread("FortressPoll").apply { start() }
  private val handler = Handler(handlerThread.looper)

  private var pollIntervalMs = 30_000L
  private var monitoring = false
  private var checksRoot = true
  private var checksTamper = true
  private var checksEmulator = false
  private var checksRepackaging = false
  private var onCriticalThreat = "log"

  val isMonitoring: Boolean
    get() = monitoring

  val configuredPollIntervalMs: Long
    get() = pollIntervalMs

  var lastPollAt: Long = 0
    private set
  var lastThreats: List<ThreatResult> = emptyList()
    private set

  var configured = false
    private set

  private val pollRunnable =
    object : Runnable {
      override fun run() {
        if (!monitoring) {
          return
        }

        val threats = runAllChecks()
        lastPollAt = System.currentTimeMillis()
        lastThreats = threats

        if (threats.isNotEmpty()) {
          handleThreats(threats)
        }

        handler.postDelayed(this, pollIntervalMs)
      }
    }

  fun configure(config: ReadableMap) {
    configured = true

    if (config.hasKey("monitor") && config.getBoolean("monitor")) {
      monitoring = true
    }

    if (config.hasKey("pollIntervalMs")) {
      pollIntervalMs = config.getDouble("pollIntervalMs").toLong().coerceAtLeast(5_000L)
    }

    if (config.hasKey("checks")) {
      val checks = config.getMap("checks")
      if (checks != null) {
        if (checks.hasKey("root")) {
          checksRoot = checks.getBoolean("root")
        }
        if (checks.hasKey("tamper")) {
          checksTamper = checks.getBoolean("tamper")
        }
        if (checks.hasKey("emulator")) {
          checksEmulator = checks.getBoolean("emulator")
        }
        if (checks.hasKey("repackaging")) {
          checksRepackaging = checks.getBoolean("repackaging")
        }
      }
    }

    if (config.hasKey("expectedSigningCertificateSha256")) {
      RepackagingDetector.configure(config.getString("expectedSigningCertificateSha256"))
    }

    if (config.hasKey("onCriticalThreat")) {
      onCriticalThreat = config.getString("onCriticalThreat") ?: "log"
    }

    if (monitoring) {
      startPolling()
    }
  }

  fun setMonitoring(enabled: Boolean) {
    monitoring = enabled
    if (enabled) {
      startPolling()
    } else {
      stopPolling()
    }
  }

  fun runIntegrityChecks(): List<ThreatResult> {
    if (!checksRoot) {
      return emptyList()
    }

    return RootDetector.runChecks()
  }

  fun runTamperChecks(): List<ThreatResult> {
    if (!checksTamper) {
      return emptyList()
    }

    return TamperDetector.runChecks()
  }

  fun runEmulatorChecks(): List<ThreatResult> {
    if (!checksEmulator) {
      return emptyList()
    }

    return EmulatorDetector.runChecks()
  }

  fun runRepackagingChecks(): List<ThreatResult> {
    if (!checksRepackaging || !RepackagingDetector.isEnabled()) {
      return emptyList()
    }

    return RepackagingDetector.runChecks(reactContext)
  }

  fun runAllChecks(): List<ThreatResult> {
    val threats = mutableListOf<ThreatResult>()
    threats.addAll(runIntegrityChecks())
    threats.addAll(runTamperChecks())
    threats.addAll(runEmulatorChecks())
    threats.addAll(runRepackagingChecks())
    return threats
  }

  fun isDeviceCompromised(): Boolean {
    return ThreatScoring.isCompromised(runAllChecks())
  }

  fun destroy() {
    stopPolling()
    handlerThread.quitSafely()
  }

  private fun startPolling() {
    handler.removeCallbacks(pollRunnable)
    handler.post(pollRunnable)
  }

  private fun stopPolling() {
    handler.removeCallbacks(pollRunnable)
  }

  private fun handleThreats(threats: List<ThreatResult>) {
    val hasCritical = threats.any { it.severity == "critical" }
    val hasHigh = threats.any { it.severity == "high" }

    threats.forEach { threat ->
      emitThreat(threat)
    }

    when (onCriticalThreat) {
      // v1.x: exit triggers on high OR critical (name is historical).
      // v2 will split this via exitOn — see docs/V2_ROADMAP.md M3.1.
      "exit" -> {
        if (hasCritical || hasHigh) {
          Log.e(TAG, "High/critical threat detected — exiting (onCriticalThreat=exit)")
          android.os.Process.killProcess(android.os.Process.myPid())
        }
      }
      "block_ui" -> {
        if (hasCritical || hasHigh) {
          Log.w(TAG, "High/critical threat detected — block_ui not yet implemented")
        }
      }
      else -> {
        threats.forEach { threat ->
          Log.w(TAG, "Threat [${threat.severity}] ${threat.type}: ${threat.message}")
        }
      }
    }
  }

  companion object {
    const val EVENT_NAME = "onFortressThreat"
    private const val TAG = "Fortress"

    fun threatToMap(
      @Suppress("UNUSED_PARAMETER") reactContext: ReactApplicationContext,
      threat: ThreatResult,
    ): WritableMap {
      val map = com.facebook.react.bridge.Arguments.createMap()
      map.putString("type", threat.type)
      map.putString("severity", threat.severity)
      map.putString("message", threat.message)
      map.putString("platform", "android")
      map.putDouble("timestamp", System.currentTimeMillis().toDouble())
      return map
    }
  }
}
