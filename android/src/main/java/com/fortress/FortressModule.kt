package com.fortress

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.fortress.root.ThreatResult
import com.fortress.ssl.SslPinningManager

class FortressModule(reactContext: ReactApplicationContext) :
  NativeFortressSpec(reactContext) {

  private val orchestrator = ThreatOrchestrator(reactContext)

  override fun configure(config: ReadableMap, promise: Promise) {
    orchestrator.configure(config)
    promise.resolve(null)
  }

  override fun startMonitoring(promise: Promise) {
    orchestrator.setMonitoring(true)
    promise.resolve(null)
  }

  override fun stopMonitoring(promise: Promise) {
    orchestrator.setMonitoring(false)
    promise.resolve(null)
  }

  override fun runChecks(promise: Promise) {
    val threats = orchestrator.runAllChecks()
    val payload = Arguments.createArray()
    threats.forEach { threat ->
      payload.pushMap(threatToMap(threat))
    }
    // Enforce onCriticalThreat for on-demand checks too (not only background polls).
    orchestrator.respondToThreats(threats)
    promise.resolve(payload)
  }

  override fun isDeviceCompromised(promise: Promise) {
    promise.resolve(orchestrator.isDeviceCompromised())
  }

  override fun configureSslPinning(pins: ReadableArray, promise: Promise) {
    try {
      SslPinningManager.configure(pins)
      promise.resolve(null)
    } catch (error: Exception) {
      promise.reject("E_SSL_PINNING", error.message, error)
    }
  }

  override fun performPinnedRequest(url: String, promise: Promise) {
    SslPinningManager.performPinnedRequest(
      url = url,
      promise = promise,
      reactContext = reactApplicationContext,
      emitThreat = { threat -> emitThreatEvent(threat) },
    )
  }

  override fun getStatus(promise: Promise) {
    val status: WritableMap = Arguments.createMap()
    status.putBoolean("monitoring", orchestrator.isMonitoring)
    status.putBoolean("configured", orchestrator.configured)
    status.putBoolean("sslPinningConfigured", SslPinningManager.isConfigured())
    status.putString("platform", "android")
    status.putString("version", LibraryInfo.VERSION)
    status.putDouble("pollIntervalMs", orchestrator.configuredPollIntervalMs.toDouble())
    if (orchestrator.lastPollAt > 0) {
      status.putDouble("lastPollAt", orchestrator.lastPollAt.toDouble())
    }
    status.putInt("lastThreatCount", orchestrator.lastThreats.size)
    promise.resolve(status)
  }

  override fun showBlockOverlay(message: String, promise: Promise) {
    try {
      orchestrator.showBlockOverlay(message)
      promise.resolve(null)
    } catch (error: Exception) {
      promise.reject("E_BLOCK_UI", error.message, error)
    }
  }

  override fun addListener(eventName: String) {
    // Required for NativeEventEmitter; events are emitted via RCTDeviceEventEmitter.
  }

  override fun removeListeners(count: Double) {
    // Required for NativeEventEmitter.
  }

  override fun invalidate() {
    orchestrator.destroy()
    super.invalidate()
  }

  private fun emitThreatEvent(threat: ThreatResult) {
    reactApplicationContext.emitDeviceEvent(
      ThreatOrchestrator.EVENT_NAME,
      threatToMap(threat),
    )
  }

  private fun threatToMap(threat: ThreatResult): WritableMap {
    val map = Arguments.createMap()
    map.putString("type", threat.type)
    map.putString("severity", threat.severity)
    map.putString("message", threat.message)
    map.putString("platform", "android")
    map.putDouble("timestamp", System.currentTimeMillis().toDouble())
    return map
  }

  companion object {
    const val NAME = NativeFortressSpec.NAME
  }
}
