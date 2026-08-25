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
    try {
      orchestrator.configure(config)
      promise.resolve(null)
    } catch (error: IllegalArgumentException) {
      promise.reject("E_CONFIG", error.message, error)
    } catch (error: Exception) {
      promise.reject("E_CONFIG", error.message, error)
    }
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
    orchestrator.respondToThreats(threats)
    promise.resolve(payload)
  }

  override fun isDeviceCompromised(promise: Promise) {
    promise.resolve(orchestrator.isDeviceCompromised())
  }

  override fun getThreatConfidence(promise: Promise) {
    promise.resolve(orchestrator.getThreatConfidence())
  }

  override fun configureSslPinning(pins: ReadableArray, promise: Promise) {
    try {
      SslPinningManager.configure(pins)
      promise.resolve(null)
    } catch (error: Exception) {
      promise.reject("E_SSL_PINNING", error.message, error)
    }
  }

  override fun performPinnedRequest(options: ReadableMap, promise: Promise) {
    SslPinningManager.performPinnedRequest(
      options = options,
      promise = promise,
      reactContext = reactApplicationContext,
      emitThreat = { threat -> emitThreatEvent(threat) },
    )
  }

  override fun getSslPinningStatus(promise: Promise) {
    promise.resolve(SslPinningManager.pinningStatus())
  }

  override fun getStatus(promise: Promise) {
    val status: WritableMap = Arguments.createMap()
    status.putBoolean("monitoring", orchestrator.isMonitoring)
    status.putBoolean("configured", orchestrator.configured)
    status.putBoolean("sslPinningConfigured", SslPinningManager.isConfigured())
    status.putString("platform", "android")
    status.putString("version", LibraryInfo.VERSION)
    status.putString("exitOn", orchestrator.configuredExitOn)
    orchestrator.configuredMode?.let { status.putString("mode", it) }
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
    return ThreatOrchestrator.threatToMap(reactApplicationContext, threat)
  }

  companion object {
    const val NAME = NativeFortressSpec.NAME
  }
}
