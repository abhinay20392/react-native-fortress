package com.fortress.ssl

import android.util.Log
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import com.fortress.root.ThreatResult
import java.io.IOException
import java.util.concurrent.Executors
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request

object SslPinningManager : OkHttpClientFactory {
  private const val TAG = "FortressSsl"

  private val executor = Executors.newSingleThreadExecutor()
  private val lock = Any()

  @Volatile
  private var pinEntries: List<SslPinEntry> = emptyList()

  @Volatile
  private var configured = false

  fun isConfigured(): Boolean = configured

  fun configure(pins: ReadableArray) {
    val nextEntries = mutableListOf<SslPinEntry>()

    for (index in 0 until pins.size()) {
      val pinMap = pins.getMap(index) ?: continue
      val host = pinMap.getString("host")?.trim().orEmpty()
      if (host.isEmpty()) {
        continue
      }

      val hashesArray = pinMap.getArray("publicKeyHashes") ?: continue
      val hashes = mutableListOf<String>()
      for (hashIndex in 0 until hashesArray.size()) {
        val hash = hashesArray.getString(hashIndex)?.trim().orEmpty()
        if (hash.isNotEmpty()) {
          hashes.add(normalizePinHash(hash))
        }
      }

      if (hashes.isEmpty()) {
        continue
      }

      val includeSubdomains =
        pinMap.hasKey("includeSubdomains") && pinMap.getBoolean("includeSubdomains")

      nextEntries.add(
        SslPinEntry(
          host = host,
          publicKeyHashes = hashes,
          includeSubdomains = includeSubdomains,
        )
      )
    }

    synchronized(lock) {
      pinEntries = nextEntries.toList()
      configured = pinEntries.isNotEmpty()
      OkHttpClientProvider.setOkHttpClientFactory(this)
      resetCachedClient()
    }

    Log.i(TAG, "Configured SSL pinning for ${pinEntries.size} host(s)")
  }

  override fun createNewNetworkModuleClient(): OkHttpClient {
    val builder = OkHttpClientProvider.createClientBuilder()
    buildCertificatePinner()?.let { builder.certificatePinner(it) }
    return builder.build()
  }

  fun createPinnedClient(): OkHttpClient {
    return createNewNetworkModuleClient()
  }

  fun performPinnedRequest(
    url: String,
    promise: Promise,
    reactContext: ReactApplicationContext,
    emitThreat: (ThreatResult) -> Unit,
  ) {
    if (!configured) {
      promise.reject("E_SSL_PINNING", "SSL pinning is not configured. Call configureSslPinning first.")
      return
    }

    executor.execute {
      try {
        val request = Request.Builder().url(url).get().build()
        createPinnedClient().newCall(request).execute().use { response ->
          val body = response.body?.string().orEmpty()
          val result: WritableMap =
            com.facebook.react.bridge.Arguments.createMap().apply {
              putBoolean("ok", response.isSuccessful)
              putInt("status", response.code)
              putString("url", url)
              putString("body", body)
              putBoolean("pinned", true)
              putBoolean("sslPinVerified", true)
            }
          promise.resolve(result)
        }
      } catch (error: IOException) {
        val message = error.message ?: "SSL pinning validation failed"
        val threat =
          ThreatResult(
            type = "ssl_pin_failure",
            severity = "high",
            message = "Pinned request failed for $url: $message",
          )
        emitThreat(threat)
        reactContext.runOnUiQueueThread {
          promise.reject("E_SSL_PIN_FAILURE", message, error)
        }
      } catch (error: Exception) {
        reactContext.runOnUiQueueThread {
          promise.reject("E_SSL_REQUEST", error.message, error)
        }
      }
    }
  }

  private fun buildCertificatePinner(): CertificatePinner? {
    if (pinEntries.isEmpty()) {
      return null
    }

    val builder = CertificatePinner.Builder()
    pinEntries.forEach { entry ->
      entry.publicKeyHashes.forEach { hash ->
        builder.add(entry.host, hash)
        if (entry.includeSubdomains) {
          builder.add("*.${entry.host}", hash)
        }
      }
    }

    return builder.build()
  }

  private fun resetCachedClient() {
    try {
      val field = OkHttpClientProvider::class.java.getDeclaredField("client")
      field.isAccessible = true
      field.set(null, null)
    } catch (error: Exception) {
      Log.w(TAG, "Unable to reset OkHttp client cache: ${error.message}")
    }
  }

  private fun normalizePinHash(hash: String): String {
    return if (hash.startsWith("sha256/")) {
      hash
    } else {
      "sha256/$hash"
    }
  }
}
