package com.fortress.ssl

import android.util.Log
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.network.OkHttpClientFactory
import com.facebook.react.modules.network.OkHttpClientProvider
import com.fortress.root.ThreatResult
import java.io.IOException
import java.util.concurrent.Executors
import javax.net.ssl.SSLPeerUnverifiedException
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

object SslPinningManager : OkHttpClientFactory {
  private const val TAG = "FortressSsl"

  private val executor = Executors.newSingleThreadExecutor()
  private val lock = Any()

  @Volatile
  private var pinEntries: List<SslPinEntry> = emptyList()

  @Volatile
  private var configured = false

  @Volatile
  private var factoryInstalled = false

  fun isConfigured(): Boolean = configured

  /** Install OkHttp factory as early as possible (package init). Safe to call repeatedly. */
  fun installEarly() {
    synchronized(lock) {
      OkHttpClientProvider.setOkHttpClientFactory(this)
      factoryInstalled = true
      resetCachedClient()
      Log.i(TAG, "OkHttpClientFactory installed early (pins configured=$configured)")
    }
  }

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
      // Re-assert factory in case another RN networking lib overwrote it.
      OkHttpClientProvider.setOkHttpClientFactory(this)
      factoryInstalled = true
      resetCachedClient()
    }

    Log.i(TAG, "Configured SSL pinning for ${pinEntries.size} host(s)")
  }

  fun pinningStatus(): WritableMap {
    val hosts: WritableArray = Arguments.createArray()
    pinEntries.forEach { entry ->
      val hostMap = Arguments.createMap()
      hostMap.putString("host", entry.host)
      hostMap.putInt("pinCount", entry.publicKeyHashes.size)
      hostMap.putBoolean("includeSubdomains", entry.includeSubdomains)
      hosts.pushMap(hostMap)
    }

    return Arguments.createMap().apply {
      putBoolean("configured", configured)
      putArray("hosts", hosts)
      putBoolean("coversGlobalFetch", true)
      putBoolean("okHttpFactoryInstalled", factoryInstalled)
      putString(
        "platformNote",
        "Android: RN fetch()/XHR use OkHttp when Fortress's OkHttpClientFactory stays installed. " +
          "Call configureSslPinning early; other libs that replace the factory can disable pinning.",
      )
    }
  }

  override fun createNewNetworkModuleClient(): OkHttpClient {
    // Defend against race: another library may have replaced the factory after ours.
    OkHttpClientProvider.setOkHttpClientFactory(this)
    factoryInstalled = true

    val builder = OkHttpClientProvider.createClientBuilder()
    buildCertificatePinner()?.let { builder.certificatePinner(it) }
    return builder.build()
  }

  fun createPinnedClient(): OkHttpClient {
    return createNewNetworkModuleClient()
  }

  fun performPinnedRequest(
    options: ReadableMap,
    promise: Promise,
    reactContext: ReactApplicationContext,
    emitThreat: (ThreatResult) -> Unit,
  ) {
    if (!configured) {
      rejectStructured(
        promise,
        code = "E_SSL_PINNING",
        message = "SSL pinning is not configured. Call configureSslPinning first.",
        reason = "not_configured",
      )
      return
    }

    val url = options.getString("url")?.trim().orEmpty()
    if (url.isEmpty()) {
      rejectStructured(
        promise,
        code = "E_SSL_REQUEST",
        message = "Pinned request requires a non-empty url",
        reason = "invalid_url",
      )
      return
    }

    val method =
      options.getString("method")?.trim()?.uppercase().orEmpty().ifEmpty { "GET" }
    val allowed = setOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
    if (method !in allowed) {
      rejectStructured(
        promise,
        code = "E_SSL_REQUEST",
        message = "Unsupported HTTP method: $method",
        reason = "unsupported_method",
        url = url,
        method = method,
      )
      return
    }

    val bodyText =
      if (options.hasKey("body") && !options.isNull("body")) {
        options.getString("body")
      } else {
        null
      }

    executor.execute {
      try {
        val builder = Request.Builder().url(url)
        if (options.hasKey("headers") && !options.isNull("headers")) {
          val headers = options.getMap("headers")
          if (headers != null) {
            val iterator = headers.keySetIterator()
            while (iterator.hasNextKey()) {
              val key = iterator.nextKey()
              val value = headers.getString(key)
              if (value != null) {
                builder.header(key, value)
              }
            }
          }
        }

        val contentType =
          if (options.hasKey("headers") && !options.isNull("headers")) {
            options.getMap("headers")?.getString("Content-Type")
          } else {
            null
          }
        val mediaType =
          (contentType ?: "application/json; charset=utf-8").toMediaTypeOrNull()
        val requestBody =
          if (method == "GET" || method == "HEAD" || bodyText == null) {
            null
          } else {
            bodyText.toRequestBody(mediaType)
          }

        when (method) {
          "GET" -> builder.get()
          "HEAD" -> builder.head()
          "POST" -> builder.post(requestBody ?: ByteArray(0).toRequestBody(null))
          "PUT" -> builder.put(requestBody ?: ByteArray(0).toRequestBody(null))
          "PATCH" -> builder.patch(requestBody ?: ByteArray(0).toRequestBody(null))
          "DELETE" -> {
            if (requestBody != null) {
              builder.delete(requestBody)
            } else {
              builder.delete()
            }
          }
        }

        createPinnedClient().newCall(builder.build()).execute().use { response ->
          val body = response.body?.string().orEmpty()
          val result: WritableMap =
            Arguments.createMap().apply {
              putBoolean("ok", response.isSuccessful)
              putInt("status", response.code)
              putString("url", url)
              putString("body", body)
              putBoolean("pinned", true)
              putBoolean("sslPinVerified", true)
              putString("method", method)
            }
          promise.resolve(result)
        }
      } catch (error: SSLPeerUnverifiedException) {
        handlePinFailure(url, method, error, promise, reactContext, emitThreat)
      } catch (error: IOException) {
        val pinFailure =
          error is SSLPeerUnverifiedException ||
            error.message?.contains("Certificate pinning failure", ignoreCase = true) == true ||
            error.message?.contains("Pin verification failed", ignoreCase = true) == true

        if (pinFailure) {
          handlePinFailure(url, method, error, promise, reactContext, emitThreat)
        } else {
          reactContext.runOnUiQueueThread {
            rejectStructured(
              promise,
              code = "E_SSL_REQUEST",
              message = "Pinned request failed for $url: ${error.message}",
              reason = "network",
              url = url,
              method = method,
              throwable = error,
            )
          }
        }
      } catch (error: Exception) {
        reactContext.runOnUiQueueThread {
          rejectStructured(
            promise,
            code = "E_SSL_REQUEST",
            message = error.message ?: "Pinned request failed",
            reason = "network",
            url = url,
            method = method,
            throwable = error,
          )
        }
      }
    }
  }

  private fun handlePinFailure(
    url: String,
    method: String,
    error: Exception,
    promise: Promise,
    reactContext: ReactApplicationContext,
    emitThreat: (ThreatResult) -> Unit,
  ) {
    val detail = error.message ?: "SSL pinning validation failed"
    val message =
      "Pinned request failed for $url: $detail. " +
        "Check publicKeyHashes match the cert the app sees (CDN/edge), " +
        "and include a backup pin before certificate rotation."
    val threat =
      ThreatResult(
        type = "ssl_pin_failure",
        severity = "high",
        message = message,
        code = "SSL_PIN_FAILURE",
        detector = "SslPinningManager",
        evidence =
          mapOf(
            "url" to url,
            "method" to method,
            "reason" to "pin_mismatch",
          ),
      )
    emitThreat(threat)
    reactContext.runOnUiQueueThread {
      rejectStructured(
        promise,
        code = "E_SSL_PIN_FAILURE",
        message = message,
        reason = "pin_mismatch",
        url = url,
        method = method,
        throwable = error,
      )
    }
  }

  private fun rejectStructured(
    promise: Promise,
    code: String,
    message: String,
    reason: String,
    url: String? = null,
    method: String? = null,
    throwable: Throwable? = null,
  ) {
    val userInfo =
      Arguments.createMap().apply {
        putString("code", code)
        putString("message", message)
        putString("reason", reason)
        url?.let { putString("url", it) }
        method?.let { putString("method", it) }
      }
    if (throwable != null) {
      promise.reject(code, message, throwable, userInfo)
    } else {
      promise.reject(code, message, userInfo)
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
