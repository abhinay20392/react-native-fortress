package com.fortress

import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.fortress.root.ThreatResult

/**
 * Post-detector tuning: allowlist drop, severity overrides, emit fingerprint.
 */
internal object ThreatTuning {
  fun parseAllowlist(raw: ReadableArray?): Set<String> {
    if (raw == null) {
      return emptySet()
    }
    val next = mutableSetOf<String>()
    for (index in 0 until raw.size()) {
      val value = raw.getString(index)?.trim()?.lowercase().orEmpty()
      if (value.isNotEmpty()) {
        next.add(value)
      }
    }
    return next
  }

  fun parseSeverityOverrides(raw: ReadableMap?): Map<String, String> {
    if (raw == null) {
      return emptyMap()
    }
    val next = mutableMapOf<String, String>()
    val iterator = raw.keySetIterator()
    while (iterator.hasNextKey()) {
      val key = iterator.nextKey()
      val value = raw.getString(key)?.trim()?.lowercase().orEmpty()
      if (key.isNotBlank() && value in setOf("low", "medium", "high", "critical")) {
        next[key.trim().lowercase()] = value
      }
    }
    return next
  }

  fun apply(
    threats: List<ThreatResult>,
    allowlist: Set<String>,
    severityOverrides: Map<String, String>,
  ): List<ThreatResult> {
    if (threats.isEmpty()) {
      return threats
    }

    return threats.mapNotNull { threat ->
      val typeKey = threat.type.lowercase()
      if (typeKey in allowlist) {
        return@mapNotNull null
      }
      val override = severityOverrides[typeKey]
      if (override != null && override != threat.severity) {
        threat.copy(severity = override)
      } else {
        threat
      }
    }
  }

  fun fingerprint(threats: List<ThreatResult>): String {
    return threats
      .map { "${it.type.lowercase()}:${it.severity.lowercase()}:${it.code.orEmpty()}" }
      .sorted()
      .joinToString("|")
  }
}
