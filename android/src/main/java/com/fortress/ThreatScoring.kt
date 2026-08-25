package com.fortress

import com.fortress.root.ThreatResult

/**
 * Thin Kotlin facade over the shared C++ scoring core (`cpp/fortress_scoring.cpp`).
 * All compromise decisions must go through here — not JS and not duplicated platform logic.
 */
object ThreatScoring {
  data class Config(
    /** Any threat at or above this severity alone → compromised. Default: high. */
    val aloneAt: String = "high",
    /**
     * Count threats at or above this severity toward aggregate compromise.
     * Default: low (v1 parity). Use `"medium"` for “N medium signals”.
     */
    val countAtOrAbove: String = "low",
    /** Aggregate count threshold. Default: 2. */
    val countThreshold: Int = 2,
  )

  @Volatile
  private var config: Config = Config()

  init {
    System.loadLibrary("fortress")
  }

  fun configure(
    aloneAt: String? = null,
    countAtOrAbove: String? = null,
    countThreshold: Int? = null,
  ) {
    val current = config
    config =
      Config(
        aloneAt = aloneAt?.takeIf { it.isNotBlank() } ?: current.aloneAt,
        countAtOrAbove = countAtOrAbove?.takeIf { it.isNotBlank() } ?: current.countAtOrAbove,
        countThreshold = countThreshold?.coerceAtLeast(1) ?: current.countThreshold,
      )
  }

  fun resetConfig() {
    config = Config()
  }

  fun isCompromised(threats: List<ThreatResult>): Boolean {
    if (threats.isEmpty()) {
      return false
    }
    val cfg = config
    return nativeIsCompromised(
      threats.map { it.severity }.toTypedArray(),
      severityRank(cfg.aloneAt),
      severityRank(cfg.countAtOrAbove),
      cfg.countThreshold,
    )
  }

  /** Corroboration aid: C++ confidence 0–100 for the same threat set. */
  fun confidence(threats: List<ThreatResult>): Int {
    if (threats.isEmpty()) {
      return 0
    }
    val cfg = config
    return nativeConfidence(
      threats.map { it.severity }.toTypedArray(),
      severityRank(cfg.aloneAt),
      severityRank(cfg.countAtOrAbove),
      cfg.countThreshold,
    )
  }

  fun constantTimeEquals(left: String, right: String): Boolean {
    return nativeConstantTimeEquals(left, right)
  }

  fun constantTimeEqualsNormalizedHex(left: String, right: String): Boolean {
    return nativeConstantTimeEqualsNormalizedHex(left, right)
  }

  private fun severityRank(value: String): Int {
    return when (value.lowercase()) {
      "low" -> 0
      "medium" -> 1
      "high" -> 2
      "critical" -> 3
      else -> 2
    }
  }

  @JvmStatic
  private external fun nativeIsCompromised(
    severities: Array<String>,
    aloneThreshold: Int,
    countMinSeverity: Int,
    countThreshold: Int,
  ): Boolean

  @JvmStatic
  private external fun nativeConfidence(
    severities: Array<String>,
    aloneThreshold: Int,
    countMinSeverity: Int,
    countThreshold: Int,
  ): Int

  @JvmStatic
  private external fun nativeConstantTimeEquals(left: String, right: String): Boolean

  @JvmStatic
  private external fun nativeConstantTimeEqualsNormalizedHex(left: String, right: String): Boolean
}
