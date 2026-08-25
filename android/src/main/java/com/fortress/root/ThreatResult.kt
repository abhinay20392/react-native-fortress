package com.fortress.root

data class ThreatResult(
  val type: String,
  val severity: String,
  val message: String,
  val code: String? = null,
  val detector: String? = null,
  val evidence: Map<String, Any>? = null,
)
