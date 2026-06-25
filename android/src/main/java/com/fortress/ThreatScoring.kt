package com.fortress

import com.fortress.root.ThreatResult

object ThreatScoring {
  fun isCompromised(threats: List<ThreatResult>): Boolean {
    if (threats.isEmpty()) {
      return false
    }

    if (threats.any { it.severity == "high" || it.severity == "critical" }) {
      return true
    }

    return threats.size >= 2
  }
}
