#pragma once

#include <string>
#include <vector>

namespace fortress {

enum class Severity : int {
  Unknown = -1,
  Low = 0,
  Medium = 1,
  High = 2,
  Critical = 3,
};

/**
 * Shared compromise policy for Android + iOS.
 *
 * Defaults match v1.x:
 * - any high/critical alone → compromised
 * - OR any 2+ threats (low+) → compromised
 */
struct ScoringConfig {
  Severity aloneThreshold = Severity::High;
  Severity countMinSeverity = Severity::Low;
  int countThreshold = 2;
};

struct ScoringResult {
  bool compromised = false;
  /** Simple 0–100 confidence derived from severities (corroboration aid). */
  int confidence = 0;
  int aloneHits = 0;
  int countedSignals = 0;
};

Severity parseSeverity(const char *severity) noexcept;
Severity parseSeverity(const std::string &severity) noexcept;

ScoringResult evaluate(
    const std::vector<Severity> &severities,
    const ScoringConfig &config = {}) noexcept;

bool isCompromised(
    const std::vector<Severity> &severities,
    const ScoringConfig &config = {}) noexcept;

} // namespace fortress
