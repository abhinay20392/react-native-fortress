#include "fortress_scoring.hpp"

#include <algorithm>
#include <cctype>

namespace fortress {
namespace {

std::string toLower(const char *input) {
  std::string out;
  if (input == nullptr) {
    return out;
  }
  for (const char *p = input; *p != '\0'; ++p) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(*p))));
  }
  return out;
}

int severityWeight(Severity severity) noexcept {
  switch (severity) {
    case Severity::Critical:
      return 40;
    case Severity::High:
      return 25;
    case Severity::Medium:
      return 10;
    case Severity::Low:
      return 5;
    case Severity::Unknown:
    default:
      return 0;
  }
}

} // namespace

Severity parseSeverity(const char *severity) noexcept {
  const std::string value = toLower(severity);
  if (value == "low") {
    return Severity::Low;
  }
  if (value == "medium") {
    return Severity::Medium;
  }
  if (value == "high") {
    return Severity::High;
  }
  if (value == "critical") {
    return Severity::Critical;
  }
  return Severity::Unknown;
}

Severity parseSeverity(const std::string &severity) noexcept {
  return parseSeverity(severity.c_str());
}

ScoringResult evaluate(
    const std::vector<Severity> &severities,
    const ScoringConfig &config) noexcept {
  ScoringResult result;

  if (severities.empty()) {
    return result;
  }

  const int aloneFloor = static_cast<int>(config.aloneThreshold);
  const int countFloor = static_cast<int>(config.countMinSeverity);
  const int threshold = std::max(1, config.countThreshold);

  int confidence = 0;
  for (const Severity severity : severities) {
    if (severity == Severity::Unknown) {
      continue;
    }

    const int rank = static_cast<int>(severity);
    confidence += severityWeight(severity);

    if (rank >= aloneFloor) {
      result.aloneHits += 1;
    }
    if (rank >= countFloor) {
      result.countedSignals += 1;
    }
  }

  result.confidence = std::min(100, confidence);
  result.compromised =
      result.aloneHits > 0 || result.countedSignals >= threshold;
  return result;
}

bool isCompromised(
    const std::vector<Severity> &severities,
    const ScoringConfig &config) noexcept {
  return evaluate(severities, config).compromised;
}

} // namespace fortress
