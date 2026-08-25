#include "fortress_crypto.hpp"
#include "fortress_scoring.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

int gFailures = 0;

void expectTrue(bool condition, const char *label) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", label);
    gFailures += 1;
  } else {
    std::printf("ok: %s\n", label);
  }
}

} // namespace

int main() {
  using fortress::Severity;
  using fortress::ScoringConfig;

  std::printf("--- scoring ---\n");

  expectTrue(!fortress::isCompromised({}), "empty not compromised");
  expectTrue(fortress::isCompromised({Severity::High}), "single high alone");
  expectTrue(fortress::isCompromised({Severity::Critical}), "single critical alone");
  expectTrue(!fortress::isCompromised({Severity::Medium}), "single medium not alone");
  expectTrue(!fortress::isCompromised({Severity::Low}), "single low not alone");
  expectTrue(
      fortress::isCompromised({Severity::Low, Severity::Medium}),
      "two low+ aggregate (v1 default)");

  ScoringConfig mediumOnly;
  mediumOnly.countMinSeverity = Severity::Medium;
  mediumOnly.countThreshold = 2;
  expectTrue(
      !fortress::isCompromised({Severity::Low, Severity::Low}, mediumOnly),
      "lows ignored when countAtOrAbove=medium");
  expectTrue(
      fortress::isCompromised({Severity::Medium, Severity::Medium}, mediumOnly),
      "two mediums with countAtOrAbove=medium");

  ScoringConfig criticalOnly;
  criticalOnly.aloneThreshold = Severity::Critical;
  criticalOnly.countThreshold = 99;
  expectTrue(
      !fortress::isCompromised({Severity::High}, criticalOnly),
      "high ignored when aloneAt=critical");
  expectTrue(
      fortress::isCompromised({Severity::Critical}, criticalOnly),
      "critical still alone");

  const auto result = fortress::evaluate({Severity::High, Severity::Medium});
  expectTrue(result.compromised, "evaluate compromised");
  expectTrue(result.confidence == 35, "confidence high+medium = 35");

  std::printf("--- crypto ---\n");
  expectTrue(fortress::constantTimeEquals("abc", "abc"), "equals");
  expectTrue(!fortress::constantTimeEquals("abc", "abd"), "not equals");
  expectTrue(!fortress::constantTimeEquals("abc", "ab"), "length mismatch");
  expectTrue(
      fortress::constantTimeEqualsNormalizedHex("AA:BB", "aabb"),
      "normalized hex");
  expectTrue(
      fortress::constantTimeContains("pin1", {"x", "pin1", "y"}),
      "contains match");
  expectTrue(
      !fortress::constantTimeContains("pin1", {"x", "y"}),
      "contains miss");

  if (gFailures > 0) {
    std::fprintf(stderr, "%d failure(s)\n", gFailures);
    return EXIT_FAILURE;
  }

  std::printf("all tests passed\n");
  return EXIT_SUCCESS;
}
