#import "ThreatScoring.h"

#import "FortressThreatResult.h"

#include "fortress_crypto.hpp"
#include "fortress_scoring.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace {

fortress::ScoringConfig gScoringConfig;
std::mutex gScoringMutex;

fortress::Severity severityFromString(NSString * _Nullable value) {
  if (value == nil) {
    return fortress::Severity::Unknown;
  }
  return fortress::parseSeverity([value UTF8String]);
}

fortress::ScoringConfig currentConfig() {
  std::lock_guard<std::mutex> lock(gScoringMutex);
  return gScoringConfig;
}

std::vector<fortress::Severity> severitiesFromThreats(NSArray<FortressThreatResult *> *threats) {
  std::vector<fortress::Severity> values;
  values.reserve(threats.count);
  for (FortressThreatResult *threat in threats) {
    values.push_back(severityFromString(threat.severity));
  }
  return values;
}

} // namespace

@implementation FortressThreatScoring

+ (void)configureWithAloneAt:(NSString *)aloneAt
              countAtOrAbove:(NSString *)countAtOrAbove
              countThreshold:(NSInteger)countThreshold
{
  std::lock_guard<std::mutex> lock(gScoringMutex);
  if (aloneAt.length > 0) {
    gScoringConfig.aloneThreshold = severityFromString(aloneAt);
  }
  if (countAtOrAbove.length > 0) {
    gScoringConfig.countMinSeverity = severityFromString(countAtOrAbove);
  }
  if (countThreshold > 0) {
    gScoringConfig.countThreshold = static_cast<int>(countThreshold);
  }
}

+ (void)resetConfig
{
  std::lock_guard<std::mutex> lock(gScoringMutex);
  gScoringConfig = fortress::ScoringConfig{};
}

+ (BOOL)isCompromisedWithThreats:(NSArray<FortressThreatResult *> *)threats
{
  if (threats.count == 0) {
    return NO;
  }
  return fortress::isCompromised(severitiesFromThreats(threats), currentConfig()) ? YES : NO;
}

+ (NSInteger)confidenceWithThreats:(NSArray<FortressThreatResult *> *)threats
{
  if (threats.count == 0) {
    return 0;
  }
  return fortress::evaluate(severitiesFromThreats(threats), currentConfig()).confidence;
}

+ (BOOL)constantTimeEquals:(NSString *)left with:(NSString *)right
{
  const char *leftChars = left.UTF8String ?: "";
  const char *rightChars = right.UTF8String ?: "";
  return fortress::constantTimeEquals(std::string(leftChars), std::string(rightChars)) ? YES : NO;
}

+ (BOOL)constantTimeEqualsNormalizedHex:(NSString *)left with:(NSString *)right
{
  const char *leftChars = left.UTF8String ?: "";
  const char *rightChars = right.UTF8String ?: "";
  return fortress::constantTimeEqualsNormalizedHex(std::string(leftChars), std::string(rightChars))
             ? YES
             : NO;
}

+ (BOOL)constantTimeContains:(NSString *)candidate in:(NSArray<NSString *> *)allowed
{
  std::vector<std::string> pins;
  pins.reserve(allowed.count);
  for (NSString *entry in allowed) {
    pins.emplace_back(entry.UTF8String ?: "");
  }
  const char *candidateChars = candidate.UTF8String ?: "";
  return fortress::constantTimeContains(std::string(candidateChars), pins) ? YES : NO;
}

@end
