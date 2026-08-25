#include <jni.h>

#include <string>
#include <vector>

#include "fortress_crypto.hpp"
#include "fortress_scoring.hpp"

namespace {

fortress::Severity severityFromJString(JNIEnv *env, jstring value) {
  if (value == nullptr) {
    return fortress::Severity::Unknown;
  }
  const char *chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    return fortress::Severity::Unknown;
  }
  const fortress::Severity severity = fortress::parseSeverity(chars);
  env->ReleaseStringUTFChars(value, chars);
  return severity;
}

std::string stringFromJString(JNIEnv *env, jstring value) {
  if (value == nullptr) {
    return {};
  }
  const char *chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    return {};
  }
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

fortress::ScoringConfig configFromInts(
    jint aloneThreshold,
    jint countMinSeverity,
    jint countThreshold) {
  fortress::ScoringConfig config;
  config.aloneThreshold = static_cast<fortress::Severity>(aloneThreshold);
  config.countMinSeverity = static_cast<fortress::Severity>(countMinSeverity);
  config.countThreshold = countThreshold;
  return config;
}

} // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fortress_ThreatScoring_nativeIsCompromised(
    JNIEnv *env,
    jclass /* clazz */,
    jobjectArray severities,
    jint aloneThreshold,
    jint countMinSeverity,
    jint countThreshold) {
  std::vector<fortress::Severity> values;
  if (severities != nullptr) {
    const jsize count = env->GetArrayLength(severities);
    values.reserve(static_cast<std::size_t>(count));
    for (jsize i = 0; i < count; ++i) {
      auto severity = reinterpret_cast<jstring>(env->GetObjectArrayElement(severities, i));
      values.push_back(severityFromJString(env, severity));
      if (severity != nullptr) {
        env->DeleteLocalRef(severity);
      }
    }
  }

  const bool compromised = fortress::isCompromised(
      values,
      configFromInts(aloneThreshold, countMinSeverity, countThreshold));
  return compromised ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fortress_ThreatScoring_nativeConfidence(
    JNIEnv *env,
    jclass /* clazz */,
    jobjectArray severities,
    jint aloneThreshold,
    jint countMinSeverity,
    jint countThreshold) {
  std::vector<fortress::Severity> values;
  if (severities != nullptr) {
    const jsize count = env->GetArrayLength(severities);
    values.reserve(static_cast<std::size_t>(count));
    for (jsize i = 0; i < count; ++i) {
      auto severity = reinterpret_cast<jstring>(env->GetObjectArrayElement(severities, i));
      values.push_back(severityFromJString(env, severity));
      if (severity != nullptr) {
        env->DeleteLocalRef(severity);
      }
    }
  }

  const fortress::ScoringResult result = fortress::evaluate(
      values,
      configFromInts(aloneThreshold, countMinSeverity, countThreshold));
  return static_cast<jint>(result.confidence);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fortress_ThreatScoring_nativeConstantTimeEquals(
    JNIEnv *env,
    jclass /* clazz */,
    jstring left,
    jstring right) {
  const bool equal =
      fortress::constantTimeEquals(stringFromJString(env, left), stringFromJString(env, right));
  return equal ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_fortress_ThreatScoring_nativeConstantTimeEqualsNormalizedHex(
    JNIEnv *env,
    jclass /* clazz */,
    jstring left,
    jstring right) {
  const bool equal = fortress::constantTimeEqualsNormalizedHex(
      stringFromJString(env, left),
      stringFromJString(env, right));
  return equal ? JNI_TRUE : JNI_FALSE;
}
