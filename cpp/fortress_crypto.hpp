#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace fortress {

/** Constant-time equality for arbitrary byte strings of equal length. */
bool constantTimeEquals(const unsigned char *a, const unsigned char *b, std::size_t length) noexcept;

/** Constant-time equality for std::string (false if lengths differ). */
bool constantTimeEquals(const std::string &a, const std::string &b) noexcept;

/**
 * Normalize hex digests for comparison: lowercase, strip ':' and whitespace.
 * Non-hex characters are preserved lowercased (callers should pass hex).
 */
std::string normalizeHex(const std::string &input);

/** Normalize both sides then constant-time compare. */
bool constantTimeEqualsNormalizedHex(const std::string &a, const std::string &b) noexcept;

/**
 * True if `candidate` matches any entry in `allowed` using constant-time compare.
 * Does not short-circuit on first match for timing safety across the set.
 */
bool constantTimeContains(
    const std::string &candidate,
    const std::vector<std::string> &allowed) noexcept;

} // namespace fortress
