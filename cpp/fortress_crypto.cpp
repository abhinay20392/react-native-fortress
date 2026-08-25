#include "fortress_crypto.hpp"

#include <cctype>

namespace fortress {

bool constantTimeEquals(
    const unsigned char *a,
    const unsigned char *b,
    std::size_t length) noexcept {
  if (a == nullptr || b == nullptr) {
    return a == b && length == 0;
  }

  unsigned char diff = 0;
  for (std::size_t i = 0; i < length; ++i) {
    diff = static_cast<unsigned char>(diff | (a[i] ^ b[i]));
  }
  return diff == 0;
}

bool constantTimeEquals(const std::string &a, const std::string &b) noexcept {
  if (a.size() != b.size()) {
    // Still walk the longer string to reduce length-oracle sharpness for callers
    // that only care about digest equality of fixed-size hashes.
    const std::string &longer = a.size() > b.size() ? a : b;
    unsigned char sink = 0;
    for (unsigned char ch : longer) {
      sink = static_cast<unsigned char>(sink | ch);
    }
    (void)sink;
    return false;
  }

  return constantTimeEquals(
      reinterpret_cast<const unsigned char *>(a.data()),
      reinterpret_cast<const unsigned char *>(b.data()),
      a.size());
}

std::string normalizeHex(const std::string &input) {
  std::string out;
  out.reserve(input.size());
  for (unsigned char ch : input) {
    if (ch == ':' || std::isspace(ch) != 0) {
      continue;
    }
    out.push_back(static_cast<char>(std::tolower(ch)));
  }
  return out;
}

bool constantTimeEqualsNormalizedHex(
    const std::string &a,
    const std::string &b) noexcept {
  return constantTimeEquals(normalizeHex(a), normalizeHex(b));
}

bool constantTimeContains(
    const std::string &candidate,
    const std::vector<std::string> &allowed) noexcept {
  unsigned char matched = 0;
  for (const std::string &entry : allowed) {
    const bool eq = constantTimeEquals(candidate, entry);
    matched = static_cast<unsigned char>(matched | static_cast<unsigned char>(eq ? 1 : 0));
  }
  return matched != 0;
}

} // namespace fortress
