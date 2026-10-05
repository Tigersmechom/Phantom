#include "phantom/scalar_codec.hpp"

#include <charconv>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <utility>

namespace phantom {
namespace {
using Json = nlohmann::json;
struct Type {
  bool boolean = false;
  bool floating = false;
  bool isSigned = false;
  unsigned bits = 0;
  std::size_t bytes = 0;
};

bool exactKeys(const Json& value, std::initializer_list<std::string_view> keys) {
  if (!value.is_object() || value.size() != keys.size()) return false;
  for (auto key : keys) if (!value.contains(key)) return false;
  return true;
}

bool integerIs(const Json& value, unsigned expected) {
  if (value.is_number_unsigned()) return value.get<std::uint64_t>() == expected;
  return value.is_number_integer() && value.get<std::int64_t>() == expected;
}

std::optional<Type> parseType(const Json& scalar) {
  if (!exactKeys(scalar, {"kind", "byteSize", "bits", "signed", "byteOrder", "representation"}) ||
      scalar.at("byteOrder") != "little") return std::nullopt;
  Type type;
  for (unsigned bits : {8, 16, 32, 64}) {
    if (integerIs(scalar.at("bits"), bits) && integerIs(scalar.at("byteSize"), bits / 8)) {
      type.bits = bits;
      type.bytes = bits / 8;
      break;
    }
  }
  if (!type.bits) return std::nullopt;
  if (scalar.at("kind") == "boolean") {
    if (type.bits != 8 || !scalar.at("signed").is_null() ||
        scalar.at("representation") != "boolean-01") return std::nullopt;
    type.boolean = true;
  } else if (scalar.at("kind") == "float") {
    if ((type.bits != 32 && type.bits != 64) || !scalar.at("signed").is_null() ||
        scalar.at("representation") != (type.bits == 32 ? "ieee754-binary32" : "ieee754-binary64"))
      return std::nullopt;
    type.floating = true;
  } else if (scalar.at("kind") == "integer") {
    if (!scalar.at("signed").is_boolean()) return std::nullopt;
    type.isSigned = scalar.at("signed").get<bool>();
    if (scalar.at("representation") != (type.isSigned ? "twos-complement" : "unsigned-binary"))
      return std::nullopt;
  } else return std::nullopt;
  return type;
}

std::uint64_t mask(unsigned bits) {
  return bits == 64 ? std::numeric_limits<std::uint64_t>::max() : (std::uint64_t{1} << bits) - 1;
}

bool encode(const Json& scalar, const Json& value, std::string& raw, std::string& reason) {
  const auto type = parseType(scalar);
  if (!type) { reason = "invalid-type"; return false; }
  if (!value.is_object() || !value.contains("kind") || !value.at("kind").is_string()) {
    reason = "invalid-value"; return false;
  }
  if (value.at("kind") != (type->boolean ? "boolean" : type->floating ? "float" : "integer")) {
    reason = "type-mismatch"; return false;
  }
  if (type->boolean) {
    if (!exactKeys(value, {"kind", "value"}) || !value.at("value").is_boolean()) {
      reason = "invalid-value"; return false;
    }
    raw.assign(1, value.at("value").get<bool>() ? '\1' : '\0');
    return true;
  }
  if (type->floating) {
    if (!exactKeys(value, {"kind", "bits", "rawBitsHex"}) || !value.at("rawBitsHex").is_string()) {
      reason = "invalid-value"; return false;
    }
    if (!integerIs(value.at("bits"), type->bits)) {
      reason = "type-mismatch"; return false;
    }
    const auto& text = value.at("rawBitsHex").get_ref<const std::string&>();
    if (text.size() != type->bytes * 2 || text.find_first_not_of("0123456789abcdef") != std::string::npos) {
      reason = "invalid-value"; return false;
    }
    const auto nibble = [](char digit) -> unsigned { return digit <= '9' ? digit - '0' : digit - 'a' + 10; };
    raw.resize(type->bytes);
    for (std::size_t i = 0; i < type->bytes; ++i) {
      const auto offset = (type->bytes - i - 1) * 2;
      raw[i] = static_cast<char>((nibble(text[offset]) << 4) | nibble(text[offset + 1]));
    }
    return true;
  }
  if (!exactKeys(value, {"kind", "decimal", "bits", "signed"}) ||
      !value.at("decimal").is_string() || !value.at("signed").is_boolean()) {
    reason = "invalid-value"; return false;
  }
  if (!integerIs(value.at("bits"), type->bits) || value.at("signed").get<bool>() != type->isSigned) {
    reason = "type-mismatch"; return false;
  }
  const auto& text = value.at("decimal").get_ref<const std::string&>();
  const bool negative = !text.empty() && text.front() == '-';
  const auto digits = std::string_view(text).substr(negative ? 1 : 0);
  if (digits.empty() || digits.find_first_not_of("0123456789") != std::string_view::npos ||
      (digits.front() == '0' && (digits.size() != 1 || negative))) {
    reason = "invalid-value"; return false;
  }
  if (negative && !type->isSigned) { reason = "out-of-range"; return false; }
  std::uint64_t magnitude = 0;
  const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), magnitude, 10);
  if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) {
    reason = "out-of-range"; return false;
  }
  const auto limit = type->isSigned ?
      (std::uint64_t{1} << (type->bits - 1)) - (negative ? 0 : 1) : mask(type->bits);
  if (magnitude > limit) { reason = "out-of-range"; return false; }
  const std::uint64_t encoded = negative ? std::uint64_t{0} - magnitude : magnitude;
  raw.resize(type->bytes);
  for (std::size_t i = 0; i < type->bytes; ++i)
    raw[i] = static_cast<char>((encoded >> (i * 8)) & 0xff);
  return true;
}
}  // namespace

bool encodeScalarStorage(const Json& scalar, const Json& value,
                         std::string& raw, std::string& reason) noexcept {
  raw.clear(); reason.clear();
  try {
    return encode(scalar, value, raw, reason);
  } catch (...) {
    raw.clear();
    // Even allocation failures cannot escape this codec. The reason may be
    // empty only if allocating the fixed diagnostic also fails.
    try { reason = "invalid-value"; } catch (...) { reason.clear(); }
    return false;
  }
}

std::optional<Json> decodeScalarStorage(const Json& scalar, std::string_view raw) noexcept {
  try {
    const auto type = parseType(scalar);
    if (!type || raw.size() != type->bytes) return std::nullopt;
    if (type->floating) {
      constexpr char digits[] = "0123456789abcdef";
      std::string bits(type->bytes * 2, '0');
      for (std::size_t i = 0; i < type->bytes; ++i) {
        const auto byte = static_cast<unsigned char>(raw[type->bytes - i - 1]);
        bits[i * 2] = digits[byte >> 4];
        bits[i * 2 + 1] = digits[byte & 15];
      }
      return Json{{"kind", "float"}, {"bits", type->bits}, {"rawBitsHex", std::move(bits)}};
    }
    std::uint64_t encoded = 0;
    for (std::size_t i = 0; i < raw.size(); ++i)
      encoded |= std::uint64_t{static_cast<unsigned char>(raw[i])} << (i * 8);
    if (type->boolean) {
      if (encoded > 1) return std::nullopt;
      return Json{{"kind", "boolean"}, {"value", encoded == 1}};
    }
    const bool negative = type->isSigned && (encoded & (std::uint64_t{1} << (type->bits - 1)));
    // Negation remains unsigned, including 0x8000000000000000. Narrow widths
    // need masking to undo their implicit zero extension into uint64_t.
    const std::uint64_t magnitude = negative ? (std::uint64_t{0} - encoded) & mask(type->bits) : encoded;
    char decimal[21];
    auto* first = decimal;
    if (negative) *first++ = '-';
    const auto converted = std::to_chars(first, decimal + sizeof(decimal), magnitude, 10);
    if (converted.ec != std::errc{}) return std::nullopt;
    return Json{{"kind", "integer"}, {"decimal", std::string(decimal, converted.ptr)},
                {"bits", type->bits}, {"signed", type->isSigned}};
  } catch (...) {
    return std::nullopt;
  }
}
}  // namespace phantom
