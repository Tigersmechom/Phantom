#include "phantom/scalar_codec.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Json = nlohmann::json;

void require(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string(message));
}
Json type(unsigned bits, bool isSigned) {
  return {{"kind", "integer"}, {"byteSize", bits / 8}, {"bits", bits},
          {"signed", isSigned}, {"byteOrder", "little"},
          {"representation", isSigned ? "twos-complement" : "unsigned-binary"}};
}
Json booleanType() {
  return {{"kind", "boolean"}, {"byteSize", 1}, {"bits", 8}, {"signed", nullptr},
          {"byteOrder", "little"}, {"representation", "boolean-01"}};
}
Json value(unsigned bits, bool isSigned, std::string_view decimal) {
  return {{"kind", "integer"}, {"decimal", decimal}, {"bits", bits}, {"signed", isSigned}};
}
std::string hex(std::string_view raw) {
  std::string result;
  for (const unsigned char byte : raw) {
    result += "0123456789abcdef"[byte >> 4];
    result += "0123456789abcdef"[byte & 15];
  }
  return result;
}
void roundtrip(const Json& metadata, const Json& expected, std::string_view expectedHex) {
  std::string raw = "previous bytes", reason = "previous error";
  require(phantom::encodeScalarStorage(metadata, expected, raw, reason), "valid value rejected");
  require(reason.empty(), "success retained old error");
  require(hex(raw) == expectedHex, "wrong exact byte sequence");
  const auto decoded = phantom::decodeScalarStorage(metadata, raw);
  require(decoded && *decoded == expected, "lossless decoding failed");
}
void reject(const Json& metadata, const Json& candidate, std::string_view expectedReason) {
  std::string raw = "must be cleared", reason = "must be replaced";
  require(!phantom::encodeScalarStorage(metadata, candidate, raw, reason), "invalid value accepted");
  require(raw.empty(), "failed encoding retained bytes");
  require(reason == expectedReason, "wrong failure reason");
}

void integerBoundaries() {
  struct Case {
    unsigned bits;
    const char *minimum, *maximum, *unsignedMaximum, *belowMinimum, *aboveMaximum, *aboveUnsigned;
  };
  const std::array<Case, 4> cases{{
    {8, "-128", "127", "255", "-129", "128", "256"},
    {16, "-32768", "32767", "65535", "-32769", "32768", "65536"},
    {32, "-2147483648", "2147483647", "4294967295", "-2147483649", "2147483648", "4294967296"},
    {64, "-9223372036854775808", "9223372036854775807", "18446744073709551615",
         "-9223372036854775809", "9223372036854775808", "18446744073709551616"},
  }};
  for (const auto& item : cases) {
    const std::size_t bytes = item.bits / 8;
    const auto signedType = type(item.bits, true), unsignedType = type(item.bits, false);
    roundtrip(signedType, value(item.bits, true, item.minimum), std::string((bytes - 1) * 2, '0') + "80");
    roundtrip(signedType, value(item.bits, true, item.maximum), std::string((bytes - 1) * 2, 'f') + "7f");
    roundtrip(unsignedType, value(item.bits, false, item.unsignedMaximum), std::string(bytes * 2, 'f'));
    for (bool sign : {false, true}) {
      roundtrip(type(item.bits, sign), value(item.bits, sign, "0"), std::string(bytes * 2, '0'));
      roundtrip(type(item.bits, sign), value(item.bits, sign, "1"), "01" + std::string((bytes - 1) * 2, '0'));
    }
    roundtrip(signedType, value(item.bits, true, "-1"), std::string(bytes * 2, 'f'));
    reject(signedType, value(item.bits, true, item.belowMinimum), "out-of-range");
    reject(signedType, value(item.bits, true, item.aboveMaximum), "out-of-range");
    reject(unsignedType, value(item.bits, false, item.aboveUnsigned), "out-of-range");
    reject(unsignedType, value(item.bits, false, "-1"), "out-of-range");
    reject(unsignedType, value(item.bits, false, "-18446744073709551615"), "out-of-range");
  }
  roundtrip(type(16, false), value(16, false, "4660"), "3412");
  roundtrip(type(32, false), value(32, false, "305419896"), "78563412");
  roundtrip(type(64, false), value(64, false, "81985529216486895"), "efcdab8967452301");
  roundtrip(type(64, true), value(64, true, "-81985529216486895"), "1132547698badcfe");
  // Exact values above JavaScript's safe integer boundary stay decimal text.
  roundtrip(type(64, true), value(64, true, "9007199254740993"), "0100000000002000");
  roundtrip(type(64, true), value(64, true, "-9007199254740993"), "ffffffffffffdfff");
}

void booleans() {
  const auto metadata = booleanType();
  roundtrip(metadata, {{"kind", "boolean"}, {"value", false}}, "00");
  roundtrip(metadata, {{"kind", "boolean"}, {"value", true}}, "01");
  for (int byte = 2; byte <= 255; ++byte)
    require(!phantom::decodeScalarStorage(metadata, std::string(1, static_cast<char>(byte))),
            "invalid bool representation normalized");
  for (const Json& wrong : {Json(0), Json(1), Json("true"), Json(nullptr), Json::array()})
    reject(metadata, {{"kind", "boolean"}, {"value", wrong}}, "invalid-value");
  reject(metadata, {{"kind", "boolean"}}, "invalid-value");
  reject(metadata, {{"kind", "boolean"}, {"value", true}, {"extra", 1}}, "invalid-value");
  reject(metadata, value(8, false, "1"), "type-mismatch");
  reject(type(8, false), {{"kind", "boolean"}, {"value", true}}, "type-mismatch");
}

void malformedValues() {
  const auto metadata = type(64, true);
  std::vector<std::string> invalid{"", "-", "+0", "+1", "-0", "00", "01", "-01", " 1", "1 ",
    "\t1", "1\n", "0x10", "1.0", "1e2", "--1", "1-", "inf", "nan", "١", "１２", "−1"};
  invalid.emplace_back("1\0", 2);
  invalid.emplace_back("1\0002", 3);
  for (const auto& text : invalid) reject(metadata, value(64, true, text), "invalid-value");
  reject(metadata, value(64, true, std::string(10000, '9')), "out-of-range");
  for (const auto& malformed : {Json(), Json::array(), Json(true), Json(1), Json("1"), Json::object(),
                              Json{{"kind", nullptr}}, Json{{"kind", 1}}})
    reject(metadata, malformed, "invalid-value");
  for (auto field : {"decimal", "bits", "signed"}) {
    auto candidate = value(64, true, "1"); candidate.erase(field);
    reject(metadata, candidate, "invalid-value");
  }
  for (const Json& wrong : {Json(1), Json(1.0), Json(nullptr), Json::array()}) {
    auto candidate = value(64, true, "1"); candidate["decimal"] = wrong;
    reject(metadata, candidate, "invalid-value");
  }
  for (const Json& wrong : {Json(1), Json(0), Json(nullptr), Json("true")}) {
    auto candidate = value(64, true, "1"); candidate["signed"] = wrong;
    reject(metadata, candidate, "invalid-value");
  }
  for (const Json& wrong : {Json(8), Json(-64), Json(64.0), Json(nullptr), Json(true), Json("64"),
                          Json(std::numeric_limits<std::uint64_t>::max())}) {
    auto candidate = value(64, true, "1"); candidate["bits"] = wrong;
    reject(metadata, candidate, "type-mismatch");
  }
  reject(metadata, value(64, false, "1"), "type-mismatch");
  for (auto kind : {"pointer", "aggregate", "string", "enum", "float", "other"})
    reject(metadata, {{"kind", kind}}, "type-mismatch");
  reject(metadata, {{"kind", "float"}, {"bits", 64}, {"text", "nan"}, {"classification", "nan"}}, "type-mismatch");
  auto extra = value(64, true, "1"); extra["text"] = "1";
  reject(metadata, extra, "invalid-value");
}

void malformedMetadata() {
  const auto good = type(32, true), candidate = value(32, true, "1");
  std::vector<Json> bad{Json(), Json::array(), Json("integer"), Json(32), Json(true)};
  for (const auto& item : good.items()) {
    auto missing = good; missing.erase(item.key()); bad.push_back(missing);
    auto null = good; null[item.key()] = nullptr; bad.push_back(null);
  }
  for (auto field : {"bits", "byteSize"}) {
    for (const Json& wrong : {Json(0), Json(-1), Json(3), Json(128), Json(32.0), Json(true), Json("32"),
                            Json(std::numeric_limits<std::uint64_t>::max())}) {
      auto changed = good; changed[field] = wrong; bad.push_back(changed);
    }
  }
  for (const auto& [field, wrong] : std::vector<std::pair<std::string, Json>>{
      {"kind", "enum"}, {"kind", "float"}, {"kind", "pointer"}, {"kind", "boolean"},
      {"signed", 1}, {"signed", false}, {"byteOrder", "big"}, {"byteOrder", "native"},
      {"representation", "unsigned-binary"}, {"representation", "ones-complement"},
      {"representation", "boolean-01"}, {"extra", 1}}) {
    auto changed = good; changed[field] = wrong; bad.push_back(changed);
  }
  auto wideBool = booleanType(); wideBool["bits"] = 16; wideBool["byteSize"] = 2; bad.push_back(wideBool);
  auto signedBool = booleanType(); signedBool["signed"] = false; bad.push_back(signedBool);
  auto binaryBool = booleanType(); binaryBool["representation"] = "unsigned-binary"; bad.push_back(binaryBool);
  auto mismatch = good; mismatch["bits"] = 64; bad.push_back(mismatch);
  for (const auto& metadata : bad) {
    reject(metadata, candidate, "invalid-type");
    require(!phantom::decodeScalarStorage(metadata, std::string(4, '\0')), "bad metadata decoded");
  }
  for (unsigned bits : {8, 16, 32, 64}) {
    for (bool sign : {false, true}) {
      const auto metadata = type(bits, sign);
      for (std::size_t bytes : {std::size_t(0), std::size_t(bits / 8 - 1), std::size_t(bits / 8 + 1), std::size_t(256)})
        require(!phantom::decodeScalarStorage(metadata, std::string(bytes, '\0')), "wrong storage size decoded");
    }
  }
}

void exhaustiveSmallIntegersAndSamples() {
  // Test both byte interpretations against independently formatted native
  // integers, rather than relying exclusively on encode/decode agreement.
  for (int number = -128; number <= 255; ++number) {
    const bool sign = number < 128;
    const auto metadata = type(8, sign);
    const std::string raw(1, static_cast<char>(number));
    const auto expected = value(8, sign, std::to_string(number));
    require(phantom::decodeScalarStorage(metadata, raw) == std::optional<Json>(expected), "8-bit decode failed");
    roundtrip(metadata, expected, hex(raw));
  }
  for (int number = -32768; number <= 32767; ++number) {
    const auto narrowed = static_cast<std::uint16_t>(number);
    std::string raw{static_cast<char>(narrowed & 255), static_cast<char>(narrowed >> 8)};
    const auto decoded = phantom::decodeScalarStorage(type(16, true), raw);
    require(decoded && decoded->at("decimal") == std::to_string(number), "16-bit exhaustive decode failed");
  }
  std::uint64_t state = 0x8f4798e2a5cb1d73ULL;
  for (unsigned bits : {8, 16, 32, 64}) {
    for (bool sign : {false, true}) {
      const auto metadata = type(bits, sign);
      for (unsigned sample = 0; sample < 512; ++sample) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        std::string raw;
        for (unsigned byte = 0; byte < bits / 8; ++byte) raw += static_cast<char>(state >> (byte * 8));
        const auto decoded = phantom::decodeScalarStorage(metadata, raw);
        require(decoded.has_value(), "valid integer storage rejected");
        roundtrip(metadata, *decoded, hex(raw));
      }
    }
  }
}
}  // namespace

int main() {
  try {
    integerBoundaries(); booleans(); malformedValues(); malformedMetadata();
    exhaustiveSmallIntegersAndSamples();
    std::cout << "scalar codec tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "scalar codec: " << error.what() << '\n';
    return 1;
  }
}
