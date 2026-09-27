#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {
using Json = nlohmann::json;
inline constexpr std::uint64_t max_json_safe_integer = 9007199254740991ULL;

// Transport must bound its input buffer before calling parse_wire_json. These
// additional bounds protect parsing and consumers of an already constructed DOM.
struct ValidationLimits {
  std::size_t maxWireBytes = 16 * 1024 * 1024;
  std::size_t maxDepth = 64;
  std::size_t maxNodes = 100000;
  std::size_t maxObjectMembers = 4096;
  std::size_t maxArrayElements = 16384;
  std::size_t maxStringBytes = 4 * 1024 * 1024;
  std::size_t maxIdBytes = 256;
  std::size_t maxSourceBytes = 4 * 1024 * 1024;
  std::size_t maxDocuments = 128;
  std::size_t maxInputBytes = 1024 * 1024;
  std::size_t maxArguments = 256;
  std::size_t maxArgumentBytes = 4096;
  std::size_t maxEnvironmentBytes = 256 * 1024;
  std::size_t maxBreakpoints = 512;
  std::size_t maxPageSize = 1024;
  std::size_t maxMemoryReadBytes = 65536;
  std::size_t maxInstructions = 1024;
  std::size_t maxScalarBits = 4096;
};

class ValidationError : public std::runtime_error {
public:
  std::string code;
  std::string path;
  ValidationError(std::string code, std::string path, std::string message);
};

// No duplicate keys (including differently escaped spellings), invalid UTF-8,
// lone surrogate escapes, nonfinite/unsafe JSON numbers, excessive depth or size.
// The lexical pass enforces allocation budgets BEFORE constructing the DOM.
Json parse_wire_json(std::string_view wire, const ValidationLimits& limits = {});
void validate_request(const Json& request, const ValidationLimits& limits = {});
// Wire-only wrapper for DebugBackendAdapter.connect; not a new v1 command.
void validate_connect(const Json& connect, const ValidationLimits& limits = {});
void validate_scalar_value(const Json& value, const ValidationLimits& limits = {});
void validate_runtime_value(const Json& value, const ValidationLimits& limits = {});

struct TextPosition {
  std::size_t utf16 = 0;
  std::size_t line = 1;
  std::size_t column = 1;
  bool operator==(const TextPosition&) const = default;
};
// Byte offsets must be codepoint boundaries. UTF-16 offsets must not split a
// surrogate pair. LF advances line; CR and tabs retain their exact code units.
void validate_utf8(std::string_view text);
TextPosition utf8_byte_position(std::string_view text, std::size_t byteOffset);
std::size_t utf16_to_utf8_offset(std::string_view text, std::size_t utf16Offset);
void validate_source_span(const Json& span, const Json& document,
                          const ValidationLimits& limits = {});
void validate_input_trace(const Json& trace, const Json& submitted,
                          const ValidationLimits& limits = {});
// Validates shape, unique IDs, dependency references/acyclicity, and active IDs.
// Source revision/geometry must additionally be checked against saved documents.
void validate_expression_trace(const Json& trace,
                               const ValidationLimits& limits = {});
} // namespace phantom
