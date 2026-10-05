#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

// Storage encoding only: this does not prove that an object's lifetime has
// begun, authorize a write, or establish that the supplied metadata is true.
// The caller obtains the type from fresh GDB/DWARF evidence for the confirmed
// x86_64 target. The exact metadata object contains kind, byteSize, bits,
// signed, byteOrder, representation. Supported encodings are little-endian
// 8/16/32/64-bit two's-complement / unsigned integers and one-byte bool 00/01.
// Integer DTO width and signedness must match; decimal strings are canonical.
// No C++ conversions, expression evaluation, or floating-point conversion.
// Failure clears raw and reports invalid-type, invalid-value, type-mismatch,
// or out-of-range. Malformed JSON never escapes as a conversion exception.
bool encodeScalarStorage(const nlohmann::json& scalar, const nlohmann::json& value,
                         std::string& raw, std::string& reason) noexcept;

// Returns an exact canonical ScalarValueDTO, or nullopt when metadata/length
// is invalid or a bool byte is neither 00 nor 01. Invalid storage is never
// silently normalized into a value. Raw input is in target memory order.
std::optional<nlohmann::json> decodeScalarStorage(
    const nlohmann::json& scalar, std::string_view raw) noexcept;

}  // namespace phantom
