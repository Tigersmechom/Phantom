#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace phantom {

// Small dependency-free SHA-256 implementation used for source/build identity.
// It is deliberately exposed as hexadecimal text so no exact identity crosses a
// JSON number boundary.
std::string sha256_hex(std::span<const std::byte> bytes);
inline std::string sha256_hex(std::string_view text) {
  return sha256_hex(std::as_bytes(std::span{text.data(), text.size()}));
}

}
