#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

// The first native register profile deliberately excludes the instruction and
// stack/frame pointers, flags, aliases, vectors and architecture-specific state.
bool isNativeGprName(std::string_view name) noexcept;
// Validation only: a full unsigned 64-bit value, 0x plus 16 lowercase digits.
// No padding, truncation or numeric conversion is performed by this helper.
bool canonicalGprHex(std::string_view value) noexcept;

struct RegisterEditRead {
  // A canonical complete value can be retained alongside an error as evidence,
  // but only an error-free live read authorizes a write or verifies readback.
  std::optional<std::string> valueHex;
  bool debuggerAlive = true;
  std::string code;
  std::string message;
};
struct RegisterEditWrite {
  // False requires positive evidence that command submission never began.
  bool attempted = true;
  bool acknowledged = false;
  bool debuggerAlive = true;
  std::string code;
  std::string message;
};
using RegisterEditReader = std::function<RegisterEditRead(std::string_view)>;
using RegisterEditWriter = std::function<RegisterEditWrite(std::string_view, std::string_view)>;

// Bounded compare-before-write/readback, at most two reads and one write.
// The owning service enforces the stopped native x86-64 process/thread, stop
// identity, architecture, register binding and audit capacity before calling.
// Invalid names or noncanonical values throw invalid_argument before callbacks.
// Failed acknowledgement still gets readback when a write might have occurred
// and GDB remains alive. No retry, rollback, atomicity or instruction execution
// is implied. An exception during writing conservatively means an attempted
// mutation, while callback exceptions alone do not establish debugger death.
nlohmann::json compareAndWriteRegister(
    std::string_view registerName, std::string_view expectedValueHex,
    std::string_view replacementValueHex, const RegisterEditReader& read,
    const RegisterEditWriter& write);

}  // namespace phantom
