#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

struct MemoryEditRead {
  // Exact requested bytes on success. A shorter contiguous prefix is retained
  // as evidence on failure, but never authorizes a write or verifies readback.
  std::optional<std::string> bytes;
  bool debuggerAlive = true;
  std::string code;
  std::string message;
};
struct MemoryEditWrite {
  // False means the adapter knows no write command was attempted. If command
  // submission might have begun, attempted must be true even after an error.
  bool attempted = true;
  bool acknowledged = false;
  bool debuggerAlive = true;
  std::string code;
  std::string message;
};
using MemoryEditReader = std::function<MemoryEditRead(std::uint64_t, std::size_t)>;
using MemoryEditWriter = std::function<MemoryEditWrite(std::uint64_t, std::string_view)>;

// Single bounded compare-before-write operation, not an atomic transaction.
// The caller enforces owned stopped process, native profile, mapping policy,
// current stop identity and audit retention before supplying these callbacks.
// Equal nonempty buffers up to 256 bytes are required. Addresses and binary
// values are serialized exactly. At most two reads and one write are invoked.
// No retries or rollback occur. Even a failed write gets readback when the
// debugger remains alive; verified bytes and write acknowledgement are separate
// facts. An exception during writing is conservatively an attempted mutation.
// debuggerAlive records the last callback-provided lifecycle evidence; callback
// exceptions do not independently prove debugger death. The owning adapter
// must preserve real process failures outside this report as well.
nlohmann::json compareAndWriteMemory(
    std::uint64_t address, std::string_view expectedRaw,
    std::string_view desiredRaw, const MemoryEditReader& read,
    const MemoryEditWriter& write);

}  // namespace phantom
