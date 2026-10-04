#pragma once

#include <cstddef>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

struct ProcessInspectionLimits {
  // Also the hard maximums: at most five small files, one exe link, and 128 fd
  // links are read. No full smaps walk or arbitrary target-file read occurs.
  std::size_t maxFileBytes = 64 * 1024;
  std::size_t maxDescriptors = 128;
  std::size_t maxLinkBytes = 4096;
};

// Parses kernel stat fields using the LAST closing parenthesis, since comm may
// contain spaces, parentheses, newlines, and non-UTF-8 filename bytes. Unknown
// trailing fields are tolerated. Numeric strings preserve 64-bit precision.
// Address fields may be zeroed by the kernel's ptrace permission checks; zero
// is reported honestly and must not be interpreted as proof of an absent map.
nlohmann::json parseLinuxProcessStat(std::string_view text);

// Caller must authorize pid as its own stopped inferior and bind this metadata
// to the current process instance/stop. Uses a pinned proc directory descriptor
// and checks starttime before/after collection. This prevents mixing PID reuse,
// but does not promise an atomic snapshot of a running or concurrently execing
// process. Failures of optional sections remain explicit and independent.
// No environ/cmdline contents, global sysctls, or fd targets are read or changed.
nlohmann::json inspectOwnedProcess(int pid, const ProcessInspectionLimits& limits = {});

}  // namespace phantom
