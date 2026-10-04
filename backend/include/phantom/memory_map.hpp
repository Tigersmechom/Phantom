#pragma once

#include <cstddef>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

struct MemoryMapLimits {
  std::size_t maxBytes = 1024 * 1024;
  std::size_t maxRegions = 8192;
};

// Linux maps describes mapped virtual ranges, not allocations, resident pages,
// or object/vtable identities. Addresses and inode numbers remain strings.
// Permissions is the exact four-character kernel token (e.g. "r--p").
// path preserves kernel escapes such as \012; these cannot be decoded without
// ambiguity. Non-UTF-8 pathnames instead use path=null and pathBytesHex.
// Limits are clamped to hard bounds of 16 MiB and 65536 regions.
nlohmann::json parseLinuxMemoryMap(std::string_view text,
                                  const MemoryMapLimits& limits = {},
                                  bool inputTruncated = false);

// The caller must ensure that this is its stopped inferior (all threads stopped)
// and bind the result to that process instance/stop. Proc maps alone does not
// supply atomic snapshots of a running process or protection against PID reuse.
// ENOENT is process-unavailable: it cannot distinguish exit from proc hidepid.
nlohmann::json readLinuxMemoryMap(int pid, const MemoryMapLimits& limits = {});

}  // namespace phantom
