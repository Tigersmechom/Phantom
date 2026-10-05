#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

// Prove that complete parseLinuxMemoryMap snapshots differ only by adding
// (released=false) or removing (released=true) the exact unnamed private
// anonymous interval. Allocation requires permissions="rw-"; release supports
// "r--", "rw-", or "r-x". Anonymous VMA split/merge is normalized; file/special
// boundaries and all outside metadata remain exact. This does not establish
// ownership or rule out intervening unmap/remap: the caller must independently
// enforce process identity, continuous-stop authority and page alignment.
// At most 8192 regions per map and 1 MiB per allocation are supported.
bool verifyRuntimeAllocationDelta(const nlohmann::json& before,
                                  const nlohmann::json& after,
                                  std::string_view addressHex,
                                  std::size_t byteCount,
                                  bool released,
                                  std::string& detail,
                                  std::string_view permissions = "rw-");

// Prove that the only map change is a full-interval protection change of
// unnamed private anonymous memory. Both permission arguments are one of
// "r--", "rw-", or "r-x"; same-permission transitions are allowed. The caller
// must separately prove ownership, page alignment, byte preservation, and
// syscall/context restoration. The same map/interval limits apply as above.
bool verifyRuntimeProtectionDelta(const nlohmann::json& before,
                                  const nlohmann::json& after,
                                  std::string_view addressHex,
                                  std::size_t byteCount,
                                  std::string_view expectedPermissions,
                                  std::string_view replacementPermissions,
                                  std::string& detail);

}  // namespace phantom
