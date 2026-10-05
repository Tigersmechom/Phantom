#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

// Prove that complete parseLinuxMemoryMap snapshots differ only by adding
// (released=false) or removing (released=true) the exact unnamed private RW
// anonymous interval. Anonymous VMA split/merge is normalized; file/special
// boundaries and all outside metadata remain exact. This does not establish
// ownership or rule out intervening unmap/remap: the caller must independently
// enforce process identity, continuous-stop authority and page alignment.
// At most 8192 regions per map and 1 MiB per allocation are supported.
bool verifyRuntimeAllocationDelta(const nlohmann::json& before,
                                  const nlohmann::json& after,
                                  std::string_view addressHex,
                                  std::size_t byteCount,
                                  bool released,
                                  std::string& detail);

}  // namespace phantom
