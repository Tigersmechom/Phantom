#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

// Exact raw bytes, or nullopt. Partial/oversized responses are rejected. The
// caller supplies reads of its stopped inferior and preserves fatal errors.
using VtableMemoryReader = std::function<std::optional<std::string>(std::uint64_t, std::size_t)>;
// Current inspectRuntimeModuleSymbols report for this maps-derived module ID.
// The caller caches reports and limits each inspection to 1 MiB metadata.
using VtableSymbolReader = std::function<nlohmann::json(std::string_view)>;

// Caller explicitly selects itanium-x86_64-absolute-v1. This decodes sampled
// memory under that profile; it does not verify ABI compatibility, object
// lifetime, dynamic type, method count or callable function pointers. Maps are
// current OS evidence even when the debugger is replaying earlier memory.
// Requires complete sorted maps (<=8192 ranges), maxEntries in [1,64], and
// permission-readable ranges before every read. At most four distinct module
// symbol reports and five raw reads (<=560 bytes) are requested. Vptr/header
// rereads detect some changes; matching samples never establish atomicity.
nlohmann::json inspectItaniumVtable(
    std::uint64_t vptrSlotAddress, std::size_t maxEntries,
    const nlohmann::json& memoryMap, const VtableMemoryReader& readMemory,
    const VtableSymbolReader& readSymbols);

}  // namespace phantom
