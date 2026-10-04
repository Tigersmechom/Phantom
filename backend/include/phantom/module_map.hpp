#pragma once

#include <cstddef>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {

struct ModuleInspectionLimits {
  std::size_t maxModules = 128;
  std::size_t maxMetadataBytes = 8 * 1024 * 1024;
  std::size_t maxRegions = 8192;
  std::size_t maxSegmentsPerModule = 256;
  std::size_t maxInstancesPerModule = 128;
  std::size_t maxMappedRanges = 16384;
  std::size_t maxMatchOperations = 2 * 1024 * 1024;
};

// Index file-backed regions of an owned, stopped inferior. memoryMap must be
// the actual maps snapshot of this stop; all inferior threads must stay stopped
// through this call. No loader calls, inferior writes or pathname-only identity
// assumptions. Anonymous mappings and special kernel regions remain in maps.
// A module is an ELF-backed mapped file, not proof of dynamic-loader ownership.
// Instances are PT_LOAD/file-offset evidence; anonymous BSS intersections show
// address coverage, not ownership. loadBiasHex can have a leading minus sign.
// File identity is device/inode, not a content hash or immutable memory image.
// Every requested limit is clamped to the defaults above.
nlohmann::json inspectRuntimeModules(int pid, const nlohmann::json& memoryMap,
                                     const ModuleInspectionLimits& limits = {});

struct ModuleSymbolInspectionLimits {
  std::size_t maxMetadataBytes = 4 * 1024 * 1024;
  std::size_t maxSections = 1024;
  std::size_t maxSymbols = 4096;
  std::size_t maxRuntimeLocations = 8192;
  std::size_t maxMappedRanges = 16384;
  std::size_t maxMatchOperations = 2 * 1024 * 1024;
};

// Inspect section/symbol metadata for one module ID from the current maps.
// The caller keeps every inferior thread stopped. Pinned proc maps and process
// identity are checked before/after, as are the opened mapped file's identity
// and metadata version. This is file metadata plus PT_LOAD mapping evidence,
// never proof of live object lifetimes, dynamic symbol binding or vtable layout.
// TLS, undefined/common and absolute symbols do not get fabricated addresses.
// All limits are clamped to the defaults above; exhausted budgets are explicit.
nlohmann::json inspectRuntimeModuleSymbols(
    int pid, const nlohmann::json& memoryMap, std::string_view moduleId,
    const ModuleSymbolInspectionLimits& limits = {});

}  // namespace phantom
