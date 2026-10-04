#pragma once

#include <cstddef>
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

}  // namespace phantom
