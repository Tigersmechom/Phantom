#pragma once

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace phantom {

struct ElfInspectionLimits {
  std::size_t maxFileBytes = 256 * 1024 * 1024;
  std::size_t maxProgramHeaders = 4096;
  std::size_t maxNoteBytes = 1024 * 1024;
  std::size_t maxBuildIdBytes = 256;
  std::size_t maxMetadataBytes = 2 * 1024 * 1024;
};

// Inspect a regular ELF64 little-endian file without executing it or invoking
// external utilities. Addresses, offsets and sizes are hexadecimal strings.
// Limits above are also hard upper bounds. GNU build IDs are read from PT_NOTE
// segments; a null buildId means no GNU build ID was found in those segments.
// Unsupported formats, truncated/malformed metadata and exhausted limits return
// available=false with reason/detail, never a partial claim about ELF type.
// This is metadata inspection, not a complete executable/section-table verifier.
// The caller must prevent concurrent modification when binding this metadata to
// a content hash or launching the inspected artifact.
nlohmann::json inspectElf(const std::filesystem::path& path,
                          const ElfInspectionLimits& limits = {});

// Inspect a borrowed, already-open descriptor. Does not change its offset or
// close it. This lets procfs callers verify device/inode before inspecting the
// pinned mapped file. metadataBytesRead counts successful metadata reads even
// on failure; maxMetadataBytes bounds those reads independently of file size.
nlohmann::json inspectElfFd(int fd, const ElfInspectionLimits& limits = {},
                           std::size_t* metadataBytesRead = nullptr);

}  // namespace phantom
