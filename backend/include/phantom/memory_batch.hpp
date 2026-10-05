#pragma once

#include "phantom/memory_edit.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace phantom {

struct MemoryBatchEdit {
  std::uint64_t address = 0;
  std::string expectedRaw;
  std::string replacementRaw;
};

// Throws std::invalid_argument, before invoking any callback, unless there
// are 1..8 non-overlapping ranges totalling <=256 bytes. Every range must have
// equal, nonempty expected/replacement buffers and a non-overflowing extent.
// Unsorted input is supported and execution follows request order; adjacency
// is allowed. The caller remains responsible for native stopped-process,
// mapping, current-stop and retention checks before allowing a write.
//
// All ranges are read and compared before any write; preflight stops at its
// first failure. Each execution then reuses compareAndWriteMemory with fresh
// reads. Any execution failure, including missing acknowledgement despite
// matching readback, stops later writes. After any attempted write, a final
// read sweeps all ranges while the debugger is alive. This is observational,
// not atomic: reads occur at different times. No retry or rollback occurs.
// At most 4 * ranges.size() reads and ranges.size() writes are invoked.
//
// Prefix bytes are retained as evidence, but comparisons require complete,
// error-free reads with live-debugger evidence. First failureIndex is never
// replaced by a later failure. Callback exceptions do not prove death; the
// caller must preserve independent lifecycle evidence. Invalid UTF-8 errors
// are sanitized and bounded; new read messages also have a 512-byte JSON
// string budget to bound escaping expansion. Single-edit reports are unchanged.
nlohmann::json compareAndWriteMemoryBatch(
    const std::vector<MemoryBatchEdit>& edits, const MemoryEditReader& read,
    const MemoryEditWriter& write);

}  // namespace phantom
