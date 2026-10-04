#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <stop_token>
#include <string>
#include <nlohmann/json.hpp>

namespace phantom {

struct RecorderProbeOptions {
  // Trusted host configuration, never paths supplied by the debugged program.
  std::string gdbPath = "gdb";
  std::string rrPath = "rr";
  std::filesystem::path fixturePath;
  std::filesystem::path temporaryDirectory;
  // One shared deadline for all subprocesses, not a fresh timeout per command.
  std::chrono::milliseconds timeout{10000};
  std::size_t maxOutputBytes = 64 * 1024;
  std::size_t maxTraceBytes = 16 * 1024 * 1024;
};

// Runs only the shipped tiny scalar fixture in isolated owned child processes.
// Does not attach to or modify a live session, alter sysctls, install packages,
// or retain traces. Availability means this fixture actually recorded/replayed;
// it is not a promise that arbitrary instructions, syscalls or programs work.
// All processes share a deadline and cancellation token and are group-cleaned.
nlohmann::json probeRecorders(const RecorderProbeOptions& options,
                              std::stop_token stop = {});

}  // namespace phantom
