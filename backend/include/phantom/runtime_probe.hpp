#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <stop_token>
#include <string>
#include <nlohmann/json.hpp>

namespace phantom {

struct RuntimeProbeOptions {
  // Trusted host configuration only; the protocol supplies no executable,
  // script, syscall number, target address or debugger expression.
  std::string gdbPath = "gdb";
  std::filesystem::path fixturePath;
  std::filesystem::path temporaryDirectory;
  // All stages share this deadline and cancellation token.
  std::chrono::milliseconds timeout{10000};
  std::size_t maxOutputBytes = 64 * 1024;
};

// Executes only the shipped disposable x86-64 fixture. Success is evidence
// about that fixture on this host, never permission to inject into an existing
// user session. The fixture and GDB run in owned subprocesses; temporary files
// and their allocated memory disappear when the probe finishes or is stopped.
nlohmann::json probeRuntime(const RuntimeProbeOptions& options,
                            std::stop_token stop = {});

}  // namespace phantom
