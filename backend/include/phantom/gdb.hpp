#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace phantom {

/** A source document as it was used by the build.  Paths are never inferred
 * from the editor's current text; they must identify the submitted bundle. */
struct GdbSourceDocument {
  std::string documentId;
  std::string revisionId;
  std::filesystem::path path;
  // The immutable submitted text lets the adapter convert GDB's line-only
  // locations back to a protocol SourceSpan without guessing editor state.
  std::string text;
};
struct GdbSourceBundle {
  std::string id;
  std::vector<GdbSourceDocument> documents;
};

struct GdbOptions {
  std::string gdbPath = "gdb";
  // Reserved for a future alternate file-capture transport. The current
  // adapter leaves this unset and uses a dedicated PTY for the inferior.
  std::filesystem::path execWrapper;
  std::filesystem::path workingDirectory;
  std::size_t maxOutputBytes = 4u * 1024u * 1024u;
  std::size_t maxVariablesPerPage = 128;
  std::size_t maxMemoryReadBytes = 64u * 1024u;
  std::size_t maxInstructions = 512;
  std::chrono::milliseconds commandTimeout{30000};
};

struct GdbLaunchRequest {
  std::filesystem::path binaryPath;
  std::vector<std::string> argv;
  std::vector<std::pair<std::string, std::string>> environment;
  std::string input;
  bool stopAtEntry = true;
  GdbSourceBundle sourceBundle;
};

struct GdbError {
  std::string code;
  std::string message;
  bool retryable = false;
};

struct GdbStop {
  bool stopped = false;
  bool exited = false;
  std::optional<int> exitCode;
  std::optional<int> signal;
  std::string signalName;
  std::string reason;
  std::string threadId;
  std::string processInstanceId;
  nlohmann::json location = nullptr;
  nlohmann::json stack = nlohmann::json::array();
  nlohmann::json input = nlohmann::json::object();
  nlohmann::json stdoutSnapshot = nlohmann::json::object();
  nlohmann::json stderrSnapshot = nlohmann::json::object();
  // The complete stop record is retained for the owning service to attach a
  // stopId/stateRevision and to create an immutable history point.
  nlohmann::json raw = nlohmann::json::object();
};

class GdbEngine {
 public:
  explicit GdbEngine(GdbOptions options = {});
  ~GdbEngine();
  GdbEngine(const GdbEngine&) = delete;
  GdbEngine& operator=(const GdbEngine&) = delete;

  bool launch(const GdbLaunchRequest& request, GdbStop& result,
              GdbError& error);
  bool resume(std::string_view stepKind, GdbStop& result, GdbError& error);
  bool pause(GdbStop& result, GdbError& error);

  // interrupt(1) asks the current command to stop at the next safe MI
  // boundary; interrupt(2) also terminates the inferior.  It is safe to call
  // this from a control thread while launch/resume is running.
  void interrupt(int mode = 1) noexcept;
  void stop() noexcept;
  bool live() const noexcept;
  std::optional<int> gdbPid() const noexcept;

  bool setBreakpoints(const nlohmann::json& request, nlohmann::json& result,
                      GdbError& error);
  bool readVariables(std::string_view reference, std::size_t start,
                     std::size_t count, nlohmann::json& result,
                     GdbError& error);
  bool readMemory(std::string_view addressHex, std::size_t byteCount,
                  nlohmann::json& result, GdbError& error);
  bool disassemble(std::string_view addressHex, std::size_t maxInstructions,
                   nlohmann::json& result, GdbError& error);

  // Variable writes and conditions are deliberately not implemented until a
  // non-evaluating, typed assignment policy is available.  Calling these
  // methods produces UNSUPPORTED rather than invoking user code.
  bool writeVariable(std::string_view, const nlohmann::json&,
                     nlohmann::json&, GdbError& error);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace phantom
