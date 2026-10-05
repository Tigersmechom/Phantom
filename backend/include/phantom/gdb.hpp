#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stop_token>
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
  // Trusted helper used to connect the inferior's fd 0/1/2 to bounded pipes.
  // The backend executable supplies this helper next to itself. An empty or
  // inaccessible path fails launch explicitly instead of falling back to a
  // merged PTY with different stdin/stream semantics.
  std::filesystem::path execWrapper;
  std::filesystem::path workingDirectory;
  std::size_t maxOutputBytes = 4u * 1024u * 1024u;
  std::size_t maxVariablesPerPage = 128;
  std::size_t maxMemoryReadBytes = 64u * 1024u;
  std::size_t maxInstructions = 512;
  std::size_t maxInputBytes = 1024u * 1024u;
  std::chrono::milliseconds commandTimeout{30000};
  // Source-level stepping can legitimately have no different source line to
  // reach (for example `while (true) { continue; }`).  Bound that operation
  // separately so a line step cannot leave the session wedged for the full
  // command timeout.  The engine interrupts the inferior and reports the
  // resulting stop as an incomplete step.
  std::chrono::milliseconds stepTimeout{1000};
};

struct GdbLaunchRequest {
  std::filesystem::path binaryPath;
  std::vector<std::string> argv;
  std::vector<std::pair<std::string, std::string>> environment;
  std::string input;
  std::string inputId = "input-none";
  bool closeInputAfterWrite = true;
  bool stopAtEntry = true;
  // Explicit request to GDB, not proof the kernel accepted ADDR_NO_RANDOMIZE.
  bool disableRandomization = true;
  // Explicit opt-in. Software recording is bounded and only covers machine
  // state supported by GDB; it cannot undo files, pipes or other OS effects.
  std::string recordingProfile = "native";
  std::size_t maxRecordedInstructions = 200000;
  GdbSourceBundle sourceBundle;
  // Immutable artifact identity supplied by the owning build service. Older
  // direct engine callers may omit it, but live runtime helpers then refuse.
  std::string binarySha256;
  // Opt-in process-creation isolation, installed by the trusted wrapper
  // before executing the target. Native preserves ordinary program behavior.
  std::string processProfile = "native";
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
  // Optional ABI-specific snapshot of bytes still held by the C stdout
  // buffer at a real stop. The snapshot identifies this as glibc stdout and
  // only associates it with cout when sync_with_stdio is still enabled. It
  // is omitted for a dead inferior; unsupported layouts carry an explicit
  // unavailable status rather than guessing.
  nlohmann::json stdoutBufferedSnapshot = nlohmann::json::object();
  nlohmann::json stderrSnapshot = nlohmann::json::object();
  // Exact retained transport bytes for the service's append-only effect
  // journal. These are deliberately not part of the public text snapshot.
  std::string stdoutRaw;
  std::string stderrRaw;
  nlohmann::json recording = nullptr;
  // All mapped virtual regions, captured while the inferior is stopped.
  // Contents remain separately bounded readMemory requests at this stop.
  nlohmann::json memoryMap = nullptr;
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
              GdbError& error, std::stop_token cancellation = {});
  bool resume(std::string_view stepKind, GdbStop& result, GdbError& error);
  bool pause(GdbStop& result, GdbError& error);

  // Thread-safe transport mutations. These only queue/write pipe bytes;
  // they never issue MI commands or evaluate code in the inferior.
  bool appendInput(std::string_view id, std::string_view text,
                   nlohmann::json& result, GdbError& error);
  bool closeInput(nlohmann::json& result, GdbError& error);

  // interrupt(1) asks the current command to stop at the next safe MI
  // boundary; interrupt(2) also terminates the inferior.  It is safe to call
  // this from a control thread while launch/resume is running.
  void interrupt(int mode = 1) noexcept;
  // Owning worker only, after the service seals the active command.
  void clearInterrupt() noexcept;
  void stop() noexcept;
  // Terminate and preserve the final transport snapshot before closing pipes.
  GdbStop stopAndSnapshot();
  bool live() const noexcept;
  std::optional<int> gdbPid() const noexcept;
  std::optional<int> inferiorPid() const noexcept;
  // Requested profile and actual wrapper/kernel confirmation for the live
  // process. This is evidence of the fixed process-creation filter, not a
  // general sandbox; termination clears verification but retains requested.
  nlohmann::json processIsolation() const;

  bool setBreakpoints(const nlohmann::json& request, nlohmann::json& result,
                      GdbError& error);
  bool readVariables(std::string_view reference, std::size_t start,
                     std::size_t count, nlohmann::json& result,
                     GdbError& error);
  // Static DWARF type metadata and current storage evidence for one exact
  // root variable locator emitted by the current stack snapshot. No target
  // expressions, pretty-printers, inferior calls or pointer traversal.
  bool inspectVariableLayout(std::string_view locator, nlohmann::json& result,
                             GdbError& error);
  // Conservative integral/bool/float/double metadata for a root locator emitted
  // at the current stop. This native x86-64 profile never evaluates caller
  // expressions or assigns through gdb.Value; the service reads/compares
  // bytes, selects the public profile and owns the audited write. Addresses
  // do not establish lifetime; floating-point values are never evaluated.
  bool inspectScalarStorage(std::string_view locator, nlohmann::json& result,
                            GdbError& error);
  bool readMemory(std::string_view addressHex, std::size_t byteCount,
                  nlohmann::json& result, GdbError& error);
  // Raw memory intervention primitives. The service owns current mapping
  // permissions, compare-before-write, readback and the immutable audit.
  // These reject every recording profile other than native and require
  // exactly one confirmed stopped thread. None delivers queued stdin/EOF.
  bool prepareMemoryWrite(GdbError& error);
  // Only 1..256 literal bytes, with a strict uint64 address. attempted is
  // reset on entry and set immediately before sending the mutating MI
  // command; false return with attempted=true can mean a partial write.
  bool writeMemoryBytes(std::string_view addressHex, std::string_view bytesHex,
                        bool& attempted, GdbError& error);
  // Native x86-64 general-register interventions, excluding PC, stack/frame
  // pointers, aliases, flags, vectors and system registers. Each call verifies
  // one stopped thread, selects its innermost frame, and independently checks
  // the actual architecture, width and dynamic MI register number. No call
  // executes target code or exposes queued input/EOF. Input-wait stops and
  // recording profiles other than native are unsupported.
  // target = {architecture, register, bits, threadId, frameLevel}; a successful
  // read adds valueHex, always 0x followed by 16 lowercase hexadecimal digits.
  bool prepareRegisterWrite(std::string_view name, nlohmann::json& target,
                            GdbError& error);
  bool readRegisterValue(std::string_view name, nlohmann::json& result,
                         GdbError& error);
  // valueHex must already be canonical. attempted follows the same send-
  // boundary convention as writeMemoryBytes; a failed attempted write still
  // needs independent readback and an immutable service audit.
  bool writeRegisterValue(std::string_view name, std::string_view valueHex,
                          bool& attempted, GdbError& error);
  // Explicit bounded runtime transaction, only for the trusted opt-in helper
  // manifest from the immutable build and verified single-process-v1 launch.
  // No caller code or syscall arguments.
  // After a possible mutation, any unverified state/signal/cancellation closes
  // the debugger and inferior; report remains suitable for the service audit.
  bool executeRuntimeHelper(const nlohmann::json& manifest,
                            nlohmann::json& report, GdbError& error,
                            std::stop_token cancellation = {});
  // Trusted service-only retained mappings. Allocation accepts an empty
  // address and 1..65536 requested bytes. Release accepts only the service's
  // owned, page-aligned address and mapped size; no wire address is allowed.
  // afterMaps is the independently verified complete post-operation map.
  bool executeRuntimeAllocation(const nlohmann::json& manifest, bool release,
                                std::string_view addressHex, std::size_t byteCount,
                                nlohmann::json& report, nlohmann::json& afterMaps,
                                GdbError& error, std::stop_token cancellation = {});
  // Independently re-check the stop, capture without target execution or
  // input delivery, and replace issued variable handles for this new state.
  bool refreshStoppedSnapshot(GdbStop& result, GdbError& error);
  bool disassemble(std::string_view addressHex, std::size_t maxInstructions,
                   nlohmann::json& result, GdbError& error);
  // Empty selection returns general registers. Names are resolved through MI
  // register metadata; no expression supplied by the client is evaluated.
  bool readRegisters(const std::vector<std::string>& names,
                     nlohmann::json& result, GdbError& error);
  // Execute at most 256 actual instruction steps and retain bounded boundary
  // observations, not a store log or a reversible process recording. Ranges
  // are [{addressHex, byteCount}], at most eight / 4096 bytes in total.
  // Like resume(), false can still provide an authoritative stopped result.
  bool traceInstructions(std::size_t count,
                         const std::vector<std::string>& registerNames,
                         const nlohmann::json& memoryRanges,
                         GdbStop& finalStop, nlohmann::json& trace,
                         GdbError& error);

  bool readRecording(nlohmann::json& result, GdbError& error);
  bool reverseInstruction(GdbStop& result, GdbError& error);
  bool seekRecording(std::uint64_t instruction, GdbStop& result,
                     GdbError& error);

  // Variable writes and conditions are deliberately not implemented until a
  // non-evaluating, typed assignment policy is available.  Calling these
  // methods produces UNSUPPORTED rather than invoking user code.
  bool writeVariable(std::string_view, const nlohmann::json&,
                     nlohmann::json&, GdbError& error);

 private:
  enum class RuntimeOperation { scratch, allocate, release };
  bool executeRuntimeOperation(const nlohmann::json& manifest, RuntimeOperation operation,
                               std::string_view addressHex, std::size_t byteCount,
                               nlohmann::json& report, nlohmann::json& afterMaps,
                               GdbError& error, std::stop_token cancellation);
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace phantom
