#include "phantom/service.hpp"

#include "phantom/process.hpp"
#include "phantom/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <unistd.h>

namespace phantom {
namespace {
using Json = nlohmann::json;

std::string string_at(const Json& object, const char* key) {
  return object.contains(key) && object.at(key).is_string() ? object.at(key).get<std::string>() : std::string{};
}
std::string make_id(std::string_view prefix, std::uint64_t value) {
  return std::string(prefix) + "-" + std::to_string(value);
}
std::string first_line(std::string_view text) {
  const auto end = text.find_first_of("\r\n");
  return std::string(text.substr(0, end == std::string_view::npos ? text.size() : end));
}
std::string json_text(const Json& value) {
  return value.dump(-1, ' ', false, Json::error_handler_t::strict);
}
bool contains_flag(const std::vector<std::string>& flags, std::string_view prefix) {
  return std::any_of(flags.begin(), flags.end(), [prefix](const auto& f) { return f == prefix || f.rfind(std::string(prefix), 0) == 0; });
}
bool redirects_output(std::string_view flag) {
  if (flag.rfind("@", 0) == 0) return true;  // response files bypass DTO limits
  if (flag.rfind("-Wl,", 0) == 0 && (flag.find(",-o,") != std::string_view::npos || flag.ends_with(",-o"))) return true;
  return false;
}
constexpr std::uintmax_t maxArtifactBytes = 256u * 1024u * 1024u;
} // namespace

BackendService::BackendService(ServiceOptions options) : options_(std::move(options)) {
  if (options_.workspace.empty()) options_.workspace = std::filesystem::current_path();
  options_.workspace = std::filesystem::weakly_canonical(options_.workspace);
  if (options_.buildDirectory.empty()) options_.buildDirectory = options_.workspace / ".phantom" / "backend-build";
  options_.buildDirectory = std::filesystem::weakly_canonical(options_.buildDirectory);
  std::filesystem::create_directories(options_.buildDirectory);
  GdbOptions gdbOptions;
  gdbOptions.execWrapper = options_.ioWrapper;
  gdbOptions.maxOutputBytes = std::min<std::size_t>(1024u * 1024u, options_.limits.maxWireBytes / 16);
  gdbOptions.maxVariablesPerPage = options_.limits.maxPageSize;
  gdbOptions.maxMemoryReadBytes = options_.limits.maxMemoryReadBytes;
  gdbOptions.maxInstructions = options_.limits.maxInstructions;
  gdbOptions.maxInputBytes = options_.limits.maxInputBytes;
  engine_ = std::make_unique<GdbEngine>(std::move(gdbOptions));
}

BackendService::~BackendService() { dispose(); }

void BackendService::clearActive(std::string_view requestId) noexcept {
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) active_.reset();
  }
  controlWake_.notify_all();
}

std::string BackendService::activeInterruption(std::string_view requestId) {
  std::lock_guard lock(controlMutex_);
  if (!active_ || active_->id != requestId) return {};
  // Close the control handoff before publishing the final checkpoint. A
  // control that arrives later must execute against that checkpoint itself.
  active_->ready = false;
  engine_->clearInterrupt();
  return active_->interruption;
}

void BackendService::publishFailedState(std::vector<Json>& frames, const Json& request) {
  // A fatal GDB/MI failure closes the owned debugger. Do not leave the last
  // stopped snapshot looking live after the process has already disappeared.
  if (engine_->live()) return;
  if (liveState_.is_object() && liveState_.value("phase", "") != "failed" &&
      liveState_.value("phase", "") != "terminated") {
    liveState_["phase"] = "failed";
    liveState_["live"] = nullptr;
    liveState_["exit"] = nullptr;
    frames.push_back(event({{"kind", "state"}, {"state", liveState_}}, processInstanceId_, string_at(request, "requestId")));
  }
}

std::vector<Json> BackendService::engineError(const Json& request, const GdbError& error) {
  std::vector<Json> frames{errorResponse(request, error.code.empty() ? "INTERNAL" : error.code,
                                        error.message, error.retryable)};
  publishFailedState(frames, request);
  return frames;
}

Json BackendService::capabilities() const {
  return {
      {"protocolVersion", 1}, {"backendName", "phantom-linux"},
      {"backendVersion", options_.backendVersion}, {"architectures", {"x86_64"}},
      {"stepKinds", {"over", "into", "out", "instruction"}},
      {"sourceBreakpoints", true}, {"conditionalBreakpoints", false},
      {"hitCountBreakpoints", false}, {"variableWrite", false},
      {"inputTracking", "transport-only"}, {"interactiveInput", true}, {"expressionGroups", false}, {"history", true},
      {"restore", "none"}, {"asm", {{"currentPc", true}, {"sourceRange", false}}},
      {"memoryRead", true}, {"eventReplay", true},
      {"limits", {{"maxOutputBytes", std::min<std::size_t>(1024u * 1024u, options_.limits.maxWireBytes / 16)},
                   {"maxHistoryBytes", options_.limits.maxWireBytes},
                   {"maxResidentSnapshots", 4096},
                   {"maxVariablesPerPage", options_.limits.maxPageSize},
                   {"maxStringBytes", options_.limits.maxStringBytes},
                   {"maxMemoryReadBytes", options_.limits.maxMemoryReadBytes},
                   {"maxInstructionsPerRequest", options_.limits.maxInstructions},
                   {"commandTimeoutMs", 30000}, {"replayTimeoutMs", 30000}}},
  };
}

Json BackendService::errorResponse(const Json& request, std::string code, std::string message,
                                   bool retryable) const {
  const auto requestId = string_at(request, "requestId");
  Json response = {{"protocolVersion", 1}, {"requestId", requestId}, {"workspace", workspace_},
                   {"session", sessionId_.empty() ? Json(nullptr) : Json{{"id", sessionId_}, {"generation", sessionGeneration_}}},
                   {"ok", false}, {"error", {{"code", std::move(code)}, {"message", std::move(message)}, {"retryable", retryable}}}};
  return response;
}

Json BackendService::okResponse(const Json& request, Json result) const {
  const auto requestId = string_at(request, "requestId");
  return {{"protocolVersion", 1}, {"requestId", requestId}, {"workspace", workspace_},
          {"session", sessionId_.empty() ? Json(nullptr) : Json{{"id", sessionId_}, {"generation", sessionGeneration_}}},
          {"ok", true}, {"result", std::move(result)}};
}

Json BackendService::event(const Json& payload, std::optional<std::string> process,
                           std::optional<std::string> causedBy) {
  Json frame = {{"protocolVersion", 1}, {"workspace", workspace_},
                {"session", sessionId_.empty() ? Json(nullptr) : Json{{"id", sessionId_}, {"generation", sessionGeneration_}}},
                {"processInstanceId", process && !process->empty() ? Json(*process) : Json(nullptr)}, {"sequence", ++sequence_},
                {"payload", payload}};
  if (causedBy) frame["causedByRequestId"] = *causedBy;
  const auto frameBytes = frame.dump().size();
  while (!eventLog_.empty() &&
         (eventLog_.size() >= 16384 || eventBytes_ + frameBytes > options_.limits.maxWireBytes)) {
    eventBytes_ -= std::min(eventBytes_, eventLog_.front().dump().size());
    eventLog_.erase(eventLog_.begin());
  }
  if (frameBytes <= options_.limits.maxWireBytes) {
    eventLog_.push_back(frame);
    eventBytes_ += frameBytes;
  }
  return frame;
}

Json BackendService::defaultInput() const {
  return {{"submitted", {{"id", submittedInputId_}, {"text", submittedInput_}, {"encoding", "utf-8"}, {"closeAfterWrite", true}}},
          {"tracking", "none"}, {"deliveredBytes", submittedInput_.size()}, {"trace", nullptr}, {"stream", nullptr}};
}

Json BackendService::makeObservation(const GdbStop& stop, std::string reason) {
  const auto process = stop.processInstanceId.empty() ? processInstanceId_ : stop.processInstanceId;
  // `GdbStop::raw` is an adapter-internal record.  It may contain MI-only
  // bookkeeping such as `exited` and `exitCode`; copying it into the public
  // object would silently widen StopObservationDTO and make strict clients
  // reject an otherwise valid v1 response.  Construct the DTO from the
  // explicitly supported fields below instead.
  Json observation = Json::object();
  observation["id"] = make_id("observation", ordinal_ + 1);
  observation["point"] = {{"branchId", "main"}, {"eventOrdinal", ordinal_ + 1}};
  observation["stop"] = {{"stopId", make_id("stop", stateRevision_ + 1)}, {"stateRevision", stateRevision_ + 1}};
  observation["processInstanceId"] = process;
  observation["buildId"] = artifact_ ? string_at(artifact_->dto, "id") : "";
  observation["sourceBundleId"] = artifact_ ? string_at(artifact_->dto, "sourceBundleId") : "";
  const bool inputWait = reason == "input-wait";
  observation["reason"] = std::move(reason);
  observation["location"] = stop.location;
  observation["threadId"] = stop.threadId.empty() ? Json(nullptr) : Json(stop.threadId);
  observation["stack"] = stop.stack.is_array() ? stop.stack : Json::array();
  if (!observation.contains("input")) {
    auto input = defaultInput();
    if (stop.input.is_object()) for (auto it = stop.input.begin(); it != stop.input.end(); ++it) input[it.key()] = it.value();
    // Native GDB can prove that the stop is in the inferior's stdin path,
    // but cannot prove the exact C++ extraction range.  Keep the transport
    // counters and mark only the state that is actually observed.
    if (inputWait) {
      input["status"] = "waiting";
    }
    observation["input"] = std::move(input);
  }
  if (!observation.contains("stdout")) observation["stdout"] = stop.stdoutSnapshot.is_object() && stop.stdoutSnapshot.contains("text") ? stop.stdoutSnapshot : Json{{"text", ""}, {"totalBytes", 0}, {"retainedFromByte", 0}, {"truncated", false}};
  if (!observation.contains("stderr")) observation["stderr"] = stop.stderrSnapshot.is_object() && stop.stderrSnapshot.contains("text") ? stop.stderrSnapshot : Json{{"text", ""}, {"totalBytes", 0}, {"retainedFromByte", 0}, {"truncated", false}};
  if (!observation.contains("expressions")) observation["expressions"] = Json::array();
  if (!observation.contains("coverage")) observation["coverage"] = {{"variables", "partial"}, {"expressions", "none"}, {"memory", "none"}};
  return observation;
}

Json BackendService::makeState(const Json& observation, std::string phase,
                               std::optional<int> exitCode,
                               std::optional<std::string> signal) {
  const bool terminated = phase == "terminated";
  Json state = {{"session", {{"id", sessionId_}, {"generation", sessionGeneration_}}}, {"phase", std::move(phase)},
                {"processInstanceId", processInstanceId_.empty() ? Json(nullptr) : Json(processInstanceId_)},
                {"buildId", artifact_ ? Json(string_at(artifact_->dto, "id")) : Json(nullptr)}, {"exit", nullptr}};
  if (terminated) {
    state["exit"] = {{"code", exitCode ? Json(*exitCode) : Json(nullptr)},
                     {"signal", signal ? Json(*signal) : Json(nullptr)}};
  }
  if (!terminated && observation.is_object() && observation.contains("point") && observation.contains("stop")) {
    state["live"] = {{"point", observation["point"]}, {"stop", observation["stop"]}};
  } else state["live"] = nullptr;
  return state;
}

void BackendService::appendHistory(const Json& observation, const Json& state) {
  const auto entryBytes = observation.dump().size() + state.dump().size();
  while (!history_.empty() &&
         (history_.size() >= 4096 || historyBytes_ + entryBytes > options_.limits.maxWireBytes)) {
    const auto oldBytes = history_.front().observation.dump().size() + history_.front().state.dump().size();
    historyBytes_ -= std::min(historyBytes_, oldBytes);
    history_.erase(history_.begin());
  }
  if (entryBytes <= options_.limits.maxWireBytes) {
    history_.push_back({observation, state});
    historyBytes_ += entryBytes;
  }
  ++ordinal_; ++stateRevision_;
  liveObservation_ = observation; liveState_ = state;
}

void BackendService::emitCommandFinished(std::vector<Json>& frames, const Json& request,
                                         std::string_view outcome, std::optional<Json> error) {
  Json payload = {{"kind", "commandFinished"}, {"requestId", string_at(request, "requestId")}, {"outcome", outcome}};
  if (error) payload["error"] = *error;
  frames.push_back(event(payload, processInstanceId_, string_at(request, "requestId")));
}

std::filesystem::path BackendService::safePath(const std::string& supplied, bool allowMissing) const {
  if (supplied.empty() || supplied.find('\0') != std::string::npos) throw std::runtime_error("path is empty or contains NUL");
  std::filesystem::path candidate = supplied;
  if (candidate.is_relative()) candidate = options_.workspace / candidate;
  candidate = allowMissing ? std::filesystem::weakly_canonical(candidate) : std::filesystem::canonical(candidate);
  const auto rel = std::filesystem::relative(candidate, options_.workspace);
  if (rel == ".." || rel.native().starts_with(".." + std::string(1, std::filesystem::path::preferred_separator)) || rel.is_absolute())
    throw std::runtime_error("path escapes workspace");
  return candidate;
}

Json BackendService::handleBuild(const Json& request) {
  std::stop_token cancellation;
  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == string_at(request, "requestId")) {
      active_->ready = true;
      cancellation = active_->stop.get_token();
    }
  }
  controlWake_.notify_all();
  if (cancellation.stop_requested()) throw ProcessError(ProcessErrorCode::cancelled, "build cancelled");
  const auto& command = request.at("command");
  const auto& source = command.at("source");
  const auto& config = command.at("configuration");
  const auto architecture = command.at("architecture").get<std::string>();
  if (architecture != "x86_64") throw std::runtime_error("this Linux runner supports x86_64 only");
  const auto docs = source.at("documents");
  if (docs.empty()) throw std::runtime_error("source bundle has no documents");
  std::vector<std::string> flags;
  for (const auto& flag : config.at("flags")) flags.push_back(flag.get<std::string>());
  if (contains_flag(flags, "-o") || contains_flag(flags, "--output") || std::any_of(flags.begin(), flags.end(), redirects_output))
    throw std::runtime_error("configuration must not override output path or use response files");
  const auto compiler = config.at("compiler").get<std::string>();
  const auto bundleId = source.at("id").get<std::string>();
  const auto stamp = sha256_hex(json_text(source) + json_text(config) + architecture);
  const auto snapshotRoot = options_.buildDirectory / "sources" / stamp;
  const auto outputDirSupplied = config.at("outputDirectory").get<std::string>();
  const std::filesystem::path outputDir = safePath(outputDirSupplied, true);
  std::filesystem::create_directories(snapshotRoot);
  std::filesystem::path mainPath;
  std::vector<std::filesystem::path> translationUnits;
  std::unordered_set<std::string> snapshotPaths;
  auto sourceSnapshot = source;
  for (std::size_t documentIndex = 0; documentIndex < docs.size(); ++documentIndex) {
    const auto& document = docs.at(documentIndex);
    const auto original = safePath(document.at("path").get<std::string>(), true);
    const auto rel = std::filesystem::relative(original, options_.workspace);
    if (!snapshotPaths.insert(rel.generic_string()).second) throw std::runtime_error("source bundle contains duplicate paths");
    const auto target = snapshotRoot / rel;
    std::filesystem::create_directories(target.parent_path());
    const auto text = document.at("text").get<std::string>();
    if (document.contains("sha256")) {
      auto suppliedHash = document.at("sha256").get<std::string>();
      std::transform(suppliedHash.begin(), suppliedHash.end(), suppliedHash.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (suppliedHash != sha256_hex(text)) throw std::runtime_error("source sha256 does not match text");
    }
    std::ofstream file(target, std::ios::binary | std::ios::trunc); if (!file) throw std::runtime_error("cannot write source snapshot");
    file.write(text.data(), static_cast<std::streamsize>(text.size())); file.close();
    if (rel.extension() == ".cpp" || rel.extension() == ".cc" || rel.extension() == ".cxx") {
      if (mainPath.empty()) mainPath = target;
      translationUnits.push_back(target);
    }
    sourceSnapshot["documents"][documentIndex]["path"] = target.string();
  }
  if (mainPath.empty()) throw std::runtime_error("source bundle has no C++ translation unit");
  std::filesystem::create_directories(outputDir);
  const auto binary = outputDir / ("phantom-" + stamp);
  // Never let an old successful artifact make a failed/no-op compiler look
  // successful. The output path is private to this immutable build stamp.
  std::error_code removeError;
  std::filesystem::remove(binary, removeError);
  if (removeError) throw std::runtime_error("cannot remove stale build artifact: " + removeError.message());
  std::vector<std::string> argv{compiler}; argv.insert(argv.end(), flags.begin(), flags.end());
  for (const auto& translationUnit : translationUnits) argv.push_back(translationUnit.string());
  argv.push_back("-o"); argv.push_back(binary.string());
  if (cancellation.stop_requested()) throw ProcessError(ProcessErrorCode::cancelled, "build cancelled");
  Process process = Process::spawn({argv, options_.workspace.string(), {}, true, options_.limits.maxWireBytes});
  process.close_stdin();
  const auto result = process.wait(std::chrono::steady_clock::now() + std::chrono::milliseconds(120000), cancellation);
  const bool success = result.exit && result.exit->exit_code == 0 && std::filesystem::is_regular_file(binary);
  Json artifact = nullptr;
  if (success) {
    std::error_code sizeError;
    const auto binarySize = std::filesystem::file_size(binary, sizeError);
    if (sizeError || binarySize > maxArtifactBytes)
      throw std::runtime_error(sizeError ? "cannot inspect compiler artifact size" : "compiler artifact exceeds 256 MiB limit");
    std::ifstream in(binary, std::ios::binary); std::string bytes((std::istreambuf_iterator<char>(in)), {});
    if (!in) throw std::runtime_error("cannot read compiler artifact");
    const auto binaryHash = sha256_hex(bytes);
    Json compilerInfo = {{"path", compiler}, {"version", "unknown"}};
    try {
      Process version = Process::spawn({{compiler, "--version"}, options_.workspace.string(), {}, true, 65536}); version.close_stdin();
      const auto v = version.wait(std::chrono::steady_clock::now() + std::chrono::seconds(5), cancellation); compilerInfo["version"] = first_line(v.out);
    } catch (...) { /* Build success is still useful; capability reports unknown version. */ }
    if (cancellation.stop_requested()) throw ProcessError(ProcessErrorCode::cancelled, "build cancelled");
    const auto id = sha256_hex(stamp + binaryHash + json_text(config));
    const bool debugSymbols = std::any_of(flags.begin(), flags.end(), [](const std::string& flag) {
      return (flag == "-g" || flag.rfind("-g", 0) == 0) && flag != "-g0";
    });
    artifact = {{"id", id}, {"sourceBundleId", bundleId}, {"configurationRevisionId", config.at("revisionId")},
                {"architecture", architecture}, {"targetTriple", "x86_64-pc-linux-gnu"}, {"compiler", compilerInfo},
                {"command", argv}, {"binaryPath", binary.string()}, {"binarySha256", binaryHash}, {"debugSymbolsAvailable", debugSymbols}};
    artifact_ = Artifact{artifact, binary, sourceSnapshot};
  } else artifact_.reset();
  return okResponse(request, {{"kind", "build"}, {"artifact", artifact}, {"success", success}, {"command", argv},
                              {"stdout", result.out}, {"stderr", result.err}, {"exitCode", result.exit ? Json(result.exit->exit_code) : Json(nullptr)}, {"truncated", false}});
}

std::vector<Json> BackendService::handleLaunch(const Json& request, const FrameSink& publish) {
  std::vector<Json> frames;
  const auto staleArtifact = [&](std::string message) {
    const bool wasLive = engine_->live();
    if (wasLive) engine_->stop();
    artifact_.reset();
    frames.push_back(errorResponse(request, "STALE_CONTEXT", std::move(message), false));
    if (wasLive) publishFailedState(frames, request);
    return frames;
  };
  if (!artifact_ || string_at(artifact_->dto, "id") != request.at("command").at("buildId").get<std::string>()) {
    frames.push_back(errorResponse(request, "STALE_CONTEXT", "build artifact is unavailable", false)); return frames;
  }
  // Build identity includes the binary hash and the exact source snapshot.
  // Recheck both immediately before launching: a workspace process may have
  // replaced files after build, and GDB must never debug a different artifact
  // under the old session identity.
  {
    std::error_code sizeError;
    const auto binarySize = std::filesystem::file_size(artifact_->binary, sizeError);
    if (sizeError || binarySize > maxArtifactBytes)
      return staleArtifact(sizeError ? "build artifact cannot be inspected before launch" : "build artifact exceeds 256 MiB limit");
    std::ifstream binary(artifact_->binary, std::ios::binary);
    const std::string bytes((std::istreambuf_iterator<char>(binary)), {});
    if (!binary || sha256_hex(bytes) != string_at(artifact_->dto, "binarySha256")) {
      return staleArtifact("build artifact changed after compilation");
    }
    for (const auto& document : artifact_->source.at("documents")) {
      std::ifstream source(document.at("path").get<std::string>(), std::ios::binary);
      const std::string text((std::istreambuf_iterator<char>(source)), {});
      if (!source || sha256_hex(text) != sha256_hex(document.at("text").get<std::string>())) {
        return staleArtifact("source snapshot changed after compilation");
      }
    }
  }
  const auto& command = request.at("command");
  if (!command.value("stopAtEntry", true)) {
    frames.push_back(errorResponse(request, "UNSUPPORTED", "asynchronous launch without stopAtEntry is not enabled in the serialized GDB profile", false));
    return frames;
  }
  GdbLaunchRequest launch;
  launch.binaryPath = artifact_->binary; launch.stopAtEntry = command.value("stopAtEntry", true);
  for (const auto& arg : command.at("argv")) launch.argv.push_back(arg.get<std::string>());
  for (auto it = command.at("environment").begin(); it != command.at("environment").end(); ++it) launch.environment.emplace_back(it.key(), it.value().get<std::string>());
  launch.input = command.at("input").at("text").get<std::string>();
  launch.inputId = command.at("input").at("id").get<std::string>();
  launch.closeInputAfterWrite = command.at("input").at("closeAfterWrite").get<bool>();
  launch.sourceBundle.id = string_at(artifact_->dto, "sourceBundleId");
  for (const auto& document : artifact_->source.at("documents")) {
    launch.sourceBundle.documents.push_back({document.at("documentId"), document.at("revisionId"),
                                             safePath(document.at("path"), true), document.at("text")});
  }
  std::stop_token cancellation;
  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == string_at(request, "requestId")) {
      active_->ready = true;
      cancellation = active_->stop.get_token();
    }
  }
  controlWake_.notify_all();
  GdbError error; GdbStop stop;
  const bool launched = engine_->launch(launch, stop, error, cancellation);
  const auto interruption = activeInterruption(string_at(request, "requestId"));
  if (launched && !interruption.empty()) {
    engine_->stop();
    error = {"CANCELLED", "launch interrupted before it was accepted", true};
  }
  if (!launched || !interruption.empty()) {
    const auto code = (error.code.empty() || error.code == "READ_FAILED") ? "LAUNCH_FAILED" : error.code;
    frames.push_back(errorResponse(request, code, error.message, error.retryable));
    publishFailedState(frames, request);
    return frames;
  }
  submittedInputId_ = command.at("input").at("id").get<std::string>();
  submittedInput_ = launch.input;
  if (stop.exited) engine_->stop();
  // Sequence and history ordinals belong to a session generation. A fresh
  // launch must not replay frames or expose points from the previous run.
  sequence_ = ordinal_ = stateRevision_ = 0;
  history_.clear(); historyBytes_ = 0; eventLog_.clear(); eventBytes_ = 0; liveObservation_ = nullptr; liveState_ = nullptr;
  sessionId_ = make_id("session", ++sessionGeneration_); processInstanceId_ = stop.processInstanceId.empty() ? make_id("process", sessionGeneration_) : stop.processInstanceId;
  const auto accepted = okResponse(request, {{"kind", "launchAccepted"}, {"session", {{"id", sessionId_}, {"generation", sessionGeneration_}}}, {"throughSequence", sequence_}});
  if (publish) publish(accepted); else frames.push_back(accepted);
  auto observation = makeObservation(stop, stop.exited ? "exit" : "entry");
  auto state = makeState(observation, stop.exited ? "terminated" : "stopped", stop.exitCode,
                         stop.signalName.empty() ? std::nullopt : std::optional<std::string>(stop.signalName));
  appendHistory(observation, state);
  frames.push_back(event({{"kind", "observation"}, {"observation", observation}}, processInstanceId_, string_at(request, "requestId")));
  frames.push_back(event({{"kind", "state"}, {"state", state}}, processInstanceId_, string_at(request, "requestId")));
  emitCommandFinished(frames, request, "completed");
  return frames;
}

std::vector<Json> BackendService::handleExecution(const Json& request, std::string_view kind, const FrameSink& publish) {
  std::vector<Json> frames;
  const auto accepted = okResponse(request, {{"kind", "accepted"}});
  if (publish) publish(accepted); else frames.push_back(accepted);
  try {
  std::string interruption;
  {
    std::lock_guard controlLock(controlMutex_);
    if (active_ && active_->id == string_at(request, "requestId")) {
      // Mark the point at which a control request may safely interrupt this
      // operation. GDB's resume path carries an interrupt that races this
      // hand-off across its command write boundary.
      active_->ready = true;
      interruption = active_->interruption;
    }
  }
  controlWake_.notify_all();
  GdbError error; GdbStop stop;
  if (kind == "stop") {
    stop = engine_->stopAndSnapshot();
    stop.exited = true;
    stop.processInstanceId = processInstanceId_;
  }
  // All execution requests are serialized. If pause reaches this path the
  // inferior is already stopped; an asynchronous interrupt would have no new
  // stop record to wait for and would incorrectly time out.
  if (kind == "pause" && (liveState_.value("phase", "") == "stopped" ||
                           liveState_.value("phase", "") == "waitingForInput")) {
    emitCommandFinished(frames, request, "completed");
    return frames;
  }
  if (kind == "pause" && !engine_->pause(stop, error)) {
    interruption = activeInterruption(string_at(request, "requestId"));
    publishFailedState(frames, request);
    const Json err = {{"code", error.code.empty() ? "INTERNAL" : error.code}, {"message", error.message}, {"retryable", error.retryable}};
    emitCommandFinished(frames, request, "failed", err); return frames;
  }
  if (kind != "stop" && kind != "pause" && !engine_->resume(kind == "step" ? request.at("command").at("stepKind").get<std::string>() : "continue", stop, error)) {
    interruption = activeInterruption(string_at(request, "requestId"));
    // A source-level step can have no different line to reach (the common
    // `while (true) { continue; }` case).  GDB was interrupted at the step
    // deadline and returned a real stopped snapshot; keep that session live.
    // A blocked stdin read is reported separately as a recoverable input wait.
    if ((error.code == "STEP_TIMEOUT" || error.code == "INPUT_WAIT") && stop.stopped && engine_->live()) {
      const bool inputWait = error.code == "INPUT_WAIT" || stop.reason == "input-wait";
      auto observation = makeObservation(stop, inputWait ? "input-wait" : "step-timeout");
      auto state = makeState(observation, inputWait ? "waitingForInput" : "stopped", stop.exitCode,
                             stop.signalName.empty() ? std::nullopt : std::optional<std::string>(stop.signalName));
      appendHistory(observation, state);
      frames.push_back(event({{"kind", "observation"}, {"observation", observation}}, processInstanceId_, string_at(request, "requestId")));
      frames.push_back(event({{"kind", "state"}, {"state", state}}, processInstanceId_, string_at(request, "requestId")));
      const Json err = {{"code", error.code}, {"message", error.message}, {"retryable", error.retryable}};
      emitCommandFinished(frames, request, inputWait ? "waiting" : "failed", err);
      return frames;
    }
    if (interruption == "stop") {
      stop = engine_->stopAndSnapshot();
      stop.exited = true; stop.processInstanceId = processInstanceId_; stop.reason = "stop";
      auto observation = makeObservation(stop, "exit");
      auto state = makeState(observation, "terminated"); appendHistory(observation, state);
      frames.push_back(event({{"kind", "observation"}, {"observation", observation}}, processInstanceId_, string_at(request, "requestId")));
      frames.push_back(event({{"kind", "state"}, {"state", state}}, processInstanceId_, string_at(request, "requestId")));
      emitCommandFinished(frames, request, "completed");
      return frames;
    }
    publishFailedState(frames, request);
    const Json err = {{"code", error.code.empty() ? "INTERNAL" : error.code}, {"message", error.message}, {"retryable", error.retryable}};
    emitCommandFinished(frames, request, "failed", err); return frames;
  }
  interruption = activeInterruption(string_at(request, "requestId"));
  if (interruption == "stop" && !stop.exited) {
    stop = engine_->stopAndSnapshot();
    stop.exited = true;
    stop.processInstanceId = processInstanceId_;
  }
  if (stop.exited) engine_->stop();
  const auto reason = stop.exited ? "exit" :
      (interruption == "pause" || kind == "pause" ? "pause" :
       stop.reason == "breakpoint-hit" ? "breakpoint" :
       stop.reason.find("signal") != std::string::npos ? "signal" : "step");
  auto observation = makeObservation(stop, reason);
  auto state = makeState(observation, stop.exited ? "terminated" : "stopped", stop.exitCode,
                         stop.signalName.empty() ? std::nullopt : std::optional<std::string>(stop.signalName));
  appendHistory(observation, state);
  frames.push_back(event({{"kind", "observation"}, {"observation", observation}}, processInstanceId_, string_at(request, "requestId")));
  frames.push_back(event({{"kind", "state"}, {"state", state}}, processInstanceId_, string_at(request, "requestId")));
  emitCommandFinished(frames, request, interruption == "cancel" ? "cancelled" : "completed"); return frames;
  } catch (const std::exception& error) {
    // Acceptance has already been published. An unexpected adapter error
    // must finish that command, never produce a contradictory second reply.
    engine_->stop();
    (void)activeInterruption(string_at(request, "requestId"));
    publishFailedState(frames, request);
    emitCommandFinished(frames, request, "failed",
                        Json{{"code", "INTERNAL"}, {"message", error.what()}, {"retryable", true}});
    return frames;
  }
}

Json BackendService::handleInput(const Json& request) {
  const auto& command = request.at("command");
  Json input;
  GdbError error;
  bool ok = false;
  if (command.at("kind") == "appendInput")
    ok = engine_->appendInput(command.at("id").get<std::string>(), command.at("text").get<std::string>(), input, error);
  else
    ok = engine_->closeInput(input, error);
  if (!ok) return errorResponse(request, error.code.empty() ? "INTERNAL" : error.code, error.message, error.retryable);
  submittedInputId_ = input.at("submitted").at("id").get<std::string>();
  submittedInput_ = input.at("submitted").at("text").get<std::string>();
  return okResponse(request, {{"kind", "input"}, {"input", std::move(input)}});
}

Json BackendService::handleHistory(const Json& request) {
  const auto& command = request.at("command"); const auto kind = command.at("kind").get<std::string>();
  if ((kind == "listHistory" && command.at("branchId") != "main") ||
      (kind == "readHistory" && command.at("point").at("branchId") != "main"))
    return errorResponse(request, "STALE_CONTEXT", "only the live main branch exists", false);
  if (kind == "readHistory") {
    const auto point = command.at("point"); const auto ordinal = point.at("eventOrdinal").get<std::uint64_t>();
    auto it = std::find_if(history_.begin(), history_.end(), [ordinal](const auto& e) { return e.observation.value("point", Json::object()).value("eventOrdinal", 0ULL) == ordinal; });
    if (it == history_.end()) return errorResponse(request, "HISTORY_EVICTED", "history point is unavailable", false);
    return okResponse(request, {{"kind", "observation"}, {"observation", it->observation}});
  }
  Json items = Json::array(); const auto after = command.at("afterOrdinal").is_null() ? 0ULL : command.at("afterOrdinal").get<std::uint64_t>(); const auto limit = std::min<std::size_t>(command.at("limit").get<std::size_t>(), options_.limits.maxPageSize);
  bool hasMore = false;
  for (const auto& entry : history_) {
    const auto p = entry.observation.at("point"); const auto ord = p.at("eventOrdinal").get<std::uint64_t>();
    if (ord <= after) continue;
    if (items.size() >= limit) { hasMore = true; break; }
    items.push_back({{"point", p}, {"stop", entry.observation.at("stop")}, {"label", entry.observation.value("reason", "stop")}, {"retained", true}});
  }
  return okResponse(request, {{"kind", "history"}, {"items", items}, {"hasMore", hasMore}});
}

std::vector<Json> BackendService::connect(const Json& request) {
  std::lock_guard lock(mutex_);
  const bool wasConnected = connected_;
  connected_ = true;
  if (request.contains("supportedProtocolVersions") && !std::any_of(request.at("supportedProtocolVersions").begin(), request.at("supportedProtocolVersions").end(), [](const auto& v) { return v == 1; }))
    { connected_ = wasConnected; return {{{"kind", "connectResult"}, {"ok", false}, {"protocolVersion", 1}, {"error", {{"code", "UNSUPPORTED"}, {"message", "protocol version 1 is not supported by the client"}, {"retryable", false}}}}}; }
  if (request.contains("workspace") && request.at("workspace") != workspace_) {
    // A workspace identity change cannot reuse an artifact, inferior or
    // history from the previous project.  Tear down the owned debugger before
    // publishing the new checkpoint.
    if (engine_) engine_->stop();
    artifact_.reset(); sessionId_.clear(); processInstanceId_.clear();
    liveState_ = nullptr; liveObservation_ = nullptr; history_.clear(); historyBytes_ = 0; eventLog_.clear(); eventBytes_ = 0;
    sequence_ = ordinal_ = stateRevision_ = 0;
    workspace_ = request.at("workspace");
  }
  return {{{"kind", "connectResult"}, {"ok", true}, {"protocolVersion", 1}, {"workspace", workspace_}, {"session", sessionId_.empty() ? Json(nullptr) : Json{{"id", sessionId_}, {"generation", sessionGeneration_}}}, {"state", liveState_}, {"observation", liveObservation_}, {"capabilities", capabilities()}, {"throughSequence", sequence_}}};
}

std::vector<Json> BackendService::request(const Json& request, FrameSink publish) {
  try { validate_request(request, options_.limits); } catch (const ValidationError& e) { return {errorResponse(request, e.code, e.what(), false)}; }
  std::lock_guard lock(mutex_);
  try {
    const auto kind = request.at("command").at("kind").get<std::string>();
    if (!connected_) return {errorResponse(request, "INVALID_REQUEST", "connect must be the first protocol frame", false)};
    if (request.at("workspace") != workspace_) return {errorResponse(request, "STALE_CONTEXT", "request workspace does not match the connected workspace", false)};
    if (!request.at("session").is_null() &&
        (sessionId_.empty() || request.at("session").at("id").get<std::string>() != sessionId_ ||
         request.at("session").at("generation").get<std::uint64_t>() != sessionGeneration_))
      return {errorResponse(request, "STALE_CONTEXT", "request session does not match the live session", false)};
    if ((kind == "listHistory" || kind == "readHistory" || kind == "replayEvents") &&
        !sessionId_.empty() && request.at("session").is_null())
      return {errorResponse(request, "STALE_CONTEXT", "history belongs to the current debugging session", false)};
    // pause/stop/cancel may already have interrupted the active GDB command
    // on the transport reader thread. Their queued protocol frame is an
    // acknowledgement, not a second debugger operation; issuing another
    // -exec-interrupt here would race the stop record and duplicate history.
    if (kind == "pause" || kind == "stop" || kind == "cancel") {
      bool wasApplied = false;
      {
        std::lock_guard controlLock(controlMutex_);
        const auto applied = appliedControls_.find(string_at(request, "requestId"));
        if (applied != appliedControls_.end() && applied->second == request) {
          wasApplied = true;
          appliedControls_.erase(applied);
        }
      }
      if (wasApplied) {
        std::vector<Json> frames{okResponse(request, {{"kind", "accepted"}})};
        emitCommandFinished(frames, request, "completed");
        return frames;
      }
    }
    if (shuttingDown_.load() && (kind == "build" || kind == "launch" || kind == "step" ||
                                 kind == "continue" || kind == "pause" || kind == "stop" ||
                                 kind == "appendInput" || kind == "closeInput"))
      return {errorResponse(request, "CANCELLED", "transport is shutting down", false)};
    const bool liveCommand = kind == "step" || kind == "continue" || kind == "pause" || kind == "stop" || kind == "appendInput" || kind == "closeInput" ||
                             kind == "readVariables" || kind == "readMemory" || kind == "disassemble" ||
                             kind == "setBreakpoints" || kind == "writeVariable";
    if (liveCommand && (request.at("session").is_null() || sessionId_.empty()))
      return {errorResponse(request, "STALE_CONTEXT", "a live session is required for this command", false)};
    if (liveCommand && !engine_->live())
      return engineError(request, {"STALE_CONTEXT", "the session has no live inferior", false});
    if (request.contains("expectedStop")) {
      const auto& expected = request.at("expectedStop");
      const bool matches = liveObservation_.is_object() && liveObservation_.contains("stop") &&
                           liveObservation_.at("stop") == expected;
      if (!matches) return {errorResponse(request, "STALE_CONTEXT", "expectedStop is no longer current", false)};
    }
    const bool longOperation = kind == "build" || kind == "launch" || kind == "step" || kind == "continue" || kind == "pause" || kind == "stop";
    std::optional<std::string> activeId;
    if (longOperation) {
      const auto requestId = string_at(request, "requestId");
      {
        std::lock_guard controlLock(controlMutex_);
        active_ = ActiveRequest{requestId, request.at("workspace"), request.at("session"), kind, {}, {}, false,
                                liveObservation_.is_object() ? liveObservation_.value("stop", Json(nullptr)) : Json(nullptr)};
        if (shuttingDown_.load()) active_->stop.request_stop();
      }
      controlWake_.notify_all();
      activeId = requestId;
    }
    struct ScopeExit { std::function<void()> callback; ~ScopeExit() { if (callback) callback(); } } clear{[this, activeId] {
      if (activeId) clearActive(*activeId);
    }};
    if (kind == "capabilities") return {okResponse(request, {{"kind", "capabilities"}, {"capabilities", capabilities()}})};
    if (kind == "getState") {
      // v1's state result describes an assigned session and is non-null.
      // Before the first launch, connect supplies the nullable checkpoint.
      if (liveState_.is_null())
        return {errorResponse(request, "STALE_CONTEXT", "no debugging session has been established", false)};
      return {okResponse(request, {{"kind", "state"}, {"state", liveState_}, {"observation", liveObservation_}, {"throughSequence", sequence_}})};
    }
    if (kind == "build") {
      if (engine_->live())
        return {errorResponse(request, "STALE_CONTEXT", "stop the current inferior before replacing its build artifact", false)};
      try {
        auto response = handleBuild(request);
        if (activeInterruption(string_at(request, "requestId")) == "cancel") {
          artifact_.reset();
          return {errorResponse(request, "CANCELLED", "build cancelled", false)};
        }
        return {std::move(response)};
      }
      catch (const ProcessError& error) {
        artifact_.reset();
        const auto code = error.code() == ProcessErrorCode::cancelled ? "CANCELLED" :
                          error.code() == ProcessErrorCode::timeout ? "TIMEOUT" : "BUILD_FAILED";
        return {errorResponse(request, code, error.what(), false)};
      }
      catch (const std::exception& e) { artifact_.reset(); return {errorResponse(request, "BUILD_FAILED", e.what(), false)}; }
    }
    if (kind == "launch") return handleLaunch(request, publish);
    if (kind == "appendInput" || kind == "closeInput") return {handleInput(request)};
    if (kind == "step" || kind == "continue" || kind == "pause" || kind == "stop") return handleExecution(request, kind, publish);
    if (kind == "listHistory" || kind == "readHistory") return {handleHistory(request)};
    if (kind == "replayEvents") {
      const auto after = request.at("command").at("afterSequence").get<std::uint64_t>(); Json events = Json::array();
      if ((eventLog_.empty() && after < sequence_) ||
          (!eventLog_.empty() && after < eventLog_.front().value("sequence", 0ULL) - 1))
        return {errorResponse(request, "EVENT_GAP", "requested event sequence has been evicted", true)};
      for (const auto& frame : eventLog_) if (frame.value("sequence", 0ULL) > after) events.push_back(frame);
      return {okResponse(request, {{"kind", "events"}, {"events", events}})};
    }
    if (kind == "setBreakpoints") {
      const auto& command = request.at("command");
      const auto documentId = command.at("documentId").get<std::string>();
      const auto revisionId = command.at("revisionId").get<std::string>();
      bool documentMatches = false;
      if (artifact_) for (const auto& document : artifact_->source.at("documents"))
        if (document.at("documentId") == documentId && document.at("revisionId") == revisionId) { documentMatches = true; break; }
      if (!documentMatches) return {errorResponse(request, "STALE_CONTEXT", "breakpoint document revision is not part of the built source bundle", false)};
      for (const auto& breakpoint : command.at("breakpoints")) {
        if (!breakpoint.at("range").is_null() &&
            (breakpoint.at("range").at("documentId") != documentId || breakpoint.at("range").at("revisionId") != revisionId))
          return {errorResponse(request, "STALE_CONTEXT", "breakpoint range identity does not match the command document", false)};
      }
      Json result; GdbError error;
      if (!engine_->setBreakpoints(command, result, error)) return engineError(request, error);
      return {okResponse(request, {{"kind", "breakpoints"}, {"breakpoints", result}})};
    }
    if (kind == "readVariables") { Json result; GdbError error; const auto& c=request.at("command"); if (!engine_->readVariables(c.at("reference").get<std::string>(), c.at("start").get<std::size_t>(), c.at("count").get<std::size_t>(), result, error)) return engineError(request, error); result["kind"] = "variables"; return {okResponse(request, std::move(result))}; }
    if (kind == "readMemory") { Json result; GdbError error; const auto& c=request.at("command"); if (!engine_->readMemory(c.at("addressHex").get<std::string>(), c.at("byteCount").get<std::size_t>(), result, error)) return engineError(request, error); result["kind"] = "memory"; return {okResponse(request,std::move(result))}; }
    if (kind == "disassemble") {
      Json result; GdbError error; const auto& c = request.at("command");
      if (!artifact_ || c.at("buildId").get<std::string>() != string_at(artifact_->dto, "id"))
        return {errorResponse(request, "STALE_CONTEXT", "disassembly artifact is not the current build", false)};
      if (c.at("target").at("kind") != "pc") return {errorResponse(request,"UNSUPPORTED","source disassembly requires DWARF line mapping",false)};
      if (!engine_->disassemble(c.at("target").at("addressHex").get<std::string>(),c.at("maxInstructions").get<std::size_t>(),result,error)) return engineError(request, error);
      result["kind"] = "asm"; result["architecture"] = "x86_64"; return {okResponse(request,std::move(result))};
    }
    if (kind == "writeVariable") return {errorResponse(request, "UNSUPPORTED", "variable writes are disabled until typed readback and audit are implemented", false)};
    if (kind == "cancel") {
      return {errorResponse(request, "STALE_CONTEXT", "cancel target is no longer active", false)};
    }
    return {errorResponse(request, "UNSUPPORTED", "command is not implemented", false)};
  } catch (const std::exception& e) { return engineError(request, {"INTERNAL", e.what(), false}); }
}

std::optional<Json> BackendService::inputControl(const Json& request, bool waitForActive) {
  try { validate_request(request, options_.limits); } catch (...) { return std::nullopt; }
  const auto kind = request.at("command").at("kind").get<std::string>();
  if (kind != "appendInput" && kind != "closeInput") return std::nullopt;
  std::unique_lock controlLock(controlMutex_);
  if (waitForActive && (!active_ || !active_->ready))
    controlWake_.wait_for(controlLock, std::chrono::seconds(2), [this] {
      return (active_.has_value() && active_->ready) || shuttingDown_.load();
    });
  if (!active_ || !active_->ready) return std::nullopt;
  if (active_->kind != "continue" && active_->kind != "step")
    return errorResponse(request, "BUSY", "interactive input is available while execution is running", true);
  if (request.at("workspace") != active_->workspace || request.at("session") != active_->session)
    return errorResponse(request, "STALE_CONTEXT", "input request does not match the active session", false);
  if (request.at("expectedStop") != active_->expectedStop)
    return errorResponse(request, "STALE_CONTEXT", "expectedStop is no longer current", false);
  Json input; GdbError error;
  bool ok = kind == "appendInput"
      ? engine_->appendInput(request.at("command").at("id").get<std::string>(), request.at("command").at("text").get<std::string>(), input, error)
      : engine_->closeInput(input, error);
  if (!ok) return errorResponse(request, error.code.empty() ? "INTERNAL" : error.code, error.message, error.retryable);
  return okResponse(request, {{"kind", "input"}, {"input", std::move(input)}});
}

bool BackendService::control(const Json& request, bool waitForActive) {
  try { validate_request(request, options_.limits); } catch (...) { return false; }
  const auto kind = request.at("command").at("kind").get<std::string>();
  if (kind != "pause" && kind != "stop" && kind != "cancel") return false;
  const auto requestId = string_at(request, "requestId");
  std::unique_lock controlLock(controlMutex_);
  // The reader can see a control line before the worker has popped the
  // preceding execution line from its bounded queue. This includes a cancel
  // for an initial launch whose session is still null. Wait only for the
  // short dequeue handoff and never take the service's long-held mutex.
  if (waitForActive && (!active_ || !active_->ready))
    controlWake_.wait_for(controlLock, std::chrono::seconds(2), [this] {
      return (active_.has_value() && active_->ready) || shuttingDown_.load();
    });
  if (!active_ || !active_->ready) return false;
  if (active_->kind != "build" && active_->kind != "launch" && active_->kind != "step" && active_->kind != "continue") return false;
  if (active_->kind == "build" && kind != "cancel") return false;
  if (active_->kind == "launch" && kind == "pause") return false;
  if (request.at("workspace") != active_->workspace || request.at("session") != active_->session) return false;
  if (kind == "cancel" && request.at("command").at("targetRequestId") != active_->id) return false;
  if (request.contains("expectedStop") && request.at("expectedStop") != active_->expectedStop) return false;
  appliedControls_.insert_or_assign(requestId, request);
  // Termination dominates cancellation, which dominates pause. A later
  // pause must not erase a cancellation that was already applied.
  if (kind == "stop" || active_->interruption.empty() ||
      (kind == "cancel" && active_->interruption == "pause"))
    active_->interruption = kind;
  if (active_->kind == "launch" || active_->kind == "build") active_->stop.request_stop();
  if (active_->kind != "build") engine_->interrupt(kind == "stop" || active_->kind == "launch" ? 2 : 1);
  return true;
}

void BackendService::dispose() noexcept {
  shuttingDown_.store(true);
  std::lock_guard lock(mutex_);
  if (engine_) engine_->stop();
  {
    std::lock_guard controlLock(controlMutex_);
    active_.reset();
    appliedControls_.clear();
  }
  controlWake_.notify_all();
  connected_ = false; sessionId_.clear(); processInstanceId_.clear();
}
void BackendService::interrupt(int mode) noexcept {
  if (mode >= 2) shuttingDown_.store(true);
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && (active_->kind == "launch" || active_->kind == "build")) active_->stop.request_stop();
  }
  controlWake_.notify_all();
  if (engine_) engine_->interrupt(mode);
}
} // namespace phantom
