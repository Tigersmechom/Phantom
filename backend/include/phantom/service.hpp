#pragma once

#include "phantom/gdb.hpp"
#include "phantom/output_journal.hpp"
#include "phantom/validation.hpp"

#include <condition_variable>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace phantom {

struct ServiceOptions {
  std::filesystem::path workspace;
  std::filesystem::path buildDirectory;
  std::string backendVersion = "0.1.0";
  ValidationLimits limits{};
  std::filesystem::path ioWrapper;
  std::filesystem::path recorderProbeFixture;
  std::string gdbPath = "gdb";
};

// The service is intentionally transport-agnostic. One caller owns the
// dispatch sequence; the NDJSON front end converts each returned frame to one
// line. Every history item is a copied JSON snapshot and is never updated by a
// later live read.
class BackendService final {
 public:
  explicit BackendService(ServiceOptions options);
  ~BackendService();
  BackendService(const BackendService&) = delete;
  BackendService& operator=(const BackendService&) = delete;

  std::vector<Json> connect(const Json& request);
  using FrameSink = std::function<void(const Json&)>;
  std::vector<Json> request(const Json& request, FrameSink publish = {});
  // The transport may submit a validated control request while the worker is
  // executing. Context and target matching happen before any signal is sent.
  bool control(const Json& request, bool waitForActive = true);
  // Input can unblock an executing inferior, so its response cannot wait
  // behind that execution request. nullopt asks the normal worker to handle
  // a stopped-session command (or canonical validation/context error).
  std::optional<Json> inputControl(const Json& request, bool waitForActive = true);
  // May be called by the transport reader while the serialized worker is in
  // a long-running GDB command. It never waits for the service mutex; when a
  // control frame races dequeue of its target, it waits briefly on the
  // control condition so the active request can be matched first.
  void interrupt(int mode = 1) noexcept;
  void dispose() noexcept;

 private:
  struct Artifact { Json dto; std::filesystem::path binary; Json source; };
  struct HistoryEntry { Json observation; Json state; };
  Json capabilities() const;
  Json errorResponse(const Json& request, std::string code, std::string message,
                     bool retryable = false) const;
  Json okResponse(const Json& request, Json result) const;
  Json event(const Json& payload, std::optional<std::string> process = std::nullopt,
             std::optional<std::string> causedBy = std::nullopt);
  Json makeObservation(const GdbStop& stop, std::string reason);
  Json makeState(const Json& observation, std::string phase,
                 std::optional<int> exitCode = std::nullopt,
                 std::optional<std::string> signal = std::nullopt);
  Json defaultInput() const;
  Json handleBuild(const Json& request);
  Json handleRecorderProbe(const Json& request);
  std::vector<Json> handleRecordedExecution(const Json& request, const FrameSink& publish);
  std::vector<Json> handleModules(const Json& request);
  std::vector<Json> handleModuleSymbols(const Json& request);
  std::vector<Json> handleVariableLayout(const Json& request);
  std::vector<Json> handleVtable(const Json& request);
  std::vector<Json> handleMemoryIntervention(const Json& request);
  std::vector<Json> handleLaunch(const Json& request, const FrameSink& publish);
  std::vector<Json> handleExecution(const Json& request, std::string_view kind, const FrameSink& publish);
  Json handleInput(const Json& request);
  std::vector<Json> handleInspection(const Json& request);
  std::vector<Json> handleTrace(const Json& request, const FrameSink& publish);
  std::string storeInspection(Json value, std::string_view prefix);
  Json handleHistory(const Json& request);
  std::filesystem::path safePath(const std::string& supplied, bool allowMissing) const;
  void appendHistory(const Json& observation, const Json& state);
  void clearActive(std::string_view requestId) noexcept;
  std::string activeInterruption(std::string_view requestId);
  void publishFailedState(std::vector<Json>& frames, const Json& request);
  std::vector<Json> engineError(const Json& request, const GdbError& error);
  void emitCommandFinished(std::vector<Json>& frames, const Json& request,
                           std::string_view outcome,
                           std::optional<Json> error = std::nullopt);

  ServiceOptions options_;
  mutable std::mutex mutex_;
  mutable std::mutex controlMutex_;
  std::condition_variable controlWake_;
  struct ActiveRequest {
    std::string id;
    Json workspace;
    Json session;
    std::string kind;
    std::stop_source stop;
    std::string interruption;
    bool ready = false;
    Json expectedStop = nullptr;
  };
  std::optional<ActiveRequest> active_;
  std::map<std::string, Json> appliedControls_;
  std::atomic<bool> shuttingDown_{false};
  bool connected_ = false;
  Json workspace_ = Json{{"id", "workspace-local"}, {"revisionId", "workspace-0"}};
  std::optional<Artifact> artifact_;
  std::unique_ptr<GdbEngine> engine_;
  std::string submittedInputId_ = "input-none";
  std::string submittedInput_;
  std::string sessionId_;
  std::string processInstanceId_;
  std::uint64_t sessionGeneration_ = 0;
  std::uint64_t sequence_ = 0;
  std::uint64_t ordinal_ = 0;
  std::uint64_t stateRevision_ = 0;
  std::string currentBranchId_ = "main";
  Json branches_ = Json::array({{{"id", "main"}, {"parent", nullptr}, {"interventionId", nullptr}}});
  // Session ledger: never silently evicted. Capacity is reserved before writes;
  // a retry returns its original response without repeating events or effects.
  struct InterventionEntry { Json request; Json response; };
  std::vector<InterventionEntry> interventions_;
  static constexpr std::size_t maxInterventions = 128;
  static constexpr std::size_t interventionReservation = 32768;
  Json executionLayout_ = nullptr;
  OutputJournal stdoutJournal_, stderrJournal_;
  bool outputJournalConsistent_ = true;
  // Proven transport prefixes at observed instruction boundaries only.
  std::map<std::uint64_t, std::pair<std::uint64_t, std::uint64_t>> recordingOutputMarkers_;
  struct InspectionEntry { std::string id; Json value; std::size_t bytes; };
  std::vector<InspectionEntry> inspectionStore_;
  std::size_t inspectionBytes_ = 0;
  std::uint64_t inspectionCounter_ = 0;
  Json liveState_ = nullptr;
  Json liveObservation_ = nullptr;
  std::vector<HistoryEntry> history_;
  std::size_t historyBytes_ = 0;
  std::vector<Json> eventLog_;
  std::size_t eventBytes_ = 0;
};

} // namespace phantom
