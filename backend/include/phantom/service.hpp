#pragma once

#include "phantom/gdb.hpp"
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
  bool control(const Json& request);
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
  std::vector<Json> handleLaunch(const Json& request, const FrameSink& publish);
  std::vector<Json> handleExecution(const Json& request, std::string_view kind, const FrameSink& publish);
  Json handleHistory(const Json& request);
  std::filesystem::path safePath(const std::string& supplied, bool allowMissing) const;
  void appendHistory(const Json& observation, const Json& state);
  void clearActive(std::string_view requestId) noexcept;
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
  Json liveState_ = nullptr;
  Json liveObservation_ = nullptr;
  std::vector<HistoryEntry> history_;
  std::size_t historyBytes_ = 0;
  std::vector<Json> eventLog_;
  std::size_t eventBytes_ = 0;
};

} // namespace phantom
