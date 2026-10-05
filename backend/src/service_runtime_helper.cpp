#include "phantom/service.hpp"

namespace phantom {

std::vector<Json> BackendService::handleRuntimeIntervention(const Json& request) {
  if (!liveObservation_.is_object() || liveState_.value("phase", "") != "stopped")
    return {errorResponse(request, "STALE_CONTEXT", "runtime helper requires a stopped native session outside an input wait")};
  if (!artifact_ || !artifact_->dto.contains("runtimeHelper"))
    return {errorResponse(request, "UNSUPPORTED", "build did not opt into the runtime helper profile")};
  const auto originalMaps = liveObservation_.value("memoryMap", Json(nullptr));
  if (!originalMaps.is_object() || !originalMaps.value("available", false) ||
      originalMaps.value("coverage", "") != "complete")
    return {errorResponse(request, "UNSUPPORTED", "runtime helper requires a complete current memory map")};
  if (const auto failure = interventionBudgetError(request, interventionReservation)) return {*failure};

  // Reserve identity and retention before the engine can alter registers or
  // execute a syscall. Even a lost execution acknowledgement needs an audit.
  auto audit = beginIntervention(request);
  audit["target"] = artifact_->dto.at("runtimeHelper");
  const auto requestId = request.at("requestId").get<std::string>();
  std::stop_token cancellation;
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) {
      cancellation = active_->stop.get_token();
      active_->ready = true;
    }
  }
  controlWake_.notify_all();

  Json report;
  GdbError error;
  const bool success = engine_->executeRuntimeHelper(audit.at("target"), report, error, cancellation);
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) {
      active_->ready = false;
      // A late cancel cannot erase proof of an already completed operation.
      // Keep the actual outcome and separately record the accepted request.
      if (active_->interruption == "cancel" || cancellation.stop_requested())
        report["cancelled"] = true;
    }
  }
  if (!report.value("writeAttempted", false)) {
    if (report.value("cancelled", false))
      return engineError(request, {"CANCELLED", "runtime helper cancelled before execution", false});
    return engineError(request, error.code.empty()
        ? GdbError{"UNSUPPORTED", "runtime helper preflight did not establish support", false} : error);
  }
  // The engine must close the session on every unverified attempted operation.
  // This also prevents a stale pre-helper stop from being presented as current.
  if (!success && engine_->live()) engine_->stop();
  audit["report"] = std::move(report);
  return finishIntervention(request, std::move(audit), "runtimeIntervention",
                            interventionReservation, originalMaps);
}

}  // namespace phantom
