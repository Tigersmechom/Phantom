#include "phantom/service.hpp"

namespace phantom {

std::vector<Json> BackendService::handleRuntimeProtection(const Json& request) {
  synchronizeRuntimeAllocations();
  if (!liveObservation_.is_object() || liveState_.value("phase", "") != "stopped")
    return {errorResponse(request, "STALE_CONTEXT", "runtime protection requires a stopped native session outside input wait")};
  if (!artifact_ || !artifact_->dto.contains("runtimeHelper"))
    return {errorResponse(request, "UNSUPPORTED", "build did not opt into the runtime helper profile")};
  const auto maps = liveObservation_.value("memoryMap", Json(nullptr));
  if (!maps.is_object() || !maps.value("available", false) || maps.value("coverage", "") != "complete")
    return {errorResponse(request, "UNSUPPORTED", "runtime protection requires a complete current memory map")};

  const auto& command = request.at("command");
  Json* owned = nullptr;
  for (auto& allocation : runtimeAllocations_)
    if (allocation.at("id") == command.at("allocationId")) { owned = &allocation; break; }
  if (!owned || owned->at("state") != "owned" || owned->at("processInstanceId") != processInstanceId_)
    return {errorResponse(request, "STALE_CONTEXT", "allocation has no protection authority at this stop")};
  if (owned->at("permissions") != command.at("expectedPermissions"))
    return {errorResponse(request, "STALE_CONTEXT", "expected permissions do not match the owned allocation")};
  if (const auto failure = interventionBudgetError(request, interventionReservation)) return {*failure};

  const auto saved = *owned;
  auto audit = beginIntervention(request);
  const auto interventionId = audit.at("id");
  audit["action"] = "protect";
  audit["target"] = {{"allocationId", owned->at("id")}, {"addressHex", owned->at("addressHex")},
      {"byteCount", owned->at("byteCount")}, {"expectedPermissions", command.at("expectedPermissions")},
      {"replacementPermissions", command.at("replacementPermissions")}};
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
  // The service worker serializes registry access. Only a proven read-only
  // rejection or a verified operation can preserve the earlier authority.
  (*owned)["state"] = "ownership-unknown";
  (*owned)["invalidatedByRequestId"] = requestId;
  Json report, afterMaps;
  GdbError error;
  const bool success = engine_->executeRuntimeProtection(artifact_->dto.at("runtimeHelper"),
      saved.at("addressHex").get<std::string>(), saved.at("byteCount").get<std::size_t>(),
      command.at("expectedPermissions").get<std::string>(), command.at("replacementPermissions").get<std::string>(),
      report, afterMaps, error, cancellation);
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) {
      active_->ready = false;
      if (active_->interruption == "cancel" || cancellation.stop_requested()) report["cancelled"] = true;
    }
  }
  if (!report.value("writeAttempted", false)) {
    *owned = saved;
    synchronizeRuntimeAllocations();
    if (report.value("cancelled", false))
      return engineError(request, {"CANCELLED", "runtime protection cancelled before execution", false});
    return engineError(request, error.code.empty()
        ? GdbError{"UNSUPPORTED", "runtime protection preflight did not establish support", false} : error);
  }
  if (!success && engine_->live()) engine_->stop();
  if (success) {
    const auto& proof = report.at("evidence");
    if (proof.at("addressHex") != saved.at("addressHex") || proof.at("byteCount") != saved.at("byteCount") ||
        proof.at("beforePermissions") != command.at("expectedPermissions") ||
        proof.at("afterPermissions") != command.at("replacementPermissions") ||
        !afterMaps.is_object() || !afterMaps.value("available", false) || afterMaps.value("coverage", "") != "complete") {
      engine_->stop();
      report["outcome"] = "failed";
      report["debuggerAlive"] = false;
      report["error"] = {{"code", "READ_FAILED"}, {"message", "runtime protection proof does not match the owned allocation"}};
      report["evidence"] = nullptr;
    } else {
      *owned = saved;
      (*owned)["permissions"] = command.at("replacementPermissions");
      (*owned)["lastProtectionInterventionId"] = interventionId;
    }
  }
  audit["report"] = std::move(report);
  auto frames = finishIntervention(request, std::move(audit), "runtimeProtectionIntervention",
                                  interventionReservation, afterMaps);
  synchronizeRuntimeAllocations();
  return frames;
}

}  // namespace phantom
