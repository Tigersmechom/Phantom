#include "phantom/service.hpp"

#include <algorithm>
#include <unistd.h>

namespace phantom {

void BackendService::revokeRuntimeAllocations(std::string_view requestId) {
  for (auto& allocation : runtimeAllocations_) {
    if (allocation.at("state") != "owned") continue;
    allocation["state"] = "ownership-unknown";
    allocation["invalidatedByRequestId"] = requestId;
  }
}

void BackendService::synchronizeRuntimeAllocations() {
  if (engine_->inferiorPid()) return;
  for (auto& allocation : runtimeAllocations_)
    if (allocation.at("state") != "released") allocation["state"] = "process-ended";
}

Json BackendService::handleRuntimeAllocationQuery(const Json& request) {
  if (sessionId_.empty())
    return errorResponse(request, "STALE_CONTEXT", "runtime allocations require an established session");
  synchronizeRuntimeAllocations();
  const auto current = [&](const Json& stored) {
    auto result = stored;
    const bool allowed = stored.at("state") == "owned" && engine_->inferiorPid().has_value() &&
        liveState_.value("phase", "") == "stopped" && liveObservation_.is_object();
    result["releaseAllowed"] = allowed;
    result["authorityStop"] = allowed ? liveObservation_.at("stop") : Json(nullptr);
    return result;
  };
  const auto& command = request.at("command");
  if (command.at("kind") == "readRuntimeAllocation") {
    for (const auto& allocation : runtimeAllocations_)
      if (allocation.at("id") == command.at("allocationId"))
        return okResponse(request, {{"kind", "runtimeAllocation"}, {"allocation", current(allocation)}});
    return errorResponse(request, "HISTORY_EVICTED", "runtime allocation is unavailable in this session");
  }
  const auto start = command.at("start").get<std::size_t>();
  const auto count = command.at("count").get<std::size_t>();
  Json items = Json::array();
  std::size_t totalBytes = 0;
  for (std::size_t index = 0; index < runtimeAllocations_.size(); ++index) {
    const auto& allocation = runtimeAllocations_[index];
    if (index >= start && items.size() < count) items.push_back(current(allocation));
    if (allocation.at("state") == "owned" || allocation.at("state") == "ownership-unknown")
      totalBytes += allocation.at("byteCount").get<std::size_t>();
  }
  const bool more = std::min(start, runtimeAllocations_.size()) + items.size() < runtimeAllocations_.size();
  return okResponse(request, {{"kind", "runtimeAllocations"}, {"items", std::move(items)},
      {"start", start}, {"total", runtimeAllocations_.size()},
      {"hasMore", more},
      {"totalBytes", totalBytes}});
}

std::vector<Json> BackendService::handleRuntimeAllocation(const Json& request) {
  synchronizeRuntimeAllocations();
  if (!liveObservation_.is_object() || liveState_.value("phase", "") != "stopped")
    return {errorResponse(request, "STALE_CONTEXT", "runtime allocation requires a stopped native session outside input wait")};
  if (!artifact_ || !artifact_->dto.contains("runtimeHelper"))
    return {errorResponse(request, "UNSUPPORTED", "build did not opt into the runtime helper profile")};
  const auto originalMaps = liveObservation_.value("memoryMap", Json(nullptr));
  if (!originalMaps.is_object() || !originalMaps.value("available", false) ||
      originalMaps.value("coverage", "") != "complete")
    return {errorResponse(request, "UNSUPPORTED", "runtime allocation requires a complete current memory map")};

  const auto& command = request.at("command");
  const bool release = command.at("kind") == "releaseRuntimeMemory";
  const auto requestId = request.at("requestId").get<std::string>();
  Json* owned = nullptr;
  Json saved = nullptr;
  std::string address;
  std::size_t requestedBytes = 0, mappedBytes = 0;
  std::string allocationId;
  if (release) {
    for (auto& allocation : runtimeAllocations_)
      if (allocation.at("id") == command.at("allocationId")) { owned = &allocation; break; }
    if (!owned || owned->at("state") != "owned" || owned->at("processInstanceId") != processInstanceId_)
      return {errorResponse(request, "STALE_CONTEXT", "allocation has no release authority at this stop")};
    saved = *owned;
    allocationId = owned->at("id").get<std::string>();
    address = owned->at("addressHex").get<std::string>();
    requestedBytes = owned->at("requestedBytes").get<std::size_t>();
    mappedBytes = owned->at("byteCount").get<std::size_t>();
  } else {
    requestedBytes = command.at("byteCount").get<std::size_t>();
    const auto pageSize = ::sysconf(_SC_PAGESIZE);
    if (pageSize < 4096 || pageSize > 1048576 || (pageSize & (pageSize - 1)) != 0)
      return {errorResponse(request, "UNSUPPORTED", "unsupported runtime page size")};
    const auto page = static_cast<std::size_t>(pageSize);
    mappedBytes = ((requestedBytes + page - 1) / page) * page;
    std::size_t totalBytes = 0;
    for (const auto& allocation : runtimeAllocations_)
      if (allocation.at("state") == "owned" || allocation.at("state") == "ownership-unknown")
        totalBytes += allocation.at("byteCount").get<std::size_t>();
    if (runtimeAllocations_.size() >= maxRuntimeAllocations ||
        mappedBytes > maxRuntimeAllocationTotalBytes - totalBytes)
      return {errorResponse(request, "LIMIT_EXCEEDED", "runtime allocation record or outstanding byte budget is exhausted")};
    runtimeAllocations_.reserve(maxRuntimeAllocations);
    allocationId = "allocation-" + std::to_string(runtimeAllocationCounter_ + 1);
  }
  if (const auto failure = interventionBudgetError(request, interventionReservation)) return {*failure};
  auto audit = beginIntervention(request);
  const auto interventionId = audit.at("id");
  audit["action"] = release ? "release" : "allocate";
  audit["target"] = {{"allocationId", allocationId}, {"requestedBytes", requestedBytes},
      {"addressHex", release ? Json(address) : Json(nullptr)}, {"byteCount", release ? Json(mappedBytes) : Json(nullptr)}};
  Json created = {{"id", allocationId}, {"processInstanceId", processInstanceId_},
      {"requestedBytes", requestedBytes}, {"byteCount", mappedBytes}, {"addressHex", nullptr},
      {"createdByInterventionId", interventionId}, {"createdAt", nullptr},
      {"releasedByInterventionId", nullptr}, {"state", "owned"}, {"invalidatedByRequestId", nullptr}};
  std::stop_token cancellation;
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) {
      cancellation = active_->stop.get_token();
      active_->ready = true;
    }
  }
  controlWake_.notify_all();
  // The worker mutex excludes concurrent queries/releases. Restore this
  // temporary revocation only after a proven read-only preflight rejection.
  if (owned) {
    (*owned)["state"] = "ownership-unknown";
    (*owned)["invalidatedByRequestId"] = requestId;
  }
  Json report, afterMaps;
  GdbError error;
  const bool success = engine_->executeRuntimeAllocation(artifact_->dto.at("runtimeHelper"),
      release, address, release ? mappedBytes : requestedBytes, report, afterMaps, error, cancellation);
  {
    std::lock_guard lock(controlMutex_);
    if (active_ && active_->id == requestId) {
      active_->ready = false;
      if (active_->interruption == "cancel" || cancellation.stop_requested()) report["cancelled"] = true;
    }
  }
  if (!report.value("writeAttempted", false)) {
    if (owned) *owned = std::move(saved);
    synchronizeRuntimeAllocations();
    if (report.value("cancelled", false))
      return engineError(request, {"CANCELLED", "runtime allocation cancelled before execution", false});
    return engineError(request, error.code.empty()
        ? GdbError{"UNSUPPORTED", "runtime allocation preflight did not establish support", false} : error);
  }
  if (!release) ++runtimeAllocationCounter_;
  if (!success && engine_->live()) engine_->stop();
  if (success) {
    const auto& evidence = report.at("evidence");
    if (evidence.at("byteCount") != mappedBytes || !afterMaps.is_object() ||
        !afterMaps.value("available", false) || afterMaps.value("coverage", "") != "complete") {
      engine_->stop();
      report["outcome"] = "failed";
      report["debuggerAlive"] = false;
      report["error"] = {{"code", "READ_FAILED"}, {"message", "runtime allocation proof does not match reserved bounds"}};
      report["evidence"] = nullptr;
    } else {
      audit["target"]["addressHex"] = evidence.at("addressHex");
      audit["target"]["byteCount"] = mappedBytes;
      if (release) {
        (*owned)["state"] = "released";
        (*owned)["releasedByInterventionId"] = interventionId;
        (*owned)["invalidatedByRequestId"] = saved.at("invalidatedByRequestId");
      } else created["addressHex"] = evidence.at("addressHex");
    }
  }
  const bool provenAllocation = !release && report.at("outcome") == "verified";
  audit["report"] = std::move(report);
  auto frames = finishIntervention(request, std::move(audit), "runtimeAllocationIntervention",
                                  interventionReservation, afterMaps);
  if (provenAllocation) {
    const auto& completed = frames.front().at("result").at("intervention");
    created["createdAt"] = completed.at("afterPoint");
    if (completed.at("contextStatus") != "refreshed") created["state"] = "process-ended";
    runtimeAllocations_.push_back(std::move(created));
  }
  synchronizeRuntimeAllocations();
  return frames;
}

}  // namespace phantom
