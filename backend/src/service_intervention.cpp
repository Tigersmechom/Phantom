#include "phantom/service.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace phantom {

std::optional<Json> BackendService::interventionBudgetError(const Json& request, std::size_t reservationBytes) const {
  const auto budget = std::min<std::size_t>(4 * 1024 * 1024, options_.limits.maxWireBytes);
  std::size_t reserved = 0;
  for (const auto& saved : interventions_) {
    if (saved.reservationBytes > budget-reserved)
      return errorResponse(request,"LIMIT_EXCEEDED","intervention audit retention budget is exhausted");
    reserved += saved.reservationBytes;
  }
  if (interventions_.size() >= maxInterventions || reservationBytes > budget-reserved || request.dump().size() > 4096)
    return errorResponse(request,"LIMIT_EXCEEDED","intervention audit retention budget is exhausted or request identity is too large");
  return std::nullopt;
}

Json BackendService::beginIntervention(const Json& request) {
  // This vector never evicts or grows beyond its reserved session capacity.
  // Callers admit the operation against its byte budget before any mutation.
  interventions_.reserve(maxInterventions);
  return {{"id","intervention-" + std::to_string(interventions_.size()+1)},
    {"requestId",request.at("requestId")},{"profile",request.at("command").at("profile")},
    {"processInstanceId",processInstanceId_},{"beforePoint",liveObservation_.at("point")},
    {"beforeStop",liveObservation_.at("stop")},{"afterPoint",nullptr},{"afterStop",nullptr},
    {"branchId",nullptr},{"contextStatus","unchanged"},{"refreshError",nullptr},{"report",nullptr}};
}

std::vector<Json> BackendService::finishIntervention(const Json& request, Json audit,
    std::string_view resultKind, std::size_t reservationBytes, const Json& requiredMaps) {
  std::vector<Json> events;
  const auto requestId = request.at("requestId").get<std::string>();
  if (audit.at("report").at("writeAttempted").get<bool>()) {
    currentBranchId_ = "branch-" + std::to_string(branches_.size());
    branches_.push_back({{"id",currentBranchId_},{"parent",audit.at("beforePoint")},{"interventionId",audit.at("id")}});
    audit["branchId"] = currentBranchId_;
    events.push_back(event({{"kind","branchCreated"},{"branchId",currentBranchId_},
      {"parent",audit.at("beforePoint")}},processInstanceId_,requestId));
    try {
      GdbStop refreshed; GdbError refreshError;
      if (!engine_->live() || !engine_->refreshStoppedSnapshot(refreshed,refreshError))
        throw std::runtime_error("post-write stopped context could not be confirmed");
      // Memory edits retain their stronger mapping-equality guarantee.
      // Register edits do not require procfs merely to inspect CPU state.
      if (!requiredMaps.is_null() &&
          (!requiredMaps.value("available",false) || !refreshed.memoryMap.value("available",false) ||
           requiredMaps.value("coverage","") != "complete" || refreshed.memoryMap.value("coverage","") != "complete" ||
           requiredMaps.at("regions") != refreshed.memoryMap.at("regions")))
        throw std::runtime_error("post-write memory mappings could not be confirmed");
      auto observation = makeObservation(refreshed,"mutation");
      auto state = makeState(observation,"stopped");
      appendHistory(observation,state);
      audit["afterPoint"] = observation.at("point"); audit["afterStop"] = observation.at("stop");
      audit["contextStatus"] = "refreshed";
      events.push_back(event({{"kind","observation"},{"observation",observation}},processInstanceId_,requestId));
      events.push_back(event({{"kind","state"},{"state",state}},processInstanceId_,requestId));
    } catch (...) {
      engine_->stop(); liveObservation_ = nullptr;
      audit["contextStatus"] = "failed";
      audit["refreshError"] = {{"code","READ_FAILED"},{"message","post-write stopped context could not be confirmed; debugger closed"}};
      publishFailedState(events,request);
    }
  } else if (!engine_->live()) {
    liveObservation_ = nullptr; audit["contextStatus"] = "failed";
    publishFailedState(events,request);
  }
  auto response = okResponse(request,{{"kind",resultKind},{"intervention",std::move(audit)},{"throughSequence",sequence_}});
  interventions_.push_back({request,response,reservationBytes});
  std::vector<Json> frames{std::move(response)};
  frames.insert(frames.end(),std::make_move_iterator(events.begin()),std::make_move_iterator(events.end()));
  return frames;
}

std::vector<Json> BackendService::handleInterventionQuery(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request,"STALE_CONTEXT","interventions require an established session")};
  const auto& command = request.at("command");
  const auto kind = command.at("kind").get<std::string>();
  if (kind == "listBranches") return {okResponse(request,{{"kind","branches"},
    {"currentBranchId",currentBranchId_},{"branches",branches_}})};
  const bool memory = kind == "readMemoryIntervention" || kind == "listMemoryInterventions";
  const bool registers = kind == "readRegisterIntervention" || kind == "listRegisterInterventions";
  const auto matches = [&](const InterventionEntry& entry) {
    const auto& tag = entry.response.at("result").at("kind");
    return memory ? tag == "memoryIntervention" : registers ? tag == "registerIntervention" : true;
  };
  const std::string singular = memory ? "memoryIntervention" : registers ? "registerIntervention" : "intervention";
  if (kind.starts_with("read")) {
    for (const auto& entry : interventions_) if (matches(entry)) {
      const auto& audit = entry.response.at("result").at("intervention");
      if (audit.at("id") == command.at("interventionId"))
        return {okResponse(request,{{"kind",singular},{"intervention",audit}})};
    }
    return {errorResponse(request,"HISTORY_EVICTED","intervention is unavailable in this session or requested category")};
  }
  const auto start = command.at("start").get<std::size_t>();
  const auto count = command.at("count").get<std::size_t>();
  std::size_t total = 0;
  Json items = Json::array();
  for (const auto& entry : interventions_) if (matches(entry)) {
    if (total >= start && items.size() < count) items.push_back(entry.response.at("result").at("intervention"));
    ++total;
  }
  // Avoid start+count arithmetic: start may be any JSON-safe integer.
  const bool more = std::min(start,total)+items.size() < total;
  return {okResponse(request,{{"kind",singular+"s"},{"items",std::move(items)},
    {"start",start},{"total",total},{"hasMore",more}})};
}
} // namespace phantom
