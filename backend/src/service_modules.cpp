#include "phantom/service.hpp"
#include "phantom/module_map.hpp"

namespace phantom {

std::vector<Json> BackendService::handleModules(const Json& request) {
  const auto& command = request.at("command");
  const auto find = [&](const std::string& id) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type", "") == "moduleSnapshot") return &entry.value;
    return nullptr;
  };
  if (command.at("kind") == "readModuleSnapshot") {
    const auto* saved = find(command.at("snapshotId").get<std::string>());
    if (!saved) return {errorResponse(request,"HISTORY_EVICTED","module snapshot is unavailable or has been evicted")};
    return {okResponse(request,{{"kind","moduleSnapshot"},{"snapshot",*saved}})};
  }
  const auto pid = engine_->inferiorPid();
  if (!pid) return {errorResponse(request,"READ_FAILED","owned inferior PID is unavailable")};
  const auto map = liveObservation_.value("memoryMap",Json{{"available",false}});
  auto report = inspectRuntimeModules(*pid,map);
  const auto reason = report.value("reason", "");
  if (!report.value("available",false) && (reason == "process-unavailable" || reason == "process-changed"))
    return {errorResponse(request,"READ_FAILED","owned inferior process identity is unavailable or changed")};
  Json snapshot = {{"type","moduleSnapshot"},{"point",liveObservation_.at("point")},
    {"stop",liveObservation_.at("stop")},{"processInstanceId",processInstanceId_},
    {"evidenceScope","current-os-state"},{"modules",std::move(report)}};
  // Reserve room for the retained ID and response envelope. The inspection
  // store's shared eviction policy is the same as memory/trace captures.
  if (snapshot.dump().size() + 1024 > options_.limits.maxWireBytes)
    return {errorResponse(request,"LIMIT_EXCEEDED","module snapshot exceeds the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot),"modules");
  return {okResponse(request,{{"kind","moduleSnapshot"},{"snapshot",*find(id)}})};
}

}  // namespace phantom
