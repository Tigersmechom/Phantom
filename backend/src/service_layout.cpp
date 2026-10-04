#include "phantom/service.hpp"

namespace phantom {

std::vector<Json> BackendService::handleVariableLayout(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request, "STALE_CONTEXT", "variable layouts require an established session")};
  const auto& command = request.at("command");
  const auto find = [&](const std::string& id) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type", "") == "variableLayoutSnapshot") return &entry.value;
    return nullptr;
  };
  if (command.at("kind") == "readVariableLayout") {
    const auto* saved = find(command.at("snapshotId").get<std::string>());
    if (!saved) return {errorResponse(request, "HISTORY_EVICTED", "variable layout snapshot is unavailable or evicted")};
    return {okResponse(request, {{"kind", "variableLayout"}, {"snapshot", *saved}})};
  }
  const auto locator = command.at("locator").get<std::string>();
  // The engine tracks root locators issued at this stop, including explicit
  // readVariables queries for other frames. Merely selecting another frame
  // must not invalidate locators the frontend already received.
  Json layout;
  GdbError error;
  if (!engine_->inspectVariableLayout(locator, layout, error)) return engineError(request, error);
  Json snapshot = {{"type", "variableLayoutSnapshot"}, {"point", liveObservation_.at("point")},
    {"stop", liveObservation_.at("stop")}, {"processInstanceId", processInstanceId_}, {"layout", std::move(layout)}};
  if (snapshot.dump().size() + 1024 > options_.limits.maxWireBytes)
    return {errorResponse(request, "LIMIT_EXCEEDED", "variable layout exceeds the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot), "layout");
  return {okResponse(request, {{"kind", "variableLayout"}, {"snapshot", *find(id)}})};
}

}  // namespace phantom
