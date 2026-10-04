#include "phantom/service.hpp"
#include "phantom/module_map.hpp"

#include <algorithm>

namespace phantom {

std::vector<Json> BackendService::handleModuleSymbols(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request, "STALE_CONTEXT", "module symbols require an established session")};
  const auto& command = request.at("command");
  const auto find = [&](const std::string& id) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type", "") == "moduleSymbolsSnapshot") return &entry.value;
    return nullptr;
  };
  const auto response = [&](const Json& saved, std::size_t start, std::size_t count) {
    // Pages are derived only from the immutable capture. They never reopen the
    // mapped file, whose contents or mapping may already have disappeared.
    auto snapshot = saved;
    const auto& symbols = saved.at("report").at("symbols");
    start = std::min(start, symbols.size());
    const auto end = start + std::min(count, symbols.size() - start);
    snapshot["report"]["symbols"] = Json::array();
    for (auto i = start; i < end; ++i) snapshot["report"]["symbols"].push_back(symbols[i]);
    return okResponse(request, {{"kind", "moduleSymbols"}, {"snapshot", std::move(snapshot)},
      {"start", start}, {"totalSymbols", symbols.size()}, {"hasMore", end < symbols.size()}});
  };
  if (command.at("kind") == "readModuleSymbols") {
    const auto* saved = find(command.at("snapshotId").get<std::string>());
    if (!saved) return {errorResponse(request, "HISTORY_EVICTED", "module symbols snapshot is unavailable or evicted")};
    return {response(*saved, command.at("start").get<std::size_t>(), command.at("count").get<std::size_t>())};
  }
  const auto pid = engine_->inferiorPid();
  if (!pid) return {errorResponse(request, "READ_FAILED", "owned inferior PID is unavailable")};
  auto report = inspectRuntimeModuleSymbols(*pid, liveObservation_.value("memoryMap", Json{{"available", false}}),
                                           command.at("moduleId").get<std::string>());
  Json snapshot = {{"type", "moduleSymbolsSnapshot"}, {"point", liveObservation_.at("point")},
    {"stop", liveObservation_.at("stop")}, {"processInstanceId", processInstanceId_},
    {"evidenceScope", "current-os-state"}, {"report", std::move(report)}};
  if (snapshot.dump().size() + 1024 > options_.limits.maxWireBytes)
    return {errorResponse(request, "LIMIT_EXCEEDED", "module symbols exceed the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot), "symbols");
  return {response(*find(id), 0, std::min<std::size_t>(100, options_.limits.maxPageSize))};
}

}  // namespace phantom
