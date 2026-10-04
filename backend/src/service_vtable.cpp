#include "phantom/service.hpp"
#include "phantom/memory_map.hpp"
#include "phantom/module_map.hpp"
#include "phantom/vtable.hpp"

#include <charconv>
#include <map>
#include <sstream>

namespace phantom {
namespace {
std::string addressText(std::uint64_t value) {
  std::ostringstream out; out << "0x" << std::hex << value; return out.str();
}
std::optional<std::string> memoryBytes(const Json& result, std::size_t count) {
  if (result.value("unreadableBytes", count) != 0) return std::nullopt;
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const auto encoded = result.value("bytesBase64", "");
  std::string bytes;
  std::uint32_t value = 0; unsigned bits = 0;
  for (const auto ch : encoded) {
    if (ch == '=') break;
    const auto digit = alphabet.find(ch);
    if (digit == std::string_view::npos) return std::nullopt;
    value = (value << 6) | static_cast<unsigned>(digit); bits += 6;
    if (bits >= 8) { bits -= 8; bytes += static_cast<char>((value >> bits) & 255); }
  }
  if (bytes.size() != count) return std::nullopt;
  return bytes;
}
}

std::vector<Json> BackendService::handleVtable(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request, "STALE_CONTEXT", "vtable snapshots require an established session")};
  const auto& command = request.at("command");
  const auto find = [&](const std::string& id) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type", "") == "vtableSnapshot") return &entry.value;
    return nullptr;
  };
  if (command.at("kind") == "readVtableSnapshot") {
    const auto* saved = find(command.at("snapshotId").get<std::string>());
    if (!saved) return {errorResponse(request, "HISTORY_EVICTED", "vtable snapshot is unavailable or evicted")};
    return {okResponse(request, {{"kind", "vtableSnapshot"}, {"snapshot", *saved}})};
  }
  const auto pid = engine_->inferiorPid();
  if (!pid) return {errorResponse(request, "READ_FAILED", "owned inferior PID is unavailable")};
  const auto maps = readLinuxMemoryMap(*pid);
  // Procfs belongs to the current OS state even during record-full replay.
  // Do not quietly combine newly changed mappings with an older stop's maps.
  if (!maps.value("available", false) || maps.value("coverage", "none") != "complete")
    return {errorResponse(request, "READ_FAILED", "complete current memory mappings are unavailable")};
  const auto savedMaps = liveObservation_.value("memoryMap", Json::object());
  if (!savedMaps.value("available", false) || savedMaps.value("coverage", "none") != "complete" ||
      savedMaps.at("regions") != maps.at("regions"))
    return {errorResponse(request, "READ_FAILED", "current memory mappings differ from this stop's observation")};

  const auto address = command.at("vptrAddressHex").get<std::string>();
  std::uint64_t slot = 0;
  const auto parsed = std::from_chars(address.data()+2, address.data()+address.size(), slot, 16);
  if (parsed.ec != std::errc{} || parsed.ptr != address.data()+address.size())
    return {errorResponse(request, "INVALID_REQUEST", "invalid vptr slot address")};
  std::size_t memoryReads = 0, memoryReadBytes = 0;
  GdbError fatalError;
  const auto read = [&](std::uint64_t start, std::size_t count) -> std::optional<std::string> {
    if (!fatalError.code.empty() || count == 0 || count > options_.limits.maxMemoryReadBytes ||
        memoryReads >= 16 || count > 4096 - memoryReadBytes) return std::nullopt;
    ++memoryReads; memoryReadBytes += count;
    Json result; GdbError error;
    if (!engine_->readMemory(addressText(start), count, result, error)) {
      // A missing memory page is a reportable gap. A failed debugger requires
      // the same lifecycle/state recovery as other live inspection commands.
      if (!engine_->live()) fatalError = std::move(error);
      return std::nullopt;
    }
    return memoryBytes(result, count);
  };
  std::map<std::string, Json> reports;
  const auto symbols = [&](std::string_view moduleId) -> Json {
    const auto found = reports.find(std::string(moduleId));
    if (found != reports.end()) return found->second;
    if (!fatalError.code.empty() || reports.size() >= 4)
      return {{"available", false}, {"reason", "inspection-limit"}};
    ModuleSymbolInspectionLimits limits;
    limits.maxMetadataBytes = 1024 * 1024;
    auto report = inspectRuntimeModuleSymbols(*pid, maps, moduleId, limits);
    reports.emplace(std::string(moduleId), report);
    return report;
  };
  auto report = inspectItaniumVtable(slot, command.at("maxEntries").get<std::size_t>(), maps, read, symbols);
  if (!fatalError.code.empty()) return engineError(request, fatalError);
  const auto after = readLinuxMemoryMap(*pid);
  if (!after.value("available", false) || after.value("coverage", "none") != "complete" ||
      maps.at("regions") != after.at("regions"))
    return {errorResponse(request, "READ_FAILED", "memory mappings changed during vtable inspection")};
  Json snapshot = {{"type", "vtableSnapshot"}, {"point", liveObservation_.at("point")},
    {"stop", liveObservation_.at("stop")}, {"processInstanceId", processInstanceId_},
    {"evidenceScope", "debugger-memory-and-current-os-metadata"}, {"report", std::move(report)}};
  if (snapshot.dump().size() + 1024 > options_.limits.maxWireBytes)
    return {errorResponse(request, "LIMIT_EXCEEDED", "vtable snapshot exceeds the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot), "vtable");
  return {okResponse(request, {{"kind", "vtableSnapshot"}, {"snapshot", *find(id)}})};
}

}  // namespace phantom
