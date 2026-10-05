#include "phantom/service.hpp"
#include "phantom/memory_map.hpp"
#include "phantom/scalar_codec.hpp"

#include <charconv>
#include <limits>
#include <stdexcept>

namespace phantom {
namespace {
std::uint64_t addressValue(const std::string& text) {
  std::uint64_t result = 0;
  if (!text.starts_with("0x") || text.size() <= 2 || text.size() > 18)
    throw std::runtime_error("invalid scalar storage address");
  const auto parsed = std::from_chars(text.data()+2,text.data()+text.size(),result,16);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size())
    throw std::runtime_error("invalid scalar storage address");
  return result;
}
std::string bytesHex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (const unsigned char ch : bytes) { result += digits[ch >> 4]; result += digits[ch & 15]; }
  return result;
}
std::string decodeBase64(std::string_view text) {
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  std::uint32_t value = 0; unsigned bits = 0;
  for (const char ch : text) {
    if (ch == '=') break;
    const auto digit = alphabet.find(ch);
    if (digit == std::string_view::npos) throw std::runtime_error("invalid scalar storage byte encoding");
    value = (value << 6) | static_cast<unsigned>(digit); bits += 6;
    if (bits >= 8) { bits -= 8; result += static_cast<char>((value >> bits) & 255); }
  }
  return result;
}
bool completeEqualMaps(const Json& before, const Json& after) {
  return before.value("available",false) && after.value("available",false) &&
    before.value("coverage","none") == "complete" && after.value("coverage","none") == "complete" &&
    before.at("regions") == after.at("regions");
}
}

std::vector<Json> BackendService::handleScalarStorage(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request,"STALE_CONTEXT","scalar storage requires an established session")};
  const auto& command = request.at("command");
  const auto kind = command.at("kind").get<std::string>();
  const auto find = [&](const std::string& id) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type","") == "scalarStorageSnapshot") return &entry.value;
    return nullptr;
  };
  if (kind == "readScalarStorage") {
    const auto* snapshot = find(command.at("snapshotId").get<std::string>());
    if (!snapshot) return {errorResponse(request,"HISTORY_EVICTED","scalar storage snapshot is unavailable or evicted")};
    return {okResponse(request,{{"kind","scalarStorage"},{"snapshot",*snapshot}})};
  }
  if (!liveObservation_.is_object() || liveState_.value("phase","") != "stopped")
    return {errorResponse(request,"STALE_CONTEXT","scalar storage requires a stopped native session outside an input wait")};
  if (kind == "writeScalarStorage") {
    const auto* saved = find(command.at("snapshotId").get<std::string>());
    if (!saved) return {errorResponse(request,"HISTORY_EVICTED","scalar storage snapshot is unavailable or evicted")};
    if (saved->at("point") != liveObservation_.at("point") || saved->at("stop") != liveObservation_.at("stop") ||
        saved->at("processInstanceId") != processInstanceId_)
      return {errorResponse(request,"STALE_CONTEXT","scalar storage snapshot does not belong to the current stop")};
    if (!saved->at("target").at("available").get<bool>() || !saved->at("storage").at("available").get<bool>())
      return {errorResponse(request,"UNSUPPORTED","snapshot has no supported scalar storage with complete expected bytes")};
    Json fresh; GdbError error;
    const auto locator = saved->at("target").at("locator").get<std::string>();
    if (!engine_->inspectScalarStorage(locator,fresh,error)) return engineError(request,error);
    if (fresh != saved->at("target"))
      return {errorResponse(request,"STALE_CONTEXT","scalar type or storage metadata changed since inspection")};
    std::string replacement, reason;
    if (!encodeScalarStorage(fresh.at("scalar"),command.at("value"),replacement,reason))
      return {errorResponse(request,"INVALID_REQUEST","scalar value cannot be encoded: " + reason)};
    // The original public request reaches the common ledger unchanged. Its
    // issued snapshot binds type/address/expected bytes; the raw write path
    // still checks maps, compares bytes and records any partial effect.
    Json prepared = {{"memoryCommand",{{"kind","writeMemory"},{"addressHex",fresh.at("addressHex")},
      {"expectedBytesHex",saved->at("storage").at("bytesHex")},{"replacementBytesHex",bytesHex(replacement)}}},
      {"scalar",{{"snapshotId",saved->at("id")},{"locator",locator},{"target",fresh},
        {"requestedValue",command.at("value")},{"beforeValue",nullptr},{"afterValue",nullptr}}}};
    return handleMemoryIntervention(request,prepared);
  }

  Json target; GdbError error;
  if (!engine_->inspectScalarStorage(command.at("locator").get<std::string>(),target,error))
    return engineError(request,error);
  Json storage = {{"available",false},{"bytesHex",nullptr},{"value",nullptr},{"reason","unsupported-target"}};
  if (target.at("available").get<bool>()) {
    const auto pid = engine_->inferiorPid();
    if (!pid) return {errorResponse(request,"READ_FAILED","owned inferior PID is unavailable")};
    const auto maps = readLinuxMemoryMap(*pid);
    if (!completeEqualMaps(liveObservation_.value("memoryMap",Json::object()),maps))
      return {errorResponse(request,"READ_FAILED","current scalar storage mappings must match the observed stop")};
    const auto address = addressValue(target.at("addressHex"));
    const auto count = target.at("scalar").at("byteSize").get<std::size_t>();
    bool readable = false;
    if (count != 0 && count <= 8 && count <= options_.limits.maxMemoryReadBytes && address <= UINT64_MAX-count)
      for (const auto& region : maps.at("regions"))
        if (region.at("permissions").get<std::string>().starts_with("r") &&
            address >= addressValue(region.at("startAddressHex")) && address+count <= addressValue(region.at("endAddressHex"))) {
          readable = true; break;
        }
    storage["reason"] = "storage-not-readable";
    if (readable) {
      Json memory;
      if (!engine_->readMemory(target.at("addressHex").get<std::string>(),count,memory,error)) {
        if (!engine_->live()) return engineError(request,error);
        storage["reason"] = "read-failed";
      } else {
        const auto raw = decodeBase64(memory.at("bytesBase64").get<std::string>());
        if (raw.size() == count && memory.at("unreadableBytes") == 0) {
          storage["available"] = true; storage["bytesHex"] = bytesHex(raw);
          const auto value = decodeScalarStorage(target.at("scalar"),raw);
          storage["value"] = value ? *value : Json(nullptr);
          storage["reason"] = value ? Json(nullptr) : Json("invalid-scalar-representation");
        } else storage["reason"] = "incomplete-read";
      }
    }
    if (!completeEqualMaps(maps,readLinuxMemoryMap(*pid)))
      return {errorResponse(request,"READ_FAILED","memory mappings changed during scalar storage inspection")};
  }
  Json snapshot = {{"type","scalarStorageSnapshot"},{"profile","native-dwarf-scalar-v1"},
    {"point",liveObservation_.at("point")},{"stop",liveObservation_.at("stop")},
    {"processInstanceId",processInstanceId_},{"target",std::move(target)},{"storage",std::move(storage)}};
  if (snapshot.dump().size()+1024 > options_.limits.maxWireBytes)
    return {errorResponse(request,"LIMIT_EXCEEDED","scalar storage snapshot exceeds the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot),"scalar");
  return {okResponse(request,{{"kind","scalarStorage"},{"snapshot",*find(id)}})};
}
} // namespace phantom
