#include "phantom/service.hpp"
#include "phantom/memory_map.hpp"
#include "phantom/scalar_codec.hpp"

#include <charconv>
#include <limits>
#include <set>
#include <stdexcept>
#include <vector>

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
  if (kind == "writeScalarStorage" || kind == "writeScalarStorageBatch") {
    const bool batch = kind == "writeScalarStorageBatch";
    const Json entries = batch ? command.at("edits") : Json::array({command});
    if (!entries.is_array() || entries.empty() || entries.size() > 8)
      return {errorResponse(request,"INVALID_REQUEST","scalar batches require 1..8 snapshots")};
    Json memoryEdits = Json::array(), scalars = Json::array();
    std::set<std::string> snapshots;
    std::vector<std::pair<std::uint64_t,std::uint64_t>> ranges;
    std::size_t totalBytes = 0;
    for (const auto& entry : entries) {
      const auto snapshotId = entry.at("snapshotId").get<std::string>();
      if (!snapshots.insert(snapshotId).second)
        return {errorResponse(request,"INVALID_REQUEST","scalar batch snapshot IDs must be unique")};
      const auto* saved = find(snapshotId);
      if (!saved) return {errorResponse(request,"HISTORY_EVICTED","scalar storage snapshot is unavailable or evicted")};
      if (saved->at("profile") != entry.at("profile"))
        return {errorResponse(request,"INVALID_REQUEST","scalar storage profile must match the inspected snapshot")};
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
      if (!encodeScalarStorage(fresh.at("scalar"),entry.at("value"),replacement,reason))
        return {errorResponse(request,"INVALID_REQUEST","scalar value cannot be encoded: " + reason)};
      const auto& expected = saved->at("storage").at("bytesHex");
      if (!expected.is_string() || expected.get_ref<const std::string&>().size() != replacement.size()*2)
        return {errorResponse(request,"UNSUPPORTED","snapshot does not contain complete scalar storage bytes")};
      const auto address = addressValue(fresh.at("addressHex"));
      if (replacement.empty() || replacement.size() > 8 || address > UINT64_MAX-replacement.size())
        return {errorResponse(request,"UNSUPPORTED","scalar storage extent is unavailable")};
      const auto end = address+replacement.size();
      for (const auto& [start,limit] : ranges)
        if (address < limit && start < end)
          return {errorResponse(request,"INVALID_REQUEST","scalar batch snapshots must refer to disjoint storage")};
      ranges.emplace_back(address,end);
      totalBytes += replacement.size();
      if (totalBytes > 64 || totalBytes > options_.limits.maxMemoryReadBytes)
        return {errorResponse(request,"LIMIT_EXCEEDED","scalar edits exceed the configured batch byte limit")};
      memoryEdits.push_back({{"addressHex",fresh.at("addressHex")},{"expectedBytesHex",expected},
        {"replacementBytesHex",bytesHex(replacement)}});
      Json scalar = {{"snapshotId",saved->at("id")},{"locator",locator},{"target",std::move(fresh)},
        {"requestedValue",entry.at("value")},{"beforeValue",nullptr},{"afterValue",nullptr}};
      if (batch) {
        scalar["index"] = scalars.size(); scalar["profile"] = saved->at("profile");
        scalar["preflightValue"] = nullptr; scalar["finalValue"] = nullptr;
      }
      scalars.push_back(std::move(scalar));
    }
    // The original public request reaches the common ledger unchanged. Its
    // issued snapshots bind type/address/expected bytes. Every entry has been
    // validated before the common raw path can compare or mutate any range.
    Json prepared;
    if (batch) prepared = {{"memoryCommand",{{"kind","writeMemoryBatch"},{"edits",std::move(memoryEdits)}}},
                            {"scalars",std::move(scalars)}};
    else {
      auto memoryCommand = std::move(memoryEdits.front());
      memoryCommand["kind"] = "writeMemory";
      prepared = {{"memoryCommand",std::move(memoryCommand)},{"scalar",std::move(scalars.front())}};
    }
    return handleMemoryIntervention(request,prepared);
  }

  Json target; GdbError error;
  if (!engine_->inspectScalarStorage(command.at("locator").get<std::string>(),target,error))
    return engineError(request,error);
  const auto profile = command.value("profile",std::string("native-dwarf-scalar-v1"));
  // Legacy requests must never receive float metadata/values outside their
  // advertised union, even for an unavailable optimized/register-only float.
  if (profile == "native-dwarf-scalar-v1" && target.at("scalar").is_object() &&
      target.at("scalar").at("kind") == "float") {
    target["available"] = false; target["scalar"] = nullptr;
    target["addressHex"] = nullptr; target["reason"] = "scalar-type-unsupported";
  }
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
  Json snapshot = {{"type","scalarStorageSnapshot"},{"profile",profile},
    {"point",liveObservation_.at("point")},{"stop",liveObservation_.at("stop")},
    {"processInstanceId",processInstanceId_},{"target",std::move(target)},{"storage",std::move(storage)}};
  if (snapshot.dump().size()+1024 > options_.limits.maxWireBytes)
    return {errorResponse(request,"LIMIT_EXCEEDED","scalar storage snapshot exceeds the inspection retention budget")};
  const auto id = storeInspection(std::move(snapshot),"scalar");
  return {okResponse(request,{{"kind","scalarStorage"},{"snapshot",*find(id)}})};
}
} // namespace phantom
