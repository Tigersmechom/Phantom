#include "phantom/service.hpp"
#include "phantom/memory_edit.hpp"
#include "phantom/memory_map.hpp"

#include <algorithm>
#include <charconv>
#include <sstream>
#include <stdexcept>

namespace phantom {
namespace {
std::uint64_t addressValue(const std::string& text) {
  std::uint64_t value = 0;
  const auto parsed = std::from_chars(text.data()+2,text.data()+text.size(),value,16);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size()) throw std::runtime_error("invalid address");
  return value;
}
std::string addressText(std::uint64_t value) {
  std::ostringstream out; out << "0x" << std::hex << value; return out.str();
}
std::string hexBytes(std::string_view raw) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (const unsigned char ch : raw) { result += digits[ch >> 4]; result += digits[ch & 15]; }
  return result;
}
std::string rawHex(std::string_view text) {
  std::string raw;
  for (std::size_t i=0; i<text.size(); i+=2) {
    unsigned value = 0;
    const auto parsed = std::from_chars(text.data()+i,text.data()+i+2,value,16);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data()+i+2) throw std::runtime_error("invalid byte encoding");
    raw += static_cast<char>(value);
  }
  return raw;
}
std::string rawBase64(const std::string& text) {
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string bytes;
  std::uint32_t value = 0; unsigned bits = 0;
  for (const char ch : text) {
    if (ch == '=') break;
    const auto digit = alphabet.find(ch);
    if (digit == std::string_view::npos) throw std::runtime_error("invalid debugger byte encoding");
    value = (value << 6) | static_cast<unsigned>(digit); bits += 6;
    if (bits >= 8) { bits -= 8; bytes += static_cast<char>((value >> bits) & 255); }
  }
  return bytes;
}
bool sameCompleteMaps(const Json& before, const Json& after) {
  return before.value("available", false) && after.value("available", false) &&
    before.value("coverage", "none") == "complete" && after.value("coverage", "none") == "complete" &&
    before.at("regions") == after.at("regions");
}
}

std::vector<Json> BackendService::handleMemoryIntervention(const Json& request) {
  if (sessionId_.empty()) return {errorResponse(request,"STALE_CONTEXT","interventions require an established session")};
  const auto& command = request.at("command");
  const auto kind = command.at("kind").get<std::string>();
  if (kind == "listBranches") return {okResponse(request,{{"kind","branches"},
    {"currentBranchId",currentBranchId_},{"branches",branches_}})};
  if (kind == "readMemoryIntervention") {
    for (const auto& entry : interventions_) if (entry.response.at("result").at("intervention").at("id") == command.at("interventionId"))
      return {okResponse(request,{{"kind","memoryIntervention"},{"intervention",entry.response.at("result").at("intervention")}})};
    return {errorResponse(request,"HISTORY_EVICTED","memory intervention is unavailable in this session")};
  }
  if (kind == "listMemoryInterventions") {
    const auto start = command.at("start").get<std::size_t>();
    const auto begin = std::min(start,interventions_.size());
    const auto end = begin + std::min(command.at("count").get<std::size_t>(),interventions_.size()-begin);
    Json items = Json::array();
    for (auto i=begin; i<end; ++i) items.push_back(interventions_[i].response.at("result").at("intervention"));
    return {okResponse(request,{{"kind","memoryInterventions"},{"items",std::move(items)},
      {"start",start},{"total",interventions_.size()},{"hasMore",end < interventions_.size()}})};
  }
  if (!liveObservation_.is_object() || liveState_.value("phase","") != "stopped")
    return {errorResponse(request,"STALE_CONTEXT","memory edits require a stopped native session, outside an input wait")};
  const auto budget = std::min<std::size_t>(4 * 1024 * 1024, options_.limits.maxWireBytes);
  if (interventions_.size() >= maxInterventions || interventions_.size() >= budget/interventionReservation ||
      request.dump().size() > 4096)
    return {errorResponse(request,"LIMIT_EXCEEDED","intervention audit retention budget is exhausted or request identity is too large")};
  GdbError error;
  if (!engine_->prepareMemoryWrite(error)) return engineError(request,error);
  const auto pid = engine_->inferiorPid();
  if (!pid) return {errorResponse(request,"READ_FAILED","owned inferior PID is unavailable")};
  const auto maps = readLinuxMemoryMap(*pid);
  if (!sameCompleteMaps(liveObservation_.value("memoryMap",Json::object()),maps))
    return {errorResponse(request,"READ_FAILED","complete current mappings must match the observed stop")};
  const auto address = addressValue(command.at("addressHex"));
  const auto expected = rawHex(command.at("expectedBytesHex").get<std::string>());
  const auto replacement = rawHex(command.at("replacementBytesHex").get<std::string>());
  Json mapping = nullptr;
  for (const auto& region : maps.at("regions")) {
    if (region.at("permissions") == "rw-p" && address >= addressValue(region.at("startAddressHex")) &&
        address + expected.size() <= addressValue(region.at("endAddressHex"))) {
      mapping = {{"startAddressHex",region.at("startAddressHex")},{"endAddressHex",region.at("endAddressHex")},
                 {"permissions",region.at("permissions")}};
      break;
    }
  }
  if (mapping.is_null()) return {errorResponse(request,"INVALID_REQUEST","memory edits require one readable writable private non-executable mapping")};

  // Reserve the bounded ledger slot before the callback can submit any write.
  // This ledger is separate from the evictable history/inspection caches.
  interventions_.reserve(maxInterventions);
  const auto id = "intervention-" + std::to_string(interventions_.size()+1);
  Json audit = {{"id",id},{"requestId",request.at("requestId")},{"profile","native-private-memory-v1"},
    {"processInstanceId",processInstanceId_},{"beforePoint",liveObservation_.at("point")},
    {"beforeStop",liveObservation_.at("stop")},{"afterPoint",nullptr},{"afterStop",nullptr},
    {"branchId",nullptr},{"contextStatus","unchanged"},{"mapping",std::move(mapping)},
    {"refreshError",nullptr},{"report",nullptr}};
  const auto reader = [&](std::uint64_t start, std::size_t count) -> MemoryEditRead {
    Json result; GdbError readError;
    if (!engine_->readMemory(addressText(start),count,result,readError))
      return {std::nullopt,engine_->live(),readError.code,readError.message};
    return {rawBase64(result.at("bytesBase64")),engine_->live(),{}, {}};
  };
  const auto writer = [&](std::uint64_t start, std::string_view raw) -> MemoryEditWrite {
    if (!sameCompleteMaps(maps,readLinuxMemoryMap(*pid)))
      return {false,false,engine_->live(),"WRITE_FAILED","memory mappings changed before write"};
    bool attempted = false; GdbError writeError;
    const bool acknowledged = engine_->writeMemoryBytes(addressText(start),hexBytes(raw),attempted,writeError);
    return {attempted,acknowledged,engine_->live(),writeError.code,writeError.message};
  };
  audit["report"] = compareAndWriteMemory(address,expected,replacement,reader,writer);
  std::vector<Json> events;
  const auto requestId = request.at("requestId").get<std::string>();
  const bool attempted = audit.at("report").at("writeAttempted").get<bool>();
  if (attempted) {
    currentBranchId_ = "branch-" + std::to_string(branches_.size());
    branches_.push_back({{"id",currentBranchId_},{"parent",audit.at("beforePoint")},{"interventionId",id}});
    audit["branchId"] = currentBranchId_;
    events.push_back(event({{"kind","branchCreated"},{"branchId",currentBranchId_},
      {"parent",audit.at("beforePoint")}},processInstanceId_,requestId));
    try {
      GdbStop refreshed; GdbError refreshError;
      if (!engine_->live() || !engine_->refreshStoppedSnapshot(refreshed,refreshError) ||
          !sameCompleteMaps(maps,refreshed.memoryMap))
        throw std::runtime_error("post-write stopped context could not be confirmed");
      auto observation = makeObservation(refreshed,"mutation");
      auto state = makeState(observation,"stopped");
      appendHistory(observation,state);
      audit["afterPoint"] = observation.at("point"); audit["afterStop"] = observation.at("stop");
      audit["contextStatus"] = "refreshed";
      events.push_back(event({{"kind","observation"},{"observation",observation}},processInstanceId_,requestId));
      events.push_back(event({{"kind","state"},{"state",state}},processInstanceId_,requestId));
    } catch (...) {
      // A sent write is never erased by a failed readback/snapshot. The audit
      // remains retrievable, but no pre-write observation is presented as live.
      engine_->stop(); liveObservation_ = nullptr;
      audit["contextStatus"] = "failed";
      audit["refreshError"] = {{"code","READ_FAILED"},{"message","post-write stopped context could not be confirmed; debugger closed"}};
      publishFailedState(events,request);
    }
  } else if (!engine_->live()) {
    liveObservation_ = nullptr; audit["contextStatus"] = "failed";
    publishFailedState(events,request);
  }
  auto response = okResponse(request,{{"kind","memoryIntervention"},{"intervention",audit},{"throughSequence",sequence_}});
  interventions_.push_back({request,response});
  std::vector<Json> frames{std::move(response)};
  frames.insert(frames.end(),std::make_move_iterator(events.begin()),std::make_move_iterator(events.end()));
  return frames;
}
} // namespace phantom
