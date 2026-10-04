#include "phantom/service.hpp"
#include "phantom/process_inspection.hpp"

#include <algorithm>
#include <charconv>
#include <map>
#include <sstream>
#include <stdexcept>

namespace phantom {
namespace {
std::string hexAddress(std::uint64_t address) {
  std::ostringstream out; out << "0x" << std::hex << address; return out.str();
}
std::uint64_t addressValue(const std::string& text) {
  std::uint64_t value = 0;
  const auto parsed = std::from_chars(text.data()+2, text.data()+text.size(), value, 16);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data()+text.size()) throw std::runtime_error("invalid stored address");
  return value;
}
std::string decodeBase64(const std::string& text) {
  constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string bytes;
  std::uint32_t value = 0; unsigned bits = 0;
  for (const char c : text) {
    if (c == '=') break;
    const auto digit = alphabet.find(c);
    if (digit == std::string_view::npos) throw std::runtime_error("invalid stored base64");
    value = (value << 6) | static_cast<unsigned>(digit); bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push_back(static_cast<char>((value >> bits) & 255)); }
  }
  return bytes;
}
std::string bytesHex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out; out.reserve(bytes.size()*2);
  for (const unsigned char c : bytes) { out += digits[c >> 4]; out += digits[c & 15]; }
  return out;
}
Json page(const Json& values, std::size_t start, std::size_t count) {
  Json result = Json::array();
  start = std::min(start, values.size());
  const auto end = start + std::min(count, values.size()-start);
  for (auto i=start; i<end; ++i) result.push_back(values[i]);
  return result;
}
}

std::string BackendService::storeInspection(Json value, std::string_view prefix) {
  const auto id = std::string(prefix) + "-" + std::to_string(++inspectionCounter_);
  value["id"] = id;
  const auto bytes = value.dump().size();
  if (bytes > options_.limits.maxWireBytes) throw std::runtime_error("inspection exceeds retention budget");
  while (!inspectionStore_.empty() && (inspectionStore_.size() >= 128 ||
         inspectionBytes_ + bytes > options_.limits.maxWireBytes)) {
    inspectionBytes_ -= inspectionStore_.front().bytes;
    inspectionStore_.erase(inspectionStore_.begin());
  }
  inspectionStore_.push_back({id, std::move(value), bytes}); inspectionBytes_ += bytes;
  return id;
}

std::vector<Json> BackendService::handleInspection(const Json& request) {
  const auto& command = request.at("command");
  const auto kind = command.at("kind").get<std::string>();
  const auto find = [&](const std::string& id, std::string_view type) -> const Json* {
    for (const auto& entry : inspectionStore_)
      if (entry.id == id && entry.value.value("type", "") == type) return &entry.value;
    return nullptr;
  };
  const auto context = [&] {
    return Json{{"point", liveObservation_.at("point")}, {"stop", liveObservation_.at("stop")},
                {"processInstanceId", processInstanceId_}};
  };
  if (kind == "readOutputJournal") {
    if (sessionId_.empty()) return {errorResponse(request,"STALE_CONTEXT","output journal requires a debugging session")};
    const auto stream = command.at("stream").get<std::string>();
    auto result = (stream == "stdout" ? stdoutJournal_ : stderrJournal_).read(
        command.at("fromByte").get<std::uint64_t>(),command.at("byteCount").get<std::size_t>());
    result["kind"] = "outputJournal"; result["stream"] = stream;
    result["processInstanceId"] = processInstanceId_; result["branchId"] = "main";
    result["consistent"] = outputJournalConsistent_;
    result["selectedPoint"] = nullptr; result["selectedThroughByte"] = nullptr;
    if (command.contains("point")) {
      const Json* observation = nullptr;
      for (const auto& entry : history_) if (entry.observation.at("point") == command.at("point")) {
        observation = &entry.observation; break;
      }
      if (!observation) return {errorResponse(request,"HISTORY_EVICTED","selected output observation is unavailable or evicted")};
      result["selectedPoint"] = command.at("point");
      result["selectedThroughByte"] = observation->at("outputCursor").at(stream == "stdout" ? "stdoutThroughByte" : "stderrThroughByte");
    }
    return {okResponse(request,std::move(result))};
  }
  if (kind == "readRecording") {
    Json recording; GdbError error;
    if (!engine_->readRecording(recording,error)) return engineError(request,error);
    auto result = context(); result["kind"] = "recording"; result["recording"] = std::move(recording);
    return {okResponse(request,std::move(result))};
  }
  if (kind == "inspectProcess") {
    const auto pid = engine_->inferiorPid();
    if (!pid) return {errorResponse(request, "READ_FAILED", "owned inferior PID is unavailable")};
    auto result = context(); result["kind"] = "processInspection"; result["evidenceScope"] = "current-os-state";
    result["inspection"] = inspectOwnedProcess(*pid);
    return {okResponse(request, std::move(result))};
  }
  if (kind == "readRegisters") {
    Json registers; GdbError error;
    if (!engine_->readRegisters(command.value("registers", std::vector<std::string>{}), registers, error)) return engineError(request,error);
    auto result = context(); result["kind"] = "registers";
    result["architecture"] = registers.at("architecture"); result["registers"] = registers.at("registers");
    return {okResponse(request, std::move(result))};
  }
  if (kind == "captureMemory") {
    auto capture = context(); capture["type"] = "memoryCapture"; capture["ranges"] = Json::array();
    capture["coverage"] = "complete";
    for (const auto& range : command.at("ranges")) {
      const auto address = hexAddress(addressValue(range.at("addressHex").get<std::string>()));
      const auto count = range.at("byteCount").get<std::size_t>();
      Json read; GdbError error;
      if (engine_->readMemory(address,count,read,error) && read.value("unreadableBytes",count) == 0) {
        read["available"] = true; read["byteCount"] = count;
      } else {
        if (!engine_->live()) return engineError(request,error);
        read = {{"addressHex",address},{"byteCount",count},{"available",false},
                {"unreadableBytes",count},{"reason","read-failed"}};
        capture["coverage"] = "partial";
      }
      capture["ranges"].push_back(std::move(read));
    }
    const auto id = storeInspection(std::move(capture),"capture");
    return {okResponse(request,{{"kind","memoryCapture"},{"capture",*find(id,"memoryCapture")}})};
  }
  if (kind == "readMemoryCapture" || kind == "readInstructionTrace") {
    const bool memory = kind == "readMemoryCapture";
    const auto* saved = find(command.at(memory ? "captureId" : "traceId").get<std::string>(), memory ? "memoryCapture" : "instructionTrace");
    if (!saved) return {errorResponse(request,"HISTORY_EVICTED","inspection is unavailable or has been evicted")};
    if (memory) return {okResponse(request,{{"kind","memoryCapture"},{"capture",*saved}})};
    auto trace = *saved; const auto& entries = saved->at("entries");
    const auto start = command.at("start").get<std::size_t>();
    trace["entries"] = page(entries,start,command.at("count").get<std::size_t>());
    return {okResponse(request,{{"kind","instructionTrace"},{"trace",std::move(trace)},
             {"start",start},{"totalEntries",entries.size()},
             {"hasMore",start < entries.size() && command.at("count").get<std::size_t>() < entries.size()-start}})};
  }
  if (kind == "diffMemoryCaptures") {
    const auto* before = find(command.at("beforeCaptureId"),"memoryCapture");
    const auto* after = find(command.at("afterCaptureId"),"memoryCapture");
    if (!before || !after) return {errorResponse(request,"HISTORY_EVICTED","memory capture is unavailable or has been evicted")};
    const auto& a = before->at("ranges"); const auto& b = after->at("ranges");
    if (a.size() != b.size()) return {errorResponse(request,"INVALID_REQUEST","capture ranges must match in address, length and order")};
    Json changes = Json::array(), unavailable = Json::array(); std::size_t changedBytes = 0, comparedBytes = 0;
    for (std::size_t i=0; i<a.size(); ++i) {
      if (a[i].at("addressHex") != b[i].at("addressHex") || a[i].at("byteCount") != b[i].at("byteCount"))
        return {errorResponse(request,"INVALID_REQUEST","capture ranges must match in address, length and order")};
      if (!a[i].at("available").get<bool>() || !b[i].at("available").get<bool>()) {
        unavailable.push_back({{"addressHex",a[i].at("addressHex")},{"byteCount",a[i].at("byteCount")},
                               {"beforeAvailable",a[i].at("available")},{"afterAvailable",b[i].at("available")}}); continue;
      }
      const auto oldBytes = decodeBase64(a[i].at("bytesBase64")), newBytes = decodeBase64(b[i].at("bytesBase64"));
      if (oldBytes.size() != a[i].at("byteCount").get<std::size_t>() || oldBytes.size() != newBytes.size())
        throw std::runtime_error("stored memory capture length mismatch");
      comparedBytes += oldBytes.size();
      for (std::size_t j=0; j<oldBytes.size();) {
        if (oldBytes[j] == newBytes[j]) { ++j; continue; }
        const auto begin = j++;
        while (j<oldBytes.size() && oldBytes[j] != newBytes[j]) ++j;
        changedBytes += j-begin;
        changes.push_back({{"addressHex",hexAddress(addressValue(a[i].at("addressHex"))+begin)},
                           {"byteCount",j-begin},
                           {"beforeBytesHex",bytesHex(std::string_view(oldBytes).substr(begin,j-begin))},
                           {"afterBytesHex",bytesHex(std::string_view(newBytes).substr(begin,j-begin))}});
      }
    }
    const auto start = command.at("start").get<std::size_t>(), count = command.at("count").get<std::size_t>();
    return {okResponse(request,{{"kind","memoryCaptureDiff"},{"beforeCaptureId",before->at("id")},{"afterCaptureId",after->at("id")},
             {"coverage",unavailable.empty() ? "complete" : "partial"},{"comparedBytes",comparedBytes},{"changedBytes",changedBytes},
             {"unavailableRanges",unavailable},{"changes",page(changes,start,count)},{"start",start},
             {"totalChanges",changes.size()},{"hasMore",start < changes.size() && count < changes.size()-start}})};
  }
  if (kind == "diffMemoryMaps") {
    const auto observation = [&](const Json& point) -> const Json* {
      for (const auto& entry : history_) if (entry.observation.at("point") == point) return &entry.observation;
      return nullptr;
    };
    const auto* a = observation(command.at("beforePoint")); const auto* b = observation(command.at("afterPoint"));
    if (!a || !b) return {errorResponse(request,"HISTORY_EVICTED","memory map observation is unavailable or evicted")};
    for (const auto* saved : {a,b})
      if (!saved->contains("memoryMap") || !saved->at("memoryMap").value("available",false) || saved->at("memoryMap").value("coverage","") != "complete")
        return {errorResponse(request,"READ_FAILED","both observations need complete map metadata to establish additions and removals")};
    using Interval = std::pair<std::uint64_t,std::uint64_t>;
    std::map<Interval,std::pair<Json,Json>> intervals;
    for (const auto& region : a->at("memoryMap").at("regions"))
      intervals[{addressValue(region.at("startAddressHex")),addressValue(region.at("endAddressHex"))}].first = region;
    for (const auto& region : b->at("memoryMap").at("regions"))
      intervals[{addressValue(region.at("startAddressHex")),addressValue(region.at("endAddressHex"))}].second = region;
    Json changes = Json::array();
    for (const auto& [interval, maps] : intervals) {
      if (maps.first == maps.second) continue;
      changes.push_back({{"kind",maps.first.is_null() ? "added" : maps.second.is_null() ? "removed" : "changed"},
                         {"before",maps.first},{"after",maps.second}});
    }
    const auto start = command.at("start").get<std::size_t>(), count = command.at("count").get<std::size_t>();
    return {okResponse(request,{{"kind","memoryMapDiff"},{"beforePoint",command.at("beforePoint")},{"afterPoint",command.at("afterPoint")},
             {"changes",page(changes,start,count)},{"start",start},{"totalChanges",changes.size()},
             {"hasMore",start < changes.size() && count < changes.size()-start}})};
  }
  return {errorResponse(request,"UNSUPPORTED","unknown inspection command")};
}

std::vector<Json> BackendService::handleTrace(const Json& request, const FrameSink& publish) {
  std::vector<Json> frames;
  const auto requestId = request.at("requestId").get<std::string>();
  const auto accepted = okResponse(request,{{"kind","accepted"}});
  if (publish) publish(accepted); else frames.push_back(accepted);
  try {
    const auto beforePoint = liveObservation_.at("point");
    const auto beforeStop = liveObservation_.at("stop");
    {
      std::lock_guard lock(controlMutex_);
      if (active_ && active_->id == requestId) active_->ready = true;
    }
    controlWake_.notify_all();
    const auto& command = request.at("command");
    GdbStop stop; GdbError error; Json trace;
    const bool ok = engine_->traceInstructions(command.at("count").get<std::size_t>(),
        command.value("registers",std::vector<std::string>{}),command.at("memoryRanges"),stop,trace,error);
    const auto interruption = activeInterruption(requestId);
    if (interruption == "stop" && !stop.exited) {
      stop = engine_->stopAndSnapshot(); stop.exited = true; stop.processInstanceId = processInstanceId_;
    }
    if (stop.exited) engine_->stop();
    const bool hasFinal = stop.exited || (stop.stopped && engine_->live());
    if (hasFinal) {
      const bool waiting = error.code == "INPUT_WAIT" || stop.reason == "input-wait";
      const auto reason = stop.exited ? "exit" : waiting ? "input-wait" : interruption == "pause" ? "pause" :
                          error.code == "STEP_TIMEOUT" ? "step-timeout" : stop.reason == "breakpoint-hit" ? "breakpoint" :
                          stop.reason.find("signal") != std::string::npos ? "signal" : "step";
      auto observation = makeObservation(stop,reason);
      auto state = makeState(observation,stop.exited ? "terminated" : waiting ? "waitingForInput" : "stopped",
                             stop.exitCode,stop.signalName.empty() ? std::nullopt : std::optional<std::string>(stop.signalName));
      appendHistory(observation,state);
      frames.push_back(event({{"kind","observation"},{"observation",observation}},processInstanceId_,requestId));
      frames.push_back(event({{"kind","state"},{"state",state}},processInstanceId_,requestId));
    } else publishFailedState(frames,request);
    if (trace.is_object()) {
      trace["type"] = "instructionTrace"; trace["beforePoint"] = beforePoint; trace["beforeStop"] = beforeStop;
      trace["afterPoint"] = hasFinal ? liveObservation_.at("point") : Json(nullptr);
      trace["afterStop"] = hasFinal ? liveObservation_.at("stop") : Json(nullptr);
      trace["processInstanceId"] = processInstanceId_;
      const auto id = storeInspection(trace,"trace");
      frames.push_back(event({{"kind","instructionTraceRecorded"},{"traceId",id},
                              {"status",trace.at("status")},{"terminationReason",trace.at("terminationReason")},
                              {"totalEntries",trace.at("entries").size()}},processInstanceId_,requestId));
    }
    const auto outcome = interruption == "cancel" ? "cancelled" : error.code == "INPUT_WAIT" ? "waiting" :
                         ok || interruption == "stop" || interruption == "pause" ? "completed" : "failed";
    std::optional<Json> failure;
    if (!ok && interruption.empty()) failure = {{"code",error.code.empty() ? "READ_FAILED" : error.code},
                                                {"message",error.message},{"retryable",error.retryable}};
    emitCommandFinished(frames,request,outcome,failure);
  } catch (const std::exception& e) {
    engine_->stop(); (void)activeInterruption(requestId); publishFailedState(frames,request);
    emitCommandFinished(frames,request,"failed",Json{{"code","INTERNAL"},{"message",e.what()},{"retryable",true}});
  }
  return frames;
}
} // namespace phantom
