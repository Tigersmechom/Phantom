#include "phantom/memory_batch.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <exception>
#include <stdexcept>
#include <string_view>

namespace phantom {
namespace {
using Json = nlohmann::json;
constexpr std::size_t maxRanges = 8, maxBytes = 256;

std::size_t validate(const std::vector<MemoryBatchEdit>& edits) {
  if (edits.empty() || edits.size() > maxRanges)
    throw std::invalid_argument("memory batch requires 1..8 ranges");
  std::size_t total = 0;
  for (std::size_t i = 0; i < edits.size(); ++i) {
    const auto& edit = edits[i];
    const auto size = edit.expectedRaw.size();
    if (size == 0 || size != edit.replacementRaw.size() || size > maxBytes - total ||
        edit.address > UINT64_MAX - size)
      throw std::invalid_argument("memory batch requires equal nonempty buffers, <=256 total bytes and non-overflowing extents");
    total += size;
    for (std::size_t j = 0; j < i; ++j) {
      const auto& previous = edits[j];
      if (edit.address < previous.address + previous.expectedRaw.size() &&
          previous.address < edit.address + size)
        throw std::invalid_argument("memory batch ranges must not overlap");
    }
  }
  return total;
}

std::string addressHex(std::uint64_t address) {
  std::array<char, 16> text{};
  const auto converted = std::to_chars(text.data(), text.data() + text.size(), address, 16);
  return "0x" + std::string(text.data(), converted.ptr);
}

std::string hex(std::string_view raw) {
  constexpr char digits[] = "0123456789abcdef";
  std::string text;
  text.reserve(raw.size() * 2);
  for (unsigned char byte : raw) { text += digits[byte >> 4]; text += digits[byte & 15]; }
  return text;
}

std::string boundedMessage(std::string_view text) {
  constexpr std::size_t limit = 512;
  const auto bounded = std::string(text.substr(0, limit));
  auto clean = Json::parse(Json(bounded).dump(-1, ' ', false, Json::error_handler_t::replace)).get<std::string>();
  bool truncated = text.size() > limit;
  if (clean.size() > limit) {
    auto end = limit;
    while (end != 0 && (static_cast<unsigned char>(clean[end]) & 0xc0) == 0x80) --end;
    clean.resize(end);
    truncated = true;
  }
  // Escaped control characters can cost six bytes each on the wire. Limit
  // their serialized size too, so eight final-read errors fit the audit slot.
  if (Json(clean).dump().size() + (truncated ? 3 : 0) > limit) truncated = true;
  while (Json(clean).dump().size() + (truncated ? 3 : 0) > limit) {
    auto end = clean.size() - 1;
    while (end != 0 && (static_cast<unsigned char>(clean[end]) & 0xc0) == 0x80) --end;
    clean.resize(end);
  }
  if (truncated) clean += "...";
  return clean;
}

Json error(std::string_view code, std::string_view message) {
  auto shortCode = code.substr(0, 64);
  for (unsigned char byte : shortCode) if (byte < 0x20 || byte > 0x7e) {
    shortCode = "CALLBACK_ERROR";
    break;
  }
  return {{"code", shortCode}, {"message", boundedMessage(message)}};
}

struct ReadResult {
  Json value;
  bool alive = true;
  bool complete = false;
};

ReadResult observe(const MemoryBatchEdit& edit, const MemoryEditReader& reader, bool final) {
  ReadResult observed;
  observed.value = {{"bytesHex", nullptr}, {"matchesExpected", nullptr}, {"error", nullptr}};
  if (final) observed.value["matchesReplacement"] = nullptr;
  MemoryEditRead read;
  try { read = reader(edit.address, edit.expectedRaw.size()); }
  catch (const std::exception& exception) {
    observed.value["error"] = error("READ_FAILED", exception.what());
    return observed;
  } catch (...) {
    observed.value["error"] = error("READ_FAILED", "memory reader threw an unknown exception");
    return observed;
  }
  observed.alive = read.debuggerAlive;
  const auto size = edit.expectedRaw.size();
  if (read.bytes && read.bytes->size() <= size) observed.value["bytesHex"] = hex(*read.bytes);
  if (!read.code.empty()) observed.value["error"] = error(read.code, read.message);
  else if (!read.debuggerAlive) observed.value["error"] = error("DEBUGGER_DIED", "debugger is unavailable");
  else if (!read.bytes || read.bytes->size() != size)
    observed.value["error"] = error("READ_FAILED", read.bytes && read.bytes->size() > size ?
        "memory reader returned bytes beyond the requested range" : "memory read did not return the full requested range");
  observed.complete = read.debuggerAlive && read.bytes && read.bytes->size() == size && read.code.empty();
  if (observed.complete) {
    observed.value["matchesExpected"] = *read.bytes == edit.expectedRaw;
    if (final) observed.value["matchesReplacement"] = *read.bytes == edit.replacementRaw;
  }
  return observed;
}
}  // namespace

nlohmann::json compareAndWriteMemoryBatch(const std::vector<MemoryBatchEdit>& edits,
    const MemoryEditReader& read, const MemoryEditWriter& write) {
  const auto total = validate(edits);
  Json report = {{"byteCount", total}, {"atomic", false}, {"rollbackAttempted", false},
    {"writeAttempted", false}, {"debuggerAlive", true}, {"preflightPassed", false},
    {"outcome", "preflight-failed"}, {"failureIndex", nullptr}, {"items", Json::array()}};
  auto& items = report["items"];
  for (std::size_t i = 0; i < edits.size(); ++i) {
    const auto& edit = edits[i];
    items.push_back({{"index", i}, {"addressHex", addressHex(edit.address)},
      {"byteCount", edit.expectedRaw.size()}, {"expectedBytesHex", hex(edit.expectedRaw)},
      {"replacementBytesHex", hex(edit.replacementRaw)}, {"preflight", nullptr},
      {"execution", nullptr}, {"final", nullptr}});
  }
  for (std::size_t i = 0; i < edits.size(); ++i) {
    auto observed = observe(edits[i], read, false);
    report["debuggerAlive"] = observed.alive;
    const bool matches = observed.complete && observed.value.at("matchesExpected").get<bool>();
    items[i]["preflight"] = std::move(observed.value);
    if (!matches) { report["failureIndex"] = i; return report; }
  }
  report["preflightPassed"] = true;
  report["outcome"] = "unchanged";
  bool attempted = false, interrupted = false, alive = true;
  for (std::size_t i = 0; i < edits.size(); ++i) {
    const auto& edit = edits[i];
    auto execution = compareAndWriteMemory(edit.address, edit.expectedRaw, edit.replacementRaw, read, write);
    attempted = attempted || execution.at("writeAttempted").get<bool>();
    alive = execution.at("debuggerAlive").get<bool>();
    const auto& outcome = execution.at("outcome");
    const bool healthy = alive && execution.at("errors").empty() &&
        (outcome == "unchanged" || (outcome == "verified" && execution.at("writeAcknowledged").get<bool>()));
    items[i]["execution"] = std::move(execution);
    if (!healthy) {
      interrupted = true;
      report["failureIndex"] = i;
      report["outcome"] = "interrupted";
      break;
    }
  }
  report["writeAttempted"] = attempted;
  report["debuggerAlive"] = alive;
  if (!attempted) return report;

  if (!interrupted) report["outcome"] = "verified";
  for (std::size_t i = 0; alive && i < edits.size(); ++i) {
    auto observed = observe(edits[i], read, true);
    alive = observed.alive;
    const bool matches = observed.complete && observed.value.at("matchesReplacement").get<bool>();
    items[i]["final"] = std::move(observed.value);
    if (!matches) {
      if (report["failureIndex"].is_null()) report["failureIndex"] = i;
      if (!interrupted) report["outcome"] = "verification-failed";
    }
  }
  report["debuggerAlive"] = alive;
  return report;
}
}  // namespace phantom
