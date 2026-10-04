#include "phantom/memory_edit.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <exception>
#include <limits>

namespace phantom {
namespace {
using Json = nlohmann::json;
constexpr std::size_t maxBytes = 256;

std::string addressHex(std::uint64_t address) {
  std::array<char, 16> buffer{};
  const auto converted = std::to_chars(buffer.data(), buffer.data() + buffer.size(), address, 16);
  return "0x" + std::string(buffer.data(), converted.ptr);
}
std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result; result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
  return result;
}
std::string message(std::string_view value, std::size_t limit) {
  std::string bounded(value.substr(0, limit));
  // Callback errors may contain arbitrary target bytes or cut UTF-8 at the
  // bound. Preserve readable text while ensuring the report can be serialized.
  auto clean = Json::parse(Json(bounded).dump(-1, ' ', false, Json::error_handler_t::replace)).get<std::string>();
  if (value.size() > limit || clean.size() > limit) {
    auto end = std::min(clean.size(), limit - 3);
    while (end != 0 && end < clean.size() && (static_cast<unsigned char>(clean[end]) & 0xc0) == 0x80) --end;
    clean.resize(end); clean += "...";
  }
  return clean;
}
std::string boundedCode(std::string_view value) {
  for (unsigned char byte : value.substr(0, 64))
    if (byte < 0x20 || byte > 0x7e) return "CALLBACK_ERROR";
  return std::string(value.substr(0, 64));
}
void error(Json& report, const char* phase, std::string_view code, std::string_view text) {
  report["errors"].push_back({{"phase", phase}, {"code", boundedCode(code)}, {"message", message(text, 512)}});
}

bool captureRead(Json& report, const MemoryEditRead& result, const char* field,
                 const char* phase, std::size_t count) {
  report["debuggerAlive"] = result.debuggerAlive;
  if (result.bytes && result.bytes->size() <= count) report[field] = hex(*result.bytes);
  if (!result.code.empty()) error(report, phase, result.code, result.message);
  if (!result.debuggerAlive) {
    if (result.code.empty()) error(report, phase, "DEBUGGER_DIED", "debugger is unavailable");
    return false;
  }
  if (!result.bytes || result.bytes->size() != count) {
    if (result.code.empty()) error(report, phase, "READ_FAILED", result.bytes && result.bytes->size() > count ?
      "memory reader returned bytes beyond the requested range" : "memory read did not return the full requested range");
    return false;
  }
  return result.code.empty();
}
}  // namespace

nlohmann::json compareAndWriteMemory(std::uint64_t address, std::string_view expected,
    std::string_view desired, const MemoryEditReader& read, const MemoryEditWriter& write) {
  Json report = {{"addressHex", addressHex(address)}, {"byteCount", expected.size()},
    {"expectedBytesHex", expected.size() <= maxBytes ? Json(hex(expected)) : Json(nullptr)},
    {"replacementBytesHex", desired.size() <= maxBytes ? Json(hex(desired)) : Json(nullptr)},
    {"outcome", "write-rejected"}, {"beforeBytesHex", nullptr}, {"afterBytesHex", nullptr},
    {"beforeMatchesExpected", nullptr}, {"afterMatchesReplacement", nullptr}, {"afterMatchesBefore", nullptr},
    {"writeAttempted", false}, {"writeAcknowledged", false}, {"debuggerAlive", true},
    {"atomic", false}, {"rollbackAttempted", false}, {"errors", Json::array()}};
  if (expected.size() > maxBytes || desired.size() > maxBytes) {
    error(report, "write", "LIMIT_EXCEEDED", "memory edits are limited to 256 bytes"); return report;
  }
  if (expected.empty() || expected.size() != desired.size() || address > UINT64_MAX - expected.size()) {
    error(report, "write", "INVALID_REQUEST", "memory edits require equal nonempty buffers and a non-overflowing range");
    return report;
  }
  MemoryEditRead before;
  try { before = read(address, expected.size()); }
  catch (const std::exception& exception) {
    error(report, "read-before", "READ_FAILED", exception.what()); report["outcome"] = "read-before-failed"; return report;
  } catch (...) {
    error(report, "read-before", "READ_FAILED", "memory reader threw an unknown exception");
    report["outcome"] = "read-before-failed"; return report;
  }
  if (!captureRead(report, before, "beforeBytesHex", "read-before", expected.size())) {
    report["outcome"] = "read-before-failed"; return report;
  }
  report["beforeMatchesExpected"] = *before.bytes == expected;
  if (*before.bytes != expected) { report["outcome"] = "conflict"; return report; }
  if (expected == desired) { report["outcome"] = "unchanged"; return report; }
  if (!write) {
    error(report, "write", "WRITE_REJECTED", "memory writer is unavailable"); return report;
  }
  MemoryEditWrite written;
  report["writeAttempted"] = true;
  try { written = write(address, desired); }
  catch (const std::exception& exception) { written.code = "WRITE_FAILED"; written.message = exception.what(); }
  catch (...) { written.code = "WRITE_FAILED"; written.message = "memory writer threw an unknown exception"; }
  report["debuggerAlive"] = written.debuggerAlive;
  if (!written.attempted && written.acknowledged) {
    // Contradictory adapter evidence cannot justify saying no mutation was
    // attempted. Treat acknowledgement as untrusted and still seek readback.
    written.attempted = true; written.acknowledged = false;
    error(report, "write", "INVALID_WRITE_RESULT", "writer acknowledged a command it reported as not attempted");
  }
  report["writeAttempted"] = written.attempted;
  report["writeAcknowledged"] = written.acknowledged;
  if (!written.code.empty()) error(report, "write", written.code, written.message);
  if (!written.attempted) {
    if (written.code.empty()) error(report, "write", "WRITE_REJECTED", "writer rejected the edit before attempting a write");
    return report;
  }
  if (!written.acknowledged && written.code.empty())
    error(report, "write", "WRITE_FAILED", "memory write was not acknowledged");
  if (!written.debuggerAlive) {
    if (written.code.empty()) error(report, "write", "DEBUGGER_DIED", "debugger became unavailable during the write");
    report["outcome"] = "unverified"; return report;
  }
  MemoryEditRead after;
  try { after = read(address, expected.size()); }
  catch (const std::exception& exception) {
    error(report, "read-after", "READ_FAILED", exception.what()); report["outcome"] = "unverified"; return report;
  } catch (...) {
    error(report, "read-after", "READ_FAILED", "memory reader threw an unknown exception");
    report["outcome"] = "unverified"; return report;
  }
  if (!captureRead(report, after, "afterBytesHex", "read-after", expected.size())) {
    report["outcome"] = "unverified"; return report;
  }
  report["afterMatchesReplacement"] = *after.bytes == desired;
  report["afterMatchesBefore"] = *after.bytes == *before.bytes;
  if (*after.bytes == desired) report["outcome"] = "verified";
  else {
    report["outcome"] = "readback-mismatch";
    error(report, "read-after", "READBACK_MISMATCH", "observed bytes differ from the requested replacement");
  }
  return report;
}

}  // namespace phantom
