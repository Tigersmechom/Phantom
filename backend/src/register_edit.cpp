#include "phantom/register_edit.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <stdexcept>

namespace phantom {
namespace {
using Json = nlohmann::json;

std::string boundedMessage(std::string_view text) {
  constexpr std::size_t limit = 512;
  auto clean = Json::parse(Json(std::string(text.substr(0, limit))).dump(
      -1, ' ', false, Json::error_handler_t::replace)).get<std::string>();
  bool truncated = text.size() > limit;
  if (clean.size() > limit) {
    auto end = limit;
    while (end && (static_cast<unsigned char>(clean[end]) & 0xc0) == 0x80) --end;
    clean.resize(end);
    truncated = true;
  }
  // Bound serialized bytes too: control characters may expand sixfold in JSON.
  if (Json(clean).dump().size() + (truncated ? 3 : 0) > limit) truncated = true;
  while (Json(clean).dump().size() + (truncated ? 3 : 0) > limit) {
    auto end = clean.size() - 1;
    while (end && (static_cast<unsigned char>(clean[end]) & 0xc0) == 0x80) --end;
    clean.resize(end);
  }
  if (truncated) clean += "...";
  return clean;
}

void error(Json& report, const char* phase, std::string_view code, std::string_view message) {
  auto shortCode = code.substr(0, 64);
  for (unsigned char byte : shortCode) if (byte < 0x20 || byte > 0x7e) {
    shortCode = "CALLBACK_ERROR";
    break;
  }
  report["errors"].push_back({{"phase", phase}, {"code", shortCode},
                            {"message", boundedMessage(message)}});
}

bool captureRead(Json& report, const RegisterEditRead& result, const char* field, const char* phase) {
  report["debuggerAlive"] = result.debuggerAlive;
  const bool complete = result.valueHex && canonicalGprHex(*result.valueHex);
  if (complete) report[field] = *result.valueHex;
  if (!result.code.empty()) error(report, phase, result.code, result.message);
  if (!result.debuggerAlive) {
    if (result.code.empty()) error(report, phase, "DEBUGGER_DIED", "debugger is unavailable");
    return false;
  }
  if (!complete) {
    if (result.code.empty()) error(report, phase, "READ_FAILED",
        result.valueHex ? "register reader returned a noncanonical 64-bit value" :
                          "register reader did not return a value");
    return false;
  }
  return result.code.empty();
}
}  // namespace

bool isNativeGprName(std::string_view name) noexcept {
  constexpr std::array<std::string_view, 14> names{
      "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
  return std::find(names.begin(), names.end(), name) != names.end();
}

bool canonicalGprHex(std::string_view value) noexcept {
  if (value.size() != 18 || value[0] != '0' || value[1] != 'x') return false;
  return std::all_of(value.begin() + 2, value.end(), [](unsigned char byte) {
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f');
  });
}

nlohmann::json compareAndWriteRegister(std::string_view registerName, std::string_view expected,
    std::string_view desired, const RegisterEditReader& read, const RegisterEditWriter& write) {
  if (!isNativeGprName(registerName) || !canonicalGprHex(expected) || !canonicalGprHex(desired))
    throw std::invalid_argument("register edits require an allowed native GPR and canonical 64-bit hexadecimal values");
  Json report = {{"register", registerName}, {"bits", 64},
    {"expectedValueHex", expected}, {"replacementValueHex", desired},
    {"outcome", "write-rejected"}, {"beforeValueHex", nullptr}, {"afterValueHex", nullptr},
    {"beforeMatchesExpected", nullptr}, {"afterMatchesReplacement", nullptr}, {"afterMatchesBefore", nullptr},
    {"writeAttempted", false}, {"writeAcknowledged", false}, {"debuggerAlive", true},
    {"atomic", false}, {"rollbackAttempted", false}, {"errors", Json::array()}};
  RegisterEditRead before;
  try { before = read(registerName); }
  catch (const std::exception& exception) {
    error(report, "read-before", "READ_FAILED", exception.what());
    report["outcome"] = "read-before-failed";
    return report;
  } catch (...) {
    error(report, "read-before", "READ_FAILED", "register reader threw an unknown exception");
    report["outcome"] = "read-before-failed";
    return report;
  }
  if (!captureRead(report, before, "beforeValueHex", "read-before")) {
    report["outcome"] = "read-before-failed";
    return report;
  }
  report["beforeMatchesExpected"] = *before.valueHex == expected;
  if (*before.valueHex != expected) { report["outcome"] = "conflict"; return report; }
  if (expected == desired) { report["outcome"] = "unchanged"; return report; }
  if (!write) {
    error(report, "write", "WRITE_REJECTED", "register writer is unavailable");
    return report;
  }
  RegisterEditWrite written;
  report["writeAttempted"] = true;
  try { written = write(registerName, desired); }
  catch (const std::exception& exception) { written.code = "WRITE_FAILED"; written.message = exception.what(); }
  catch (...) { written.code = "WRITE_FAILED"; written.message = "register writer threw an unknown exception"; }
  report["debuggerAlive"] = written.debuggerAlive;
  if (!written.attempted && written.acknowledged) {
    // Contradictory evidence cannot establish that no write happened.
    written.attempted = true;
    written.acknowledged = false;
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
    error(report, "write", "WRITE_FAILED", "register write was not acknowledged");
  if (!written.debuggerAlive) {
    if (written.code.empty()) error(report, "write", "DEBUGGER_DIED", "debugger became unavailable during the write");
    report["outcome"] = "unverified";
    return report;
  }
  RegisterEditRead after;
  try { after = read(registerName); }
  catch (const std::exception& exception) {
    error(report, "read-after", "READ_FAILED", exception.what());
    report["outcome"] = "unverified";
    return report;
  } catch (...) {
    error(report, "read-after", "READ_FAILED", "register reader threw an unknown exception");
    report["outcome"] = "unverified";
    return report;
  }
  if (!captureRead(report, after, "afterValueHex", "read-after")) {
    report["outcome"] = "unverified";
    return report;
  }
  report["afterMatchesReplacement"] = *after.valueHex == desired;
  report["afterMatchesBefore"] = *after.valueHex == *before.valueHex;
  if (*after.valueHex == desired) report["outcome"] = "verified";
  else {
    report["outcome"] = "readback-mismatch";
    error(report, "read-after", "READBACK_MISMATCH", "observed register value differs from the requested replacement");
  }
  return report;
}

}  // namespace phantom
