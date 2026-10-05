#include "phantom/register_edit.hpp"

#include <array>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
constexpr auto zero = "0x0000000000000000";
constexpr auto high = "0xffffffffffffffff";
constexpr auto other = "0x8000000000000001";

struct Fixture {
  std::string name = "r15", expected = zero, desired = high, actual = zero;
  std::vector<std::string> calls;
  std::size_t reads = 0, writes = 0;
  std::size_t absentRead = 0, errorRead = 0, deathRead = 0, malformedRead = 0;
  std::size_t throwRead = 0, unknownThrowRead = 0;
  std::string malformed = "0x0", diagnostic = "register transport failed", errorCode = "READ_FAILED";
  bool mutate = true, partialMutation = false, throwWrite = false, unknownThrowWrite = false;
  phantom::RegisterEditWrite writeResult{true, true, true, {}, {}};

  Json run() {
    reads = writes = 0;
    calls.clear();
    const auto result = phantom::compareAndWriteRegister(name, expected, desired,
      [&](std::string_view registerName) -> phantom::RegisterEditRead {
        assert(registerName == name);
        ++reads;
        calls.emplace_back("read");
        if (throwRead == reads) throw std::runtime_error("reader exception");
        if (unknownThrowRead == reads) throw 7;
        const auto value = absentRead == reads ? std::optional<std::string>{} :
            std::optional<std::string>{malformedRead == reads ? malformed : actual};
        return {value, deathRead != reads, errorRead == reads ? errorCode : "",
                errorRead == reads ? diagnostic : ""};
      }, [&](std::string_view registerName, std::string_view replacement) {
        assert(registerName == name && replacement == desired);
        ++writes;
        calls.emplace_back("write");
        if (mutate) actual = partialMutation ? other : desired;
        if (throwWrite) throw std::runtime_error("writer exception after possible submission");
        if (unknownThrowWrite) throw 7;
        return writeResult;
      });
    assert(reads <= 2 && writes <= 1);
    assert(result["register"] == name && result["bits"] == 64);
    assert(result["expectedValueHex"] == expected && result["replacementValueHex"] == desired);
    assert(result["atomic"] == false && result["rollbackAttempted"] == false);
    assert(result.dump().size() < 4096);
    assert(Json::parse(result.dump()) == result);
    return result;
  }
};

void exactValuesAndNames() {
  constexpr std::array names{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
  for (const auto* name : names) {
    assert(phantom::isNativeGprName(name));
    Fixture fixture;
    fixture.name = name;
    auto result = fixture.run();
    assert(result["outcome"] == "verified" && result["errors"].empty());
    assert(result["writeAttempted"] == true && result["writeAcknowledged"] == true);
    assert(result["beforeValueHex"] == zero && result["afterValueHex"] == high);
    assert(result["beforeMatchesExpected"] == true && result["afterMatchesReplacement"] == true);
    assert(result["afterMatchesBefore"] == false && result["debuggerAlive"] == true);
    assert(fixture.calls == std::vector<std::string>({"read", "write", "read"}));
    // Preserve the sign bit and bits above JavaScript's exact integer range.
    fixture.expected = high;
    fixture.desired = other;
    result = fixture.run();
    assert(result["beforeValueHex"] == high && result["afterValueHex"] == other && fixture.actual == other);
    fixture.expected = other;
    fixture.desired = zero;
    assert(fixture.run()["outcome"] == "verified" && fixture.actual == zero);
  }
}

void invalidInputsNeverRead() {
  std::size_t reads = 0, writes = 0;
  auto rejected = [&](const std::string& name, const std::string& expected, const std::string& replacement) {
    bool threw = false;
    try {
      phantom::compareAndWriteRegister(name, expected, replacement,
          [&](std::string_view) { ++reads; return phantom::RegisterEditRead{zero, true, {}, {}}; },
          [&](std::string_view, std::string_view) { ++writes; return phantom::RegisterEditWrite{true, true, true, {}, {}}; });
    } catch (const std::invalid_argument&) { threw = true; }
    assert(threw && reads == 0 && writes == 0);
  };
  for (const auto& name : std::vector<std::string>{"", "rax ", "$rax", "RAX", "eax", "ax", "al", "ah", "r8d",
       "rip", "eip", "rsp", "esp", "rbp", "ebp", "eflags", "rflags", "xmm0", "ymm0", "zmm0",
       "orig_rax", "fs_base", "r16", "r01", std::string("rax\0", 4), std::string(100000, 'r')}) {
    assert(!phantom::isNativeGprName(name));
    rejected(name, zero, high);
  }
  assert(phantom::canonicalGprHex(zero) && phantom::canonicalGprHex(high) && phantom::canonicalGprHex(other));
  for (const auto& value : std::vector<std::string>{"", "0", "0x0", "0000000000000000", "0X0000000000000000",
       "0xFFFFFFFFFFFFFFFF", "0x00000000000000000", "0x000000000000000", "0x000000000000000g",
       "-0x0000000000000001", "+0x0000000000000001", "0x0000000000000000 ", " 0x0000000000000000",
       std::string("0x00000000\0" "0000000", 18), std::string(100000, '0'), "18446744073709551615"}) {
    assert(!phantom::canonicalGprHex(value));
    rejected("rax", value, high);
    rejected("rax", zero, value);
  }
}

void conflictAndNoop() {
  Fixture fixture;
  fixture.actual = other;
  auto result = fixture.run();
  assert(result["outcome"] == "conflict" && result["beforeMatchesExpected"] == false);
  assert(result["beforeValueHex"] == other && result["afterValueHex"].is_null());
  assert(result["writeAttempted"] == false && fixture.reads == 1 && fixture.writes == 0);
  fixture.expected = fixture.desired = high;
  result = fixture.run();
  assert(result["outcome"] == "conflict" && fixture.actual == other); // No-op requests still compare.
  fixture.expected = fixture.desired = other;
  result = fixture.run();
  assert(result["outcome"] == "unchanged" && result["beforeMatchesExpected"] == true);
  assert(result["afterValueHex"].is_null() && result["afterMatchesReplacement"].is_null());
  assert(result["writeAttempted"] == false && fixture.reads == 1 && fixture.writes == 0);
}

void readFailuresRetainOnlyEvidence() {
  for (const auto phase : {1U, 2U}) {
    Fixture fixture;
    for (auto* setting : {&fixture.absentRead, &fixture.errorRead, &fixture.deathRead,
                         &fixture.malformedRead, &fixture.throwRead, &fixture.unknownThrowRead}) {
      fixture.actual = fixture.expected;
      *setting = phase;
      const auto result = fixture.run();
      const auto* field = phase == 1 ? "beforeValueHex" : "afterValueHex";
      assert(result["outcome"] == (phase == 1 ? "read-before-failed" : "unverified"));
      assert(result["writeAttempted"] == (phase == 2));
      assert(result["writeAcknowledged"] == (phase == 2));
      assert(result[phase == 1 ? "beforeMatchesExpected" : "afterMatchesReplacement"].is_null());
      assert(result["afterMatchesBefore"].is_null() && result["errors"].size() == 1);
      assert(result["errors"][0]["phase"] == (phase == 1 ? "read-before" : "read-after"));
      assert(fixture.reads == phase && fixture.writes == phase - 1);
      assert(fixture.actual == (phase == 1 ? fixture.expected : fixture.desired));
      if (setting == &fixture.errorRead || setting == &fixture.deathRead)
        assert(result[field] == (phase == 1 ? fixture.expected : fixture.desired));
      else assert(result[field].is_null());
      assert(result["debuggerAlive"] == (setting != &fixture.deathRead));
      *setting = 0;
    }
    for (const auto& bad : {"0X0000000000000000", "0xfffffffffffffffF", "0x10000000000000000", "0x", "unavailable"}) {
      fixture.actual = fixture.expected;
      fixture.malformedRead = phase;
      fixture.malformed = bad;
      const auto result = fixture.run();
      assert(result[phase == 1 ? "beforeValueHex" : "afterValueHex"].is_null());
      assert(result["errors"][0]["code"] == "READ_FAILED");
    }
  }
  Fixture both;
  both.deathRead = both.errorRead = 1;
  auto result = both.run();
  assert(result["debuggerAlive"] == false && result["errors"].size() == 1);
  assert(result["errors"][0]["code"] == "READ_FAILED"); // Preserve adapter's more precise failure.
}

void writesAndLifecycle() {
  for (const bool acknowledged : {false, true}) for (const bool alive : {false, true}) {
    Fixture fixture;
    fixture.writeResult = {true, acknowledged, alive, {}, {}};
    const auto result = fixture.run();
    assert(result["writeAttempted"] == true && result["writeAcknowledged"] == acknowledged);
    assert(result["debuggerAlive"] == alive && fixture.reads == (alive ? 2 : 1));
    assert(result["outcome"] == (alive ? "verified" : "unverified"));
    assert(fixture.actual == high && fixture.writes == 1);
    assert(result["errors"].empty() == (acknowledged && alive));
  }
  Fixture fixture;
  fixture.writeResult = {true, false, true, "WRITE_FAILED", "acknowledgement lost after submission"};
  auto result = fixture.run();
  assert(result["outcome"] == "verified" && result["writeAcknowledged"] == false);
  assert(result["errors"].size() == 1 && result["afterMatchesReplacement"] == true);
  fixture.actual = zero;
  fixture.partialMutation = true;
  result = fixture.run();
  assert(result["outcome"] == "readback-mismatch" && result["afterValueHex"] == other);
  assert(result["afterMatchesBefore"] == false && result["afterMatchesReplacement"] == false);
  assert(result["errors"].size() == 2 && fixture.actual == other && fixture.writes == 1);
  fixture.actual = zero;
  fixture.mutate = false;
  fixture.writeResult = {true, true, true, {}, {}};
  result = fixture.run();
  assert(result["outcome"] == "readback-mismatch" && result["afterMatchesBefore"] == true);
  assert(result["writeAcknowledged"] == true && fixture.writes == 1); // Acknowledgement is not proof.
  for (const bool alive : {false, true}) {
    fixture.writeResult = {false, false, alive, {}, {}};
    result = fixture.run();
    assert(result["outcome"] == "write-rejected" && result["writeAttempted"] == false);
    assert(result["debuggerAlive"] == alive && fixture.reads == 1 && fixture.writes == 1);
    assert(result["afterValueHex"].is_null() && result["errors"][0]["code"] == "WRITE_REJECTED");
  }
  fixture.writeResult = {false, false, true, "STALE_CONTEXT", "register binding changed"};
  result = fixture.run();
  assert(result["writeAttempted"] == false && result["errors"][0]["code"] == "STALE_CONTEXT");
  fixture.mutate = true;
  fixture.partialMutation = false;
  fixture.writeResult = {false, true, true, {}, {}};
  result = fixture.run();
  assert(result["outcome"] == "verified" && result["writeAttempted"] == true && result["writeAcknowledged"] == false);
  assert(result["errors"][0]["code"] == "INVALID_WRITE_RESULT" && fixture.reads == 2);
}

void callbackExceptionsAndAbsence() {
  for (const bool known : {false, true}) for (const bool mutate : {false, true}) {
    Fixture fixture;
    fixture.throwWrite = known;
    fixture.unknownThrowWrite = !known;
    fixture.mutate = mutate;
    const auto result = fixture.run();
    assert(result["writeAttempted"] == true && result["writeAcknowledged"] == false);
    assert(result["debuggerAlive"] == true && fixture.reads == 2 && fixture.writes == 1);
    assert(result["outcome"] == (mutate ? "verified" : "readback-mismatch"));
    assert(result["errors"][0]["code"] == "WRITE_FAILED");
    assert(result["afterValueHex"] == (mutate ? high : zero));
  }
  std::size_t reads = 0;
  const auto reader = [&](std::string_view name) {
    ++reads;
    assert(name == "rax");
    return phantom::RegisterEditRead{zero, true, {}, {}};
  };
  auto result = phantom::compareAndWriteRegister("rax", zero, high, reader, {});
  assert(result["outcome"] == "write-rejected" && result["writeAttempted"] == false && reads == 1);
  result = phantom::compareAndWriteRegister("rax", zero, zero, reader, {});
  assert(result["outcome"] == "unchanged" && result["errors"].empty() && reads == 2);
  result = phantom::compareAndWriteRegister("rax", zero, high, {}, {});
  assert(result["outcome"] == "read-before-failed" && result["writeAttempted"] == false);
}

void boundedDiagnosticsAndLedger() {
  const std::vector<std::string> diagnostics{
      std::string(100000, '\0'), std::string(100000, '\xff'), std::string(100000, '"'),
      std::string(100000, '\\'), std::string(100000, '\n'), std::string(100000, 'A'),
      std::string(510, 'x') + "\xf0\x9f\x98\x80", std::string(509, 'x') + "\xf0\x9f\x98\x80",
      std::string(512, '\x80'), std::string(100000, '\1')};
  for (const auto& diagnostic : diagnostics) {
    Fixture fixture;
    fixture.writeResult = {false, true, true, std::string(100000, '\\'), diagnostic};
    fixture.errorRead = 2;
    fixture.errorCode = std::string(100000, '"');
    fixture.diagnostic = diagnostic;
    const auto report = fixture.run();
    assert(report["outcome"] == "unverified" && report["afterValueHex"] == high);
    assert(report["afterMatchesReplacement"].is_null() && report["errors"].size() == 3);
    for (const auto& error : report["errors"]) {
      assert(error["message"].get_ref<const std::string&>().size() <= 512);
      assert(error["message"].dump().size() <= 512);
      assert(error["code"].get_ref<const std::string&>().size() <= 64);
    }
    // Genuine maximum-error report plus maximum admitted public request and
    // 16 KiB for all envelope/provenance fields fits the existing 32 KiB slot.
    assert(report.dump().size() + 4096 + 16384 < 32768);
  }
  Fixture fixture;
  fixture.writeResult.code = std::string("BAD\0CODE", 8);
  fixture.writeResult.message = std::string(100000, '\0');
  auto result = fixture.run();
  assert(result["errors"][0]["code"] == "CALLBACK_ERROR" && result["outcome"] == "verified");
  fixture.actual = zero;
  fixture.writeResult.code = "\xff";
  result = fixture.run();
  assert(result["errors"][0]["code"] == "CALLBACK_ERROR");
}
}  // namespace

int main() {
  exactValuesAndNames();
  invalidInputsNeverRead();
  conflictAndNoop();
  readFailuresRetainOnlyEvidence();
  writesAndLifecycle();
  callbackExceptionsAndAbsence();
  boundedDiagnosticsAndLedger();
  std::cout << "register edit: exact GPR bits, preflight, faults, lifecycle, bounded audit and no rollback passed\n";
}
