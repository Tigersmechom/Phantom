#include "phantom/memory_edit.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
struct Fixture {
  std::string bytes = "abcd", expected = "abcd", desired = "WXYZ";
  std::uint64_t address = 0x20000000000101ULL;
  std::size_t reads = 0, writes = 0;
  std::vector<std::string> calls;
  std::size_t failRead = 0, shortRead = 0, excessRead = 0, throwRead = 0, deathRead = 0;
  bool mutate = true, partialWrite = false, throwWrite = false, unknownThrow = false;
  phantom::MemoryEditWrite writeResult{true, true, true, {}, {}};
  Json run() {
    calls.clear(); reads = writes = 0;
    const auto result = phantom::compareAndWriteMemory(address, expected, desired,
      [&](std::uint64_t location, std::size_t size) -> phantom::MemoryEditRead {
        ++reads; calls.push_back("read");
        assert(location == address && size == expected.size());
        if (throwRead == reads) throw std::runtime_error("read exception");
        if (failRead == reads) return {{}, true, "READ_FAILED", "cannot read memory"};
        auto observed = bytes;
        if (shortRead == reads && !observed.empty()) observed.pop_back();
        if (excessRead == reads) observed += '!';
        return {observed, deathRead != reads, {}, {}};
      }, [&](std::uint64_t location, std::string_view replacement) {
        ++writes; calls.push_back("write");
        assert(location == address && replacement == desired);
        if (mutate) {
          const auto count = partialWrite ? desired.size() / 2 : desired.size();
          bytes.replace(0, count, desired.substr(0, count));
        }
        if (throwWrite) {
          if (unknownThrow) throw 17;
          throw std::runtime_error("write exception after mutation");
        }
        return writeResult;
      });
    assert(reads <= 2 && writes <= 1);
    assert(result["atomic"] == false && result["rollbackAttempted"] == false);
    assert(result.dump().size() < 16384);
    return result;
  }
};

void verifiedAndConflict() {
  Fixture fixture;
  auto result = fixture.run();
  assert(result["outcome"] == "verified" && result["errors"].empty());
  assert(result["addressHex"] == "0x20000000000101" && result["byteCount"] == 4);
  assert(result["beforeBytesHex"] == "61626364" && result["afterBytesHex"] == "5758595a");
  assert(result["expectedBytesHex"] == "61626364" && result["replacementBytesHex"] == "5758595a");
  assert(result["beforeMatchesExpected"] == true && result["afterMatchesReplacement"] == true);
  assert(result["afterMatchesBefore"] == false && result["debuggerAlive"] == true);
  assert(result["writeAttempted"] == true && result["writeAcknowledged"] == true);
  assert(fixture.calls == std::vector<std::string>({"read", "write", "read"}));
  assert(fixture.bytes == fixture.desired);
  result = fixture.run(); // The previous expected bytes are now stale.
  assert(result["outcome"] == "conflict" && result["beforeMatchesExpected"] == false);
  assert(result["writeAttempted"] == false && result["afterBytesHex"].is_null());
  assert(fixture.reads == 1 && fixture.writes == 0);
  fixture.expected = fixture.desired;
  result = fixture.run();
  assert(result["outcome"] == "unchanged" && result["beforeMatchesExpected"] == true);
  assert(result["writeAttempted"] == false && result["afterMatchesReplacement"].is_null());
  assert(fixture.reads == 1 && fixture.writes == 0);
  fixture.expected = "nope"; fixture.desired = "nope";
  assert(fixture.run()["outcome"] == "conflict"); // Equal request buffers are not permission to skip the compare.
}

void readFailures() {
  Fixture fixture;
  for (auto* setting : {&fixture.failRead, &fixture.shortRead, &fixture.excessRead, &fixture.throwRead, &fixture.deathRead}) {
    *setting = 1;
    const auto result = fixture.run();
    assert(result["outcome"] == "read-before-failed" && result["writeAttempted"] == false);
    assert(result["beforeMatchesExpected"].is_null() && !result["errors"].empty());
    assert(fixture.bytes == fixture.expected && fixture.writes == 0 && fixture.reads == 1);
    if (setting == &fixture.shortRead) assert(result["beforeBytesHex"] == "616263");
    if (setting == &fixture.excessRead) assert(result["beforeBytesHex"].is_null());
    if (setting == &fixture.deathRead) assert(result["debuggerAlive"] == false);
    *setting = 0;
  }
  for (auto* setting : {&fixture.failRead, &fixture.shortRead, &fixture.excessRead, &fixture.throwRead, &fixture.deathRead}) {
    fixture.bytes = fixture.expected; *setting = 2;
    const auto result = fixture.run();
    assert(result["outcome"] == "unverified" && result["writeAttempted"] == true);
    assert(result["writeAcknowledged"] == true && result["afterMatchesReplacement"].is_null());
    assert(fixture.bytes == fixture.desired && fixture.writes == 1 && fixture.reads == 2);
    if (setting == &fixture.shortRead) assert(result["afterBytesHex"] == "575859");
    if (setting == &fixture.excessRead) assert(result["afterBytesHex"].is_null());
    if (setting == &fixture.deathRead) assert(result["debuggerAlive"] == false);
    *setting = 0;
  }
}

void writeFailuresAndReadback() {
  Fixture fixture;
  fixture.writeResult = {true, false, true, "WRITE_FAILED", "target returned an error"};
  auto result = fixture.run();
  assert(result["outcome"] == "verified" && result["writeAcknowledged"] == false);
  assert(result["afterMatchesReplacement"] == true && result["errors"].size() == 1);
  assert(result["errors"][0]["phase"] == "write" && result["errors"][0]["code"] == "WRITE_FAILED");
  fixture.bytes = fixture.expected; fixture.partialWrite = true;
  result = fixture.run();
  assert(result["outcome"] == "readback-mismatch" && result["errors"].size() == 2);
  assert(result["afterBytesHex"] == "57586364" && result["afterMatchesBefore"] == false);
  assert(result["afterMatchesReplacement"] == false && fixture.bytes == "WXcd");
  assert(fixture.writes == 1); // No retry or automatic rollback after a partial write.
  fixture.bytes = fixture.expected; fixture.mutate = false;
  result = fixture.run();
  assert(result["outcome"] == "readback-mismatch" && result["afterMatchesBefore"] == true);
  fixture.writeResult = {true, true, true, {}, {}};
  result = fixture.run();
  assert(result["outcome"] == "readback-mismatch" && result["writeAcknowledged"] == true);
  fixture.writeResult = {false, false, true, "POLICY_REJECTED", "mapping changed before command submission"};
  result = fixture.run();
  assert(result["outcome"] == "write-rejected" && result["writeAttempted"] == false);
  assert(fixture.reads == 1 && fixture.writes == 1 && result["afterBytesHex"].is_null());
  fixture.mutate = true; fixture.partialWrite = false;
  fixture.writeResult = {true, false, false, "DEBUGGER_DIED", "transport closed during write"};
  result = fixture.run();
  assert(result["outcome"] == "unverified" && result["debuggerAlive"] == false);
  assert(fixture.reads == 1 && fixture.writes == 1 && fixture.bytes == fixture.desired);
  fixture.bytes = fixture.expected;
  fixture.writeResult = {false, true, true, {}, {}}; // Contradictory callback cannot prove no write.
  result = fixture.run();
  assert(result["outcome"] == "verified" && result["writeAttempted"] == true && result["writeAcknowledged"] == false);
  assert(result["errors"][0]["code"] == "INVALID_WRITE_RESULT");
}

void exceptionsAndExactBytes() {
  Fixture fixture;
  fixture.throwWrite = true; fixture.partialWrite = true;
  auto result = fixture.run();
  assert(result["writeAttempted"] == true && result["writeAcknowledged"] == false);
  assert(result["outcome"] == "readback-mismatch" && result["afterBytesHex"] == "57586364");
  assert(fixture.calls == std::vector<std::string>({"read", "write", "read"}));
  fixture.bytes = fixture.expected; fixture.partialWrite = false; fixture.unknownThrow = true;
  result = fixture.run();
  assert(result["outcome"] == "verified" && !result["errors"].empty());
  fixture.bytes = fixture.expected; fixture.failRead = 2;
  result = fixture.run();
  assert(result["outcome"] == "unverified" && fixture.bytes == fixture.desired && fixture.writes == 1);
  Fixture binary;
  binary.bytes = binary.expected = std::string("\0\xff\x80\x7f", 4);
  binary.desired = std::string("\xff\0\x7f\x80", 4);
  result = binary.run();
  assert(result["outcome"] == "verified" && result["beforeBytesHex"] == "00ff807f");
  assert(result["afterBytesHex"] == "ff007f80");
}

void boundsAndCallbackErrors() {
  Fixture fixture;
  fixture.expected.clear(); fixture.desired.clear();
  auto result = fixture.run();
  assert(result["outcome"] == "write-rejected" && result["errors"][0]["code"] == "INVALID_REQUEST");
  assert(fixture.reads == 0 && fixture.writes == 0);
  fixture.expected = "a"; fixture.desired = "ab";
  assert(fixture.run()["outcome"] == "write-rejected" && fixture.reads == 0);
  fixture.expected = fixture.bytes = std::string(256, '\0'); fixture.desired = std::string(256, '\xff');
  assert(fixture.run()["outcome"] == "verified");
  fixture.expected += 'a'; fixture.desired += 'a';
  result = fixture.run();
  assert(result["outcome"] == "write-rejected" && result["errors"][0]["code"] == "LIMIT_EXCEEDED");
  assert(result["expectedBytesHex"].is_null() && result["replacementBytesHex"].is_null() && fixture.reads == 0);
  fixture.expected = fixture.bytes = "a"; fixture.desired = "b"; fixture.address = UINT64_MAX;
  assert(fixture.run()["outcome"] == "write-rejected" && fixture.reads == 0);
  fixture.address = UINT64_MAX - 1;
  assert(fixture.run()["outcome"] == "verified");
  fixture.bytes = fixture.expected; fixture.writeResult.code = std::string(1024, 'X');
  fixture.writeResult.message = std::string(100000, '\xff');
  result = fixture.run();
  assert(result["outcome"] == "verified" && result["errors"][0]["code"].get<std::string>().size() == 64);
  assert(result["errors"][0]["message"].get<std::string>().size() <= 512);
  assert(!result.dump().empty()); // Error sanitization never corrupts the JSON report.
  fixture.bytes = fixture.expected; fixture.writeResult.code = std::string("BAD\0CODE", 8);
  fixture.writeResult.message = std::string(100000, '\0');
  result = fixture.run();
  assert(result["errors"][0]["code"] == "CALLBACK_ERROR" && result.dump().size() < 16384);
  std::size_t reads = 0;
  const auto noWriter = phantom::compareAndWriteMemory(1, "a", "b",
    [&](std::uint64_t, std::size_t) { ++reads; return phantom::MemoryEditRead{"a", true, {}, {}}; }, {});
  assert(noWriter["outcome"] == "write-rejected" && noWriter["writeAttempted"] == false && reads == 1);
  const auto noReader = phantom::compareAndWriteMemory(1, "a", "b", {}, {});
  assert(noReader["outcome"] == "read-before-failed" && noReader["writeAttempted"] == false);
  reads = 0;
  const auto unreliableRead = phantom::compareAndWriteMemory(1, "a", "b",
    [&](std::uint64_t, std::size_t) { ++reads; return phantom::MemoryEditRead{"a", true, "READ_FAILED", "full bytes but failed read"}; }, {});
  assert(unreliableRead["outcome"] == "read-before-failed" && unreliableRead["beforeMatchesExpected"].is_null() && reads == 1);
}
}  // namespace

int main() {
  verifiedAndConflict(); readFailures(); writeFailuresAndReadback(); exceptionsAndExactBytes(); boundsAndCallbackErrors();
  std::cout << "memory edit: compare, no-op, exact bytes, partial writes, readback, death and bounds passed\n";
}
