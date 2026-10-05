#include "phantom/memory_batch.hpp"

#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
using Edit = phantom::MemoryBatchEdit;
using Read = phantom::MemoryEditRead;
using Write = phantom::MemoryEditWrite;

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
struct Fixture {
  std::vector<Edit> edits{{0x3000, "ab", "AB"}, {0x1000, "cd", "CD"}, {0x2000, "ef", "EF"}};
  std::map<std::uint64_t, std::string> memory;
  std::vector<std::string> calls;
  std::size_t reads = 0, writes = 0;
  std::function<std::optional<Read>(std::size_t)> onRead;
  std::function<std::optional<Write>(std::size_t, std::string_view)> onWrite;

  Json run() {
    memory.clear(); calls.clear(); reads = writes = 0;
    for (const auto& edit : edits) memory[edit.address] = edit.expectedRaw;
    const auto indexOf = [&](std::uint64_t address) {
      for (std::size_t i = 0; i < edits.size(); ++i) if (edits[i].address == address) return i;
      throw std::runtime_error("unexpected callback address");
    };
    auto result = phantom::compareAndWriteMemoryBatch(edits,
      [&](std::uint64_t address, std::size_t size) -> Read {
        const auto index = indexOf(address);
        require(size == edits[index].expectedRaw.size(), "unexpected read length");
        ++reads; calls.push_back("r" + std::to_string(index));
        if (onRead) if (auto override = onRead(index)) return *override;
        return {memory.at(address), true, {}, {}};
      }, [&](std::uint64_t address, std::string_view bytes) -> Write {
        const auto index = indexOf(address);
        require(bytes == edits[index].replacementRaw, "unexpected write bytes");
        ++writes; calls.push_back("w" + std::to_string(index));
        if (onWrite) if (auto override = onWrite(index, bytes)) return *override;
        memory[address] = std::string(bytes);
        return {true, true, true, {}, {}};
      });
    require(reads <= edits.size() * 4 && writes <= edits.size(), "callback bound exceeded");
    require(result.size() == 9 && result["items"].size() == edits.size(), "batch schema differs");
    require(result["atomic"] == false && result["rollbackAttempted"] == false, "batch claims atomicity/rollback");
    for (std::size_t i = 0; i < edits.size(); ++i) {
      const auto& item = result["items"][i];
      require(item.size() == 8 && item["index"] == i, "item schema/order differs");
      if (!item["preflight"].is_null()) require(item["preflight"].size() == 3, "preflight schema differs");
      if (!item["final"].is_null()) require(item["final"].size() == 4, "final schema differs");
    }
    return result;
  }
};

void noFinal(const Json& report) {
  for (const auto& item : report["items"]) require(item["final"].is_null(), "unexpected final read");
}
void allFinal(const Json& report) {
  for (const auto& item : report["items"]) require(item["final"].is_object(), "missing final read");
}

void orderAndNoops() {
  Fixture fixture;
  auto report = fixture.run();
  require(report["outcome"] == "verified" && report["preflightPassed"] == true &&
      report["writeAttempted"] == true && report["debuggerAlive"] == true && report["failureIndex"].is_null(), "successful batch failed");
  require(report["byteCount"] == 6, "wrong byte total");
  require(fixture.calls == std::vector<std::string>({"r0", "r1", "r2", "r0", "w0", "r0",
    "r1", "w1", "r1", "r2", "w2", "r2", "r0", "r1", "r2"}), "preflight/execution/final order is wrong");
  require(report["items"][0]["addressHex"] == "0x3000" && report["items"][1]["addressHex"] == "0x1000", "unsorted input reordered");
  for (const auto& item : report["items"]) {
    require(item["preflight"]["matchesExpected"] == true && item["execution"]["outcome"] == "verified", "bad success evidence");
    require(item["final"]["matchesExpected"] == false && item["final"]["matchesReplacement"] == true, "bad final evidence");
  }
  fixture.edits[1].replacementRaw = fixture.edits[1].expectedRaw;
  report = fixture.run();
  require(report["outcome"] == "verified" && fixture.writes == 2, "mixed noop batch failed");
  require(report["items"][1]["execution"]["outcome"] == "unchanged" &&
      report["items"][1]["final"]["matchesExpected"] == true &&
      report["items"][1]["final"]["matchesReplacement"] == true, "noop was skipped in final sweep");
  for (auto& edit : fixture.edits) edit.replacementRaw = edit.expectedRaw;
  report = fixture.run();
  require(report["outcome"] == "unchanged" && report["writeAttempted"] == false && report["failureIndex"].is_null(), "no-op batch failed");
  require(fixture.reads == 6 && fixture.writes == 0, "noop did not get fresh execution reads");
  noFinal(report);
}

void invalidRangesAndBoundaries() {
  const std::vector<std::vector<Edit>> invalid{
    {}, std::vector<Edit>(9, Edit{1, "a", "b"}), {{1, "", ""}}, {{1, "a", "ab"}},
    {{1, std::string(257, 'a'), std::string(257, 'b')}}, {{UINT64_MAX, "a", "b"}},
    {{UINT64_MAX - 1, "aa", "bb"}}, {{10, "ab", "AB"}, {11, "cd", "CD"}},
    {{10, "abcd", "ABCD"}, {11, "cd", "CD"}}, {{10, "a", "A"}, {10, "b", "B"}},
    {{1, std::string(128, 'a'), std::string(128, 'b')}, {1000, std::string(129, 'a'), std::string(129, 'b')}},
    {{1, "a", "b"}, {100, "c", "d"}, {200, "", ""}},
  };
  for (const auto& edits : invalid) {
    unsigned callbacks = 0;
    bool rejected = false;
    try {
      phantom::compareAndWriteMemoryBatch(edits,
        [&](std::uint64_t, std::size_t) { ++callbacks; return Read{}; },
        [&](std::uint64_t, std::string_view) { ++callbacks; return Write{}; });
    } catch (const std::invalid_argument&) { rejected = true; }
    require(rejected && callbacks == 0, "invalid range invoked a callback or was accepted");
  }
  Fixture fixture;
  fixture.edits = {{4, "cd", "CD"}, {2, "ab", "AB"}, {6, "ef", "EF"}};
  require(fixture.run()["outcome"] == "verified", "adjacent unsorted ranges rejected");
  fixture.edits = {{UINT64_MAX - 1, "a", "b"}};
  require(fixture.run()["outcome"] == "verified", "valid maximum extent rejected");
  fixture.edits = {{0, std::string(256, '\0'), std::string(256, '\xff')}};
  auto report = fixture.run();
  require(report["outcome"] == "verified" && report["byteCount"] == 256, "maximum payload rejected");
  require(report["items"][0]["preflight"]["bytesHex"] == std::string(512, '0') &&
      report["items"][0]["final"]["bytesHex"] == std::string(512, 'f'), "binary bytes were altered");
}

void preflightFailures() {
  Fixture fixture;
  fixture.onRead = [&](std::size_t index) -> std::optional<Read> {
    if (index == 1) return Read{"!!", true, {}, {}};
    return std::nullopt;
  };
  auto report = fixture.run();
  require(report["outcome"] == "preflight-failed" && report["preflightPassed"] == false && report["failureIndex"] == 1 &&
      fixture.reads == 2 && fixture.writes == 0, "preflight conflict did not abort");
  require(report["items"][1]["preflight"]["matchesExpected"] == false && report["items"][1]["preflight"]["error"].is_null(), "conflict fabricated read error");
  require(report["items"][2]["preflight"].is_null(), "preflight continued after conflict");
  noFinal(report);
  const std::vector<Read> failures{{std::nullopt, true, {}, {}}, {"", true, {}, {}}, {"c", true, {}, {}},
    {"cde", true, {}, {}}, {"cd", true, "READ_FAILED", "full bytes but failed read"}, {"cd", false, {}, {}}};
  for (const auto& failure : failures) {
    fixture.onRead = [&](std::size_t index) -> std::optional<Read> { return index == 1 ? std::optional(failure) : std::nullopt; };
    report = fixture.run();
    const auto& evidence = report["items"][1]["preflight"];
    require(report["outcome"] == "preflight-failed" && fixture.writes == 0 && fixture.reads == 2, "bad preflight read allowed writes");
    require(evidence["matchesExpected"].is_null() && evidence["error"].is_object(), "bad preflight read compared bytes");
    require(evidence["bytesHex"].is_null() == (!failure.bytes || failure.bytes->size() > 2), "read prefix retention incorrect");
    require(report["debuggerAlive"] == failure.debuggerAlive, "preflight lost liveness evidence");
    noFinal(report);
  }
  for (bool standard : {false, true}) {
    fixture.onRead = [&](std::size_t index) -> std::optional<Read> {
      if (index == 1) { if (standard) throw std::runtime_error("preflight exception"); throw 17; }
      return std::nullopt;
    };
    report = fixture.run();
    require(report["outcome"] == "preflight-failed" && report["debuggerAlive"] == true && fixture.writes == 0, "preflight exception escaped/invented death");
  }
  report = phantom::compareAndWriteMemoryBatch({{1, "a", "b"}}, {}, {});
  require(report["outcome"] == "preflight-failed" && report["writeAttempted"] == false, "missing reader was not contained");
}

void freshComparisonsAndWriteFailures() {
  for (std::size_t failIndex : {std::size_t(0), std::size_t(1)}) {
    Fixture fixture;
    fixture.onRead = [&](std::size_t index) -> std::optional<Read> {
      if (index == failIndex && fixture.reads == 4 + failIndex * 2) fixture.memory[fixture.edits[index].address] = "!!";
      return std::nullopt;
    };
    auto report = fixture.run();
    require(report["outcome"] == "interrupted" && report["preflightPassed"] == true && report["failureIndex"] == failIndex, "fresh execution did not detect external change");
    require(fixture.writes == failIndex && report["items"][failIndex]["execution"]["outcome"] == "conflict", "execution conflict wrote memory");
    if (failIndex == 0) noFinal(report); else allFinal(report);
  }
  for (const auto mode : {"ack-error", "partial", "reject", "throw", "throw-unknown", "contradictory"}) {
    Fixture fixture;
    fixture.onWrite = [&](std::size_t index, std::string_view raw) -> std::optional<Write> {
      if (index != 1) return std::nullopt;
      const std::string kind(mode);
      if (kind == "reject") return Write{false, false, true, "WRITE_FAILED", "mapping changed"};
      fixture.memory[fixture.edits[index].address] = kind == "partial" ? "Cd" : std::string(raw);
      if (kind == "throw") throw std::runtime_error("write failed after mutation");
      if (kind == "throw-unknown") throw 17;
      return Write{kind != "contradictory", kind == "contradictory", true, "WRITE_FAILED", "injected write error"};
    };
    const auto report = fixture.run();
    require(report["outcome"] == "interrupted" && report["failureIndex"] == 1 && report["writeAttempted"] == true, "failed execution was accepted");
    require(fixture.writes == 2 && report["items"][2]["execution"].is_null(), "later range written after execution failure");
    allFinal(report);
    require(report["items"][2]["final"]["matchesExpected"] == true && report["items"][2]["final"]["matchesReplacement"] == false, "skipped range omitted from final read");
    if (std::string(mode) == "ack-error") require(report["items"][1]["execution"]["outcome"] == "verified", "test did not exercise matching unacknowledged write");
    if (std::string(mode) == "partial") require(report["items"][1]["execution"]["outcome"] == "readback-mismatch", "partial write was lost");
  }
  Fixture fixture;
  fixture.onWrite = [](std::size_t, std::string_view) -> std::optional<Write> { return Write{false, false, true, {}, {}}; };
  auto report = fixture.run();
  require(report["outcome"] == "interrupted" && report["writeAttempted"] == false && fixture.writes == 1, "pre-submission rejection misreported");
  noFinal(report);
  unsigned reads = 0;
  report = phantom::compareAndWriteMemoryBatch({{1, "a", "b"}},
    [&](std::uint64_t, std::size_t) { ++reads; return Read{"a", true, {}, {}}; }, {});
  require(report["outcome"] == "interrupted" && report["writeAttempted"] == false && reads == 2, "missing writer behavior changed");
}

void readbackAndDeath() {
  for (const auto mode : {"missing", "short", "error", "throw", "unknown", "dead"}) {
    Fixture fixture;
    fixture.onRead = [&](std::size_t) -> std::optional<Read> {
      if (fixture.reads != 5) return std::nullopt; // First write's own readback.
      const std::string kind(mode);
      if (kind == "throw") throw std::runtime_error("readback exception");
      if (kind == "unknown") throw 17;
      if (kind == "short") return Read{"A", true, {}, {}};
      if (kind == "error") return Read{"AB", true, "READ_FAILED", "untrusted read"};
      if (kind == "dead") return Read{"AB", false, {}, {}};
      return Read{std::nullopt, true, {}, {}};
    };
    const auto report = fixture.run();
    require(report["outcome"] == "interrupted" && report["failureIndex"] == 0 && fixture.writes == 1, "readback failure did not halt execution");
    require(report["items"][0]["execution"]["outcome"] == "unverified", "missing readback was promoted to verified");
    if (std::string(mode) == "dead") {
      noFinal(report);
      require(report["debuggerAlive"] == false && fixture.reads == 5, "reads continued after death");
    } else {
      allFinal(report);
      require(report["items"][0]["final"]["matchesReplacement"] == true, "final evidence missing after failed readback");
    }
  }
  Fixture fixture;
  fixture.onWrite = [](std::size_t, std::string_view) -> std::optional<Write> {
    return Write{true, false, false, "DEBUGGER_DIED", "connection closed"};
  };
  const auto report = fixture.run();
  require(report["outcome"] == "interrupted" && report["debuggerAlive"] == false && fixture.reads == 4, "write death did not halt reads");
  noFinal(report);
}

void finalVerification() {
  for (bool firstNoop : {false, true}) {
    Fixture fixture;
    if (firstNoop) fixture.edits[0].replacementRaw = fixture.edits[0].expectedRaw;
    fixture.onWrite = [&](std::size_t index, std::string_view) -> std::optional<Write> {
      if (index == 2) fixture.memory[fixture.edits[0].address] = "!!";
      return std::nullopt;
    };
    const auto report = fixture.run();
    require(report["outcome"] == "verification-failed" && report["failureIndex"] == 0, "later corruption of an earlier range was missed");
    require(report["items"][0]["final"]["matchesReplacement"] == false && report["items"][0]["final"]["error"].is_null(), "final mismatch fabricated read failure");
    allFinal(report);
  }
  for (const auto mode : {"missing", "short", "excess", "error", "throw", "unknown", "dead"}) {
    Fixture fixture;
    fixture.onRead = [&](std::size_t) -> std::optional<Read> {
      if (fixture.reads != 10) return std::nullopt; // First final read after 3+6 execution reads.
      const std::string kind(mode);
      if (kind == "throw") throw std::runtime_error("final exception");
      if (kind == "unknown") throw 17;
      if (kind == "short") return Read{"A", true, {}, {}};
      if (kind == "excess") return Read{"ABC", true, {}, {}};
      if (kind == "error") return Read{"AB", true, "READ_FAILED", "untrusted final bytes"};
      if (kind == "dead") return Read{"AB", false, {}, {}};
      return Read{std::nullopt, true, {}, {}};
    };
    const auto report = fixture.run();
    require(report["outcome"] == "verification-failed" && report["failureIndex"] == 0 && fixture.writes == 3, "final read failure was ignored");
    const auto& final = report["items"][0]["final"];
    require(final["error"].is_object() && final["matchesExpected"].is_null() && final["matchesReplacement"].is_null(), "unreliable final bytes were compared");
    if (std::string(mode) == "dead") {
      require(report["debuggerAlive"] == false && fixture.reads == 10 && report["items"][1]["final"].is_null(), "final sweep continued after debugger death");
    } else { allFinal(report); require(fixture.reads == 12, "final read error prevented later evidence"); }
  }
  Fixture fixture;
  fixture.onWrite = [](std::size_t index, std::string_view) -> std::optional<Write> {
    return index == 1 ? std::optional(Write{true, false, true, "WRITE_FAILED", "failed write"}) : std::nullopt;
  };
  fixture.onRead = [&](std::size_t) -> std::optional<Read> {
    if (fixture.reads == 8) return Read{std::nullopt, false, {}, {}}; // First final read.
    return std::nullopt;
  };
  const auto report = fixture.run();
  require(report["outcome"] == "interrupted" && report["failureIndex"] == 1 && report["debuggerAlive"] == false,
          "later final failure overwrote first execution failure");
}

void hostileErrorBudgets() {
  std::vector<std::string> messages{std::string(10000, '\0'), std::string(10000, '"'),
    std::string(10000, '\\'), std::string(10000, '\xff'), std::string(10000, '\1')};
  std::string unicode;
  for (unsigned i = 0; i < 1000; ++i) unicode += "Ошибка 🧪";
  messages.push_back(unicode);
  for (const auto& message : messages) {
    Fixture fixture;
    fixture.edits.clear();
    for (std::uint64_t i = 0; i < 8; ++i) {
      const auto size = i == 7 ? 123 : 19;
      fixture.edits.push_back({0x20000000000000ULL + i * 512, std::string(size, '\0'), std::string(size, '\xff')});
    }
    fixture.onWrite = [&](std::size_t index, std::string_view raw) -> std::optional<Write> {
      if (index != 7) return std::nullopt;
      fixture.memory[fixture.edits[index].address] = std::string(raw);
      return Write{false, true, true, std::string(1000, '"'), message};
    };
    fixture.onRead = [&](std::size_t index) -> std::optional<Read> {
      if (fixture.reads < 24) return std::nullopt;
      return Read{fixture.memory[fixture.edits[index].address], true, std::string(1000, '\\'), message};
    };
    const auto report = fixture.run();
    require(report["outcome"] == "interrupted" && report["failureIndex"] == 7 && report["byteCount"] == 256,
            "hostile test did not reach last execution failure");
    require(report["items"][7]["execution"]["errors"].size() == 3, "hostile execution did not contain all three errors");
    allFinal(report);
    for (const auto& item : report["items"]) {
      const auto& error = item["final"]["error"];
      require(error["code"].get<std::string>().size() <= 64 && error["message"].get<std::string>().size() <= 512 &&
              error["message"].dump().size() <= 512, "error exceeded UTF-8/serialized budget");
    }
    const auto serialized = report.dump();
    require(serialized.size() + 8192 < 32768, "report + request/audit allowance exceeds retention reservation");
    require(Json::parse(serialized) == report, "hostile errors damaged JSON");
  }
  Fixture fixture;
  fixture.onRead = [](std::size_t) -> std::optional<Read> {
    return Read{std::nullopt, true, std::string("BAD\0CODE", 8), std::string(511, 'x') + "🧪"};
  };
  const auto report = fixture.run();
  require(report["items"][0]["preflight"]["error"]["code"] == "CALLBACK_ERROR", "control-bearing error code survived");
  require(report["items"][0]["preflight"]["error"]["message"].dump().size() <= 512, "partial UTF-8 error broke budget");
}
}  // namespace

int main() {
  try {
    orderAndNoops(); invalidRangesAndBoundaries(); preflightFailures();
    freshComparisonsAndWriteFailures(); readbackAndDeath(); finalVerification(); hostileErrorBudgets();
    std::cout << "memory batch: preflight, ordered writes, final sweep, partial failures, death and bounds passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "memory batch: " << error.what() << '\n';
    return 1;
  }
}
