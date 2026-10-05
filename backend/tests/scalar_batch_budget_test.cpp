#include "phantom/memory_batch.hpp"
#include "phantom/scalar_codec.hpp"
#include "phantom/validation.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Json = nlohmann::json;
constexpr std::size_t reservation = 65536, requestBudget = 4096;

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
std::string addressText(std::uint64_t address) {
  char buffer[16];
  const auto result = std::to_chars(buffer, buffer + sizeof(buffer), address, 16);
  return "0x" + std::string(buffer, result.ptr);
}
Json decoded(const Json& scalar, const Json& bytesHex) {
  if (!bytesHex.is_string()) return nullptr;
  const auto& text = bytesHex.get_ref<const std::string&>();
  require(text.size() % 2 == 0, "helper returned odd-length hexadecimal");
  std::string raw;
  for (std::size_t i = 0; i < text.size(); i += 2) {
    unsigned byte = 0;
    const auto parsed = std::from_chars(text.data() + i, text.data() + i + 2, byte, 16);
    require(parsed.ec == std::errc{} && parsed.ptr == text.data() + i + 2, "helper returned invalid hexadecimal");
    raw += static_cast<char>(byte);
  }
  const auto value = phantom::decodeScalarStorage(scalar, raw);
  return value ? *value : Json(nullptr);
}

Json unsignedType() {
  return {{"kind", "integer"}, {"byteSize", 8}, {"bits", 64}, {"signed", false},
          {"byteOrder", "little"}, {"representation", "unsigned-binary"}};
}
Json floatType() {
  return {{"kind", "float"}, {"byteSize", 8}, {"bits", 64}, {"signed", nullptr},
          {"byteOrder", "little"}, {"representation", "ieee754-binary64"}};
}

struct Evidence {
  Json report, scalars, edits, mappings;
};

Evidence makeEvidence(const std::string& diagnostic, const std::string& typeName, bool floats) {
  const auto scalar = floats ? floatType() : unsignedType();
  const Json expected = floats ? Json{{"kind", "float"}, {"bits", 64}, {"rawBitsHex", "fff0000000000001"}} :
      Json{{"kind", "integer"}, {"decimal", "18446744073709551615"}, {"bits", 64}, {"signed", false}};
  const Json desired = floats ? Json{{"kind", "float"}, {"bits", 64}, {"rawBitsHex", "fff123456789abcd"}} :
      Json{{"kind", "integer"}, {"decimal", "18446744073709551614"}, {"bits", 64}, {"signed", false}};
  std::string before, after, reason;
  require(phantom::encodeScalarStorage(scalar, expected, before, reason) &&
          phantom::encodeScalarStorage(scalar, desired, after, reason), "budget test values cannot be encoded");
  std::vector<phantom::MemoryBatchEdit> edits;
  std::map<std::uint64_t, std::string> memory;
  for (std::uint64_t i = 0; i < 8; ++i) {
    edits.push_back({0xfffffff000000000ULL + i * 0x1000, before, after});
    memory[edits.back().address] = before;
  }
  std::size_t reads = 0, writes = 0;
  auto report = phantom::compareAndWriteMemoryBatch(edits,
    [&](std::uint64_t address, std::size_t count) -> phantom::MemoryEditRead {
      ++reads;
      require(count == 8, "budget test read is not an eight-byte scalar");
      // The last execution readback and all final reads retain complete bytes
      // alongside an error. This exercises every decoded-value phase while
      // still producing the maximum number of bounded failure diagnostics.
      if (reads >= 24) return {memory.at(address), true, std::string(64, '\\'), diagnostic};
      return {memory.at(address), true, {}, {}};
    }, [&](std::uint64_t address, std::string_view raw) -> phantom::MemoryEditWrite {
      ++writes;
      memory[address] = std::string(raw);
      if (writes == 8)
        return {false, true, true, std::string(64, '"'), diagnostic};
      return {true, true, true, {}, {}};
    });
  require(reads == 32 && writes == 8 && report["byteCount"] == 64 && report["failureIndex"] == 7 &&
          report["outcome"] == "interrupted", "test did not build the maximum typed batch report");
  require(report["items"][7]["execution"]["errors"].size() == 3,
          "last execution lacks contradictory-ack, write and readback errors");

  Evidence evidence{std::move(report), Json::array(), Json::array(), Json::array()};
  for (std::size_t i = 0; i < edits.size(); ++i) {
    // Emitted ASCII grammar allows at most frame:4095: + 256 identifier
    // bytes, slightly less than the validation locator bound of 272.
    const auto locator = "frame:4095:" + std::string(255, 'v') + static_cast<char>('a' + i);
    require(locator.size() == 267, "wrong maximum issued locator length");
    const auto snapshotId = "scalar-" + std::string(56, '9') + static_cast<char>('0' + i);
    require(snapshotId.size() == 64, "wrong conservative generated snapshot ID bound");
    const auto profile = floats ? "native-dwarf-scalar-v2" : "native-dwarf-scalar-v1";
    Json target = {{"available", true}, {"source", "gdb-python-dwarf"}, {"locator", locator},
      {"lifetime", "unknown"}, {"reason", nullptr}, {"typeName", typeName},
      {"scalar", scalar}, {"addressHex", addressText(edits[i].address)}};
    const auto& item = evidence.report["items"][i];
    Json provenance = {{"index", i}, {"profile", profile}, {"snapshotId", snapshotId},
      {"locator", locator}, {"target", target}, {"requestedValue", desired},
      {"preflightValue", decoded(scalar, item["preflight"]["bytesHex"])},
      {"beforeValue", decoded(scalar, item["execution"]["beforeBytesHex"])},
      {"afterValue", decoded(scalar, item["execution"]["afterBytesHex"])},
      {"finalValue", decoded(scalar, item["final"]["bytesHex"])}};
    require(provenance["preflightValue"] == expected && provenance["beforeValue"] == expected &&
            provenance["afterValue"] == desired && provenance["finalValue"] == desired,
            "full phase bytes lost exact typed representation");
    // Comparison failures and error-bearing samples remain explicit in the
    // raw report; decoded bytes do not turn a failed read into a verified one.
    require(item["final"]["matchesReplacement"].is_null() && item["final"]["error"].is_object(),
            "hostile final read unexpectedly became verified");
    evidence.scalars.push_back(std::move(provenance));
    evidence.edits.push_back({{"profile", profile}, {"snapshotId", snapshotId}, {"value", desired}});
    evidence.mappings.push_back({{"startAddressHex", "0xfffffff000000000"},
      {"endAddressHex", "0xffffffffffffffff"}, {"permissions", "rw-p"}});
  }
  return evidence;
}

void retainedByteBudget() {
  const phantom::ValidationLimits limits;
  require(limits.maxIdBytes == 256, "review retention test for new ID limits");
  std::string unicode;
  for (unsigned i = 0; i < 64; ++i) unicode += "🧪";
  require(unicode.size() == 256, "test type name is not the maximum UTF-8 byte length");
  const std::vector<std::string> names{std::string(256, '\0'), std::string(256, '"'),
                                     std::string(256, '\\'), unicode};
  const std::vector<std::string> diagnostics{std::string(10000, '\0'), std::string(10000, '"'),
                                           std::string(10000, '\\'), std::string(10000, '\xff'), unicode + unicode + unicode};
  std::size_t peak = 0, largestRawReport = 0, largestScalars = 0;
  for (bool floats : {false, true}) for (const auto& name : names) for (const auto& diagnostic : diagnostics) {
    auto evidence = makeEvidence(diagnostic, name, floats);
    largestRawReport = std::max(largestRawReport, evidence.report.dump().size());
    largestScalars = std::max(largestScalars, evidence.scalars.dump().size());
    const auto generatedId = std::string(64, '9');
    const auto hostileId = std::string(limits.maxIdBytes, '\0');
    const auto point = Json{{"branchId", generatedId}, {"eventOrdinal", phantom::max_json_safe_integer}};
    const auto stop = Json{{"stopId", generatedId}, {"stateRevision", phantom::max_json_safe_integer}};
    Json audit = {{"id", generatedId}, {"requestId", hostileId}, {"profile", "native-dwarf-scalar-batch-v1"},
      {"processInstanceId", generatedId}, {"beforePoint", point}, {"beforeStop", stop},
      {"afterPoint", point}, {"afterStop", stop}, {"branchId", generatedId},
      {"contextStatus", "refreshed"}, {"refreshError", nullptr}, {"mappings", evidence.mappings},
      {"report", evidence.report}, {"scalars", evidence.scalars}};
    // Deliberately overestimate: the envelope uses maximum escaped request,
    // workspace and session identifiers independently of the <=4096 request
    // bound. Such simultaneous values need not be realizable in one request.
    Json response = {{"protocolVersion", 1}, {"requestId", hostileId},
      {"workspace", {{"id", hostileId}, {"revisionId", hostileId}}},
      {"session", {{"id", hostileId}, {"generation", phantom::max_json_safe_integer}}}, {"ok", true},
      {"result", {{"kind", "memoryIntervention"}, {"intervention", audit},
                  {"throughSequence", phantom::max_json_safe_integer}}}};
    Json request = {{"protocolVersion", 1}, {"requestId", std::string(256, 'r')},
      {"workspace", {{"id", std::string(256, 'w')}, {"revisionId", std::string(256, 'v')}}},
      {"session", {{"id", generatedId}, {"generation", phantom::max_json_safe_integer}}}, {"expectedStop", stop},
      {"command", {{"kind", "writeScalarStorageBatch"}, {"profile", "native-dwarf-scalar-batch-v1"},
                   {"edits", evidence.edits}}}};
    require(request.dump().size() <= requestBudget, "eight legal generated snapshot handles exceed request budget");
    const auto serialized = response.dump();
    require(Json::parse(serialized) == response, "budget response lost valid UTF-8/JSON");
    // Include the entire original request reservation and 4096 additional
    // bytes beyond the explicitly constructed full response as headroom.
    const auto retained = serialized.size() + requestBudget + 4096;
    peak = std::max(peak, retained);
    require(retained < reservation, "typed batch response + original request exceed 64 KiB reservation");
  }
  std::cout << "scalar batch retention peak=" << peak << " bytes (includes 8192 extra), report="
            << largestRawReport << ", provenance=" << largestScalars << '\n';
}

void unavailableAndExactPhaseValues() {
  const auto type = unsignedType();
  require(decoded(type, nullptr).is_null() && decoded(type, "").is_null() &&
          decoded(type, "ffffffffffffff").is_null(), "partial/absent scalar bytes fabricated a value");
  const Json boolean = {{"kind", "boolean"}, {"byteSize", 1}, {"bits", 8}, {"signed", nullptr},
                        {"byteOrder", "little"}, {"representation", "boolean-01"}};
  require(decoded(boolean, "02").is_null(), "invalid bool phase bytes fabricated a value");
  require(decoded(boolean, "00") == Json({{"kind", "boolean"}, {"value", false}}), "valid false bytes rejected");
  require(decoded(floatType(), "010000000000f0ff") ==
      Json({{"kind", "float"}, {"bits", 64}, {"rawBitsHex", "fff0000000000001"}}),
      "signaling NaN phase evidence changed sign or payload");
}
} // namespace

int main() {
  try {
    retainedByteBudget(); unavailableAndExactPhaseValues();
    std::cout << "scalar batch budget and exact phase evidence passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "scalar batch budget: " << error.what() << '\n';
    return 1;
  }
}
