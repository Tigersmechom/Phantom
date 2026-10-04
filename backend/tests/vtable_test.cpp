#include "phantom/vtable.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {
using Json = nlohmann::json;
std::string hex(std::uint64_t value) {
  char bytes[32]; std::snprintf(bytes, sizeof(bytes), "0x%llx", static_cast<unsigned long long>(value));
  return bytes;
}
std::string word(std::uint64_t value) {
  std::string result(8, '\0');
  for (unsigned i = 0; i < 8; ++i) result[i] = static_cast<char>(value >> (i * 8));
  return result;
}
Json region(std::uint64_t start, std::uint64_t end, const char* permissions, unsigned inode = 0) {
  return {{"startAddressHex", hex(start)}, {"endAddressHex", hex(end)}, {"permissions", permissions},
    {"kind", inode ? "file" : "anonymous"}, {"device", "00:01"}, {"inodeDecimal", std::to_string(inode)}};
}
std::string module(unsigned inode) { return "module:0x0:0x1:" + std::to_string(inode); }
Json symbol(const char* name, const char* type, std::uint64_t address, std::uint64_t size, unsigned index = 1) {
  return {{"name", name}, {"type", type}, {"tableSectionIndex", 4}, {"index", index},
    {"definition", "section"}, {"valueKind", "virtual-address"}, {"runtimeMeaning", "address"},
    {"sizeHex", hex(size)}, {"runtimeLocations", Json::array({{
      {"status", "mapped"}, {"addressHex", hex(address)}, {"endAddressHex", hex(address + size)}}})}};
}
Json symbolReport(unsigned inode, const Json& values) {
  return {{"available", true}, {"identityVerified", true}, {"source", "linux-proc-maps-elf-symbols"},
    {"coverage", "complete"}, {"moduleId", module(inode)}, {"symbols", values}};
}
struct Fixture {
  Json maps = {{"available", true}, {"coverage", "complete"}, {"regions", Json::array({
    region(0x1000, 0x2000, "rw-p"), region(0x2000, 0x3000, "r--p", 1),
    region(0x3000, 0x4000, "r--p", 2), region(0x4000, 0x5000, "r-xp", 3)})}};
  std::map<std::uint64_t, unsigned char> bytes;
  std::map<std::string, Json> metadata;
  std::vector<std::pair<std::uint64_t, std::size_t>> reads;
  std::vector<std::string> metadataReads;
  std::uint64_t slot = 0x1100, point = 0x2100;
  std::size_t failRead = 0, shortRead = 0, throwRead = 0, changeSlotAtRead = 0, changeHeaderAtRead = 0;
  Fixture() {
    put(slot, word(point));
    put(point - 16, word(0) + word(0x3100));
    put(point, word(0x4100) + word(0) + word(UINT64_MAX - 15) + word(0x3100) + word(0x4200));
    metadata[module(1)] = symbolReport(1, Json::array({symbol("_ZTV1A", "STT_OBJECT", point - 16, 56)}));
    metadata[module(2)] = symbolReport(2, Json::array({symbol("_ZTI1A", "STT_OBJECT", 0x3100, 16)}));
    metadata[module(3)] = symbolReport(3, Json::array({symbol("_ZN1AD1Ev", "STT_FUNC", 0x4100, 32),
      symbol("_ZN1AD0Ev", "STT_FUNC", 0x4200, 32, 2), symbol("alias", "STT_FUNC", 0x4100, 32, 3),
      symbol("ifunc", "STT_GNU_IFUNC", 0x4100, 32, 4)}));
  }
  void put(std::uint64_t address, std::string_view data) {
    for (std::size_t i = 0; i < data.size(); ++i) bytes[address + i] = static_cast<unsigned char>(data[i]);
  }
  Json inspect(std::size_t count = 5) {
    reads.clear(); metadataReads.clear();
    return phantom::inspectItaniumVtable(slot, count, maps,
      [&](std::uint64_t address, std::size_t size) -> std::optional<std::string> {
        reads.emplace_back(address, size);
        if (changeSlotAtRead == reads.size()) put(slot, word(point + 8));
        if (changeHeaderAtRead == reads.size()) put(point - 16, word(UINT64_MAX - 7) + word(0x3100));
        if (throwRead == reads.size()) throw std::runtime_error("reader failed");
        if (failRead == reads.size()) return {};
        std::string result;
        for (std::size_t i = 0; i < size; ++i) {
          const auto found = bytes.find(address + i);
          if (found == bytes.end()) return {};
          result += static_cast<char>(found->second);
        }
        if (shortRead == reads.size() && !result.empty()) result.pop_back();
        return result;
      }, [&](std::string_view id) {
        metadataReads.emplace_back(id);
        const auto found = metadata.find(std::string(id));
        return found == metadata.end() ? Json{{"available", false}} : found->second;
      });
  }
};

void ordinaryAndSecondaryWords() {
  Fixture fixture;
  const auto result = fixture.inspect();
  assert(result["available"] == true && result["coverage"] == "complete");
  assert(result["abi"] == "itanium-x86_64-absolute-v1" && result["abiEvidence"] == "requested-profile");
  assert(result["lifetime"] == "unknown" && result["consistency"] == "sampled-not-atomic");
  assert(result["sampleStatus"] == "stable" && result["tableEnd"] == "unknown");
  assert(result["header"]["offsetToTopDecimal"] == "0" && result["header"]["topAddressCandidateHex"] == "0x1100");
  assert(result["tableSymbols"].size() == 1 && result["rttiSymbols"].size() == 1);
  assert(result["entries"].size() == 5);
  assert(result["entries"][0]["classification"] == "executable-address");
  assert(result["entries"][0]["functions"].size() == 2); // aliases retained, IFUNC not substituted
  assert(result["entries"][1]["classification"] == "null");
  assert(result["entries"][2]["classification"] == "other"); // Secondary header offset is not a method.
  assert(result["entries"][3]["classification"] == "other");
  assert(result["entries"][4]["classification"] == "executable-address");
  assert(fixture.reads.size() == 5 && fixture.metadataReads.size() == 3);
  assert(result["vptrSlot"]["bytesHex"] == "0021000000000000");
  assert(result["entries"][2]["bytesHex"] == "f0ffffffffffffff");
  const auto limited = fixture.inspect(64);
  assert(limited["available"] == true && limited["coverage"] == "partial");
  assert(limited["entries"].size() == 5 && limited["scanStop"] == "symbol-group-end");
  assert(limited["tableEnd"] == "unknown");
  // A shorter overlapping alias must not grant the longer symbol's extent.
  fixture.metadata[module(1)]["symbols"].push_back(symbol("_ZTV5Alias", "STT_OBJECT", fixture.point - 16, 24, 2));
  const auto alias = fixture.inspect();
  assert(alias["tableSymbols"].size() == 2 && alias["entries"].size() == 1);
  Fixture manyAliases;
  manyAliases.metadata[module(1)]["symbols"] = Json::array();
  for (unsigned i = 0; i < 129; ++i)
    manyAliases.metadata[module(1)]["symbols"].push_back(
      symbol("_ZTV1A", "STT_OBJECT", manyAliases.point - 16, i == 128 ? 24 : 56, i));
  const auto capped = manyAliases.inspect();
  assert(capped["tableSymbols"].size() == 128 && capped["coverage"] == "truncated");
  assert(capped["entries"].size() == 1 && capped["scanStop"] == "symbol-group-end");
}

void signedOffsetsAndNullRtti() {
  Fixture fixture;
  fixture.put(fixture.point - 16, word(UINT64_MAX - 15) + word(0));
  auto result = fixture.inspect();
  assert(result["available"] == true && result["header"]["offsetToTopDecimal"] == "-16");
  assert(result["header"]["topAddressCandidateHex"] == "0x10f0" && result["header"]["rttiAddressHex"] == "0x0");
  assert(result["rttiSymbols"].empty());
  fixture.put(fixture.point - 16, word(16) + word(0));
  fixture.metadata[module(1)]["symbols"][0]["name"] = "_ZTC1D0_1B";
  result = fixture.inspect();
  assert(result["available"] == true && result["header"]["offsetToTopDecimal"] == "16");
  assert(result["header"]["topAddressCandidateHex"] == "0x1110");
  assert(result["tableSymbols"][0]["kind"] == "construction-vtable");
  fixture.put(fixture.point - 16, word(std::uint64_t{1} << 63) + word(0));
  result = fixture.inspect();
  assert(result["available"] == true && result["coverage"] == "partial");
  assert(result["header"]["offsetToTopDecimal"] == "-9223372036854775808");
  assert(result["header"]["topAddressCandidateHex"].is_null() && result["reason"] == "offset-to-top-overflow");
  fixture.put(fixture.point - 16, word(0x6000) + word(0));
  result = fixture.inspect();
  assert(result["available"] == true && result["reason"] == "top-candidate-not-map-readable");
  // A packed/unaligned slot is safely decoded using byte reads on x86-64.
  fixture.slot += 1; fixture.put(fixture.slot, word(fixture.point));
  fixture.put(fixture.point - 16, word(0) + word(0));
  assert(fixture.inspect()["available"] == true);
  // Positive offset overflow at a high slot; no signed/unsigned wraparound.
  fixture.slot = UINT64_MAX - 0x100;
  fixture.maps["regions"].push_back(region(UINT64_MAX - 0x1000, UINT64_MAX, "rw-p"));
  fixture.put(fixture.slot, word(fixture.point));
  fixture.put(fixture.point - 16, word(0x200) + word(0));
  result = fixture.inspect();
  assert(result["available"] == true && result["header"]["topAddressCandidateHex"].is_null());
  assert(result["reason"] == "offset-to-top-overflow");
}

void mapsAndBoundaries() {
  Fixture fixture;
  fixture.maps["regions"][0]["permissions"] = "---p";
  auto result = fixture.inspect();
  assert(!result["available"] && result["reason"] == "vptr-slot-not-map-readable" && fixture.reads.empty());
  fixture.maps["regions"][0]["permissions"] = "rw-p";
  fixture.maps["regions"][1]["permissions"] = "---p";
  result = fixture.inspect();
  assert(!result["available"] && result["reason"] == "header-not-map-readable" && fixture.reads.size() == 1);
  fixture.maps["regions"][1]["permissions"] = "r--p";
  fixture.maps["regions"][1]["endAddressHex"] = hex(fixture.point + 13);
  result = fixture.inspect();
  assert(result["available"] == true && result["entries"].size() == 1 && result["scanStop"] == "map-boundary");
  assert(fixture.reads[2].second == 8); // Never zero-fill partial word or read across the gap.
  fixture.maps["regions"][1]["endAddressHex"] = hex(fixture.point);
  fixture.metadata[module(1)]["symbols"][0]["sizeHex"] = "0x10";
  fixture.metadata[module(1)]["symbols"][0]["runtimeLocations"][0]["endAddressHex"] = hex(fixture.point);
  result = fixture.inspect();
  assert(result["available"] == true && result["entries"].empty());
  assert(result["scanStop"] == "symbol-group-end" && fixture.reads.size() == 4);
  assert(result["tableSymbols"].size() == 1); // Zero-function table: AP can equal symbol end.
  fixture.maps["regions"][0]["endAddressHex"] = "0x1104";
  assert(fixture.inspect()["reason"] == "vptr-slot-not-map-readable");
  fixture.maps["coverage"] = "truncated";
  assert(fixture.inspect()["reason"] == "maps-unavailable");
  fixture.maps["coverage"] = "complete";
  fixture.maps["regions"][0]["startAddressHex"] = "0x10000000000000000";
  assert(fixture.inspect()["reason"] == "invalid-maps");
}

void malformedPointersAndReads() {
  Fixture fixture;
  fixture.put(fixture.slot, word(0));
  assert(fixture.inspect()["reason"] == "null-vptr");
  fixture.put(fixture.slot, word(8));
  assert(fixture.inspect()["reason"] == "header-address-underflow");
  fixture.put(fixture.slot, word(fixture.point + 1));
  assert(fixture.inspect()["reason"] == "misaligned-address-point");
  fixture.put(fixture.slot, word(fixture.point));
  fixture.put(fixture.point - 8, word(0xdeadbeef));
  assert(fixture.inspect()["reason"] == "rtti-pointer-not-map-readable");
  fixture.put(fixture.point - 8, word(0));
  fixture.failRead = 1;
  assert(fixture.inspect()["reason"] == "vptr-slot-read-failed");
  fixture.failRead = 2;
  assert(fixture.inspect()["reason"] == "header-read-failed");
  fixture.failRead = 3;
  auto result = fixture.inspect();
  assert(result["available"] == true && result["entries"].empty() && result["scanStop"] == "memory-read-failed");
  assert(result["sampleStatus"] == "stable");
  fixture.failRead = 4;
  result = fixture.inspect();
  assert(!result["available"] && result["reason"] == "consistency-read-failed" && result["sampleStatus"] == "unconfirmed");
  fixture.failRead = 0; fixture.shortRead = 1;
  assert(fixture.inspect()["reason"] == "vptr-slot-read-failed");
  fixture.shortRead = 3;
  assert(fixture.inspect()["entries"].empty());
  fixture.shortRead = 0; fixture.throwRead = 2;
  assert(fixture.inspect()["reason"] == "header-read-failed");
  fixture.throwRead = 0; fixture.changeSlotAtRead = 4;
  result = fixture.inspect();
  assert(!result["available"] && result["reason"] == "memory-changed" && result["sampleStatus"] == "changed");
  fixture.changeSlotAtRead = 0; fixture.put(fixture.slot, word(fixture.point)); fixture.changeHeaderAtRead = 5;
  result = fixture.inspect();
  assert(!result["available"] && result["reason"] == "memory-changed");
}

void unknownEvidenceAndBudgets() {
  Fixture fixture;
  fixture.metadata.clear();
  auto result = fixture.inspect();
  assert(result["available"] == true && result["coverage"] == "partial" && result["tableSymbols"].empty());
  assert(result["entries"].size() == 5 && result["entries"][0]["functions"].empty());
  fixture.metadata[module(1)] = {{"available", "malformed"}};
  assert(fixture.inspect()["available"] == true);
  fixture.metadata[module(1)] = symbolReport(1, Json::array({symbol("_ZTV1A", "STT_OBJECT", fixture.point - 16, 56)}));
  fixture.metadata[module(1)]["moduleId"] = "module:another-process";
  assert(fixture.inspect()["tableSymbols"].empty());
  fixture.metadata[module(1)] = symbolReport(1, Json::array({
    symbol("_ZTV4Fake", "STT_FUNC", fixture.point - 16, 56),
    symbol("_ZTV5Fake2", "STT_GNU_IFUNC", fixture.point - 16, 56, 2),
    symbol("_ZTV5Fake3", "STT_NOTYPE", fixture.point - 16, 56, 3)}));
  fixture.metadata[module(2)] = symbolReport(2, Json::array({symbol("_ZTI4Fake", "STT_GNU_IFUNC", 0x3100, 16)}));
  result = fixture.inspect();
  assert(result["available"] == true && result["tableSymbols"].empty() && result["rttiSymbols"].empty());
  fixture.metadata[module(1)]["symbols"][0]["type"] = "STT_OBJECT";
  fixture.metadata[module(1)]["symbols"][0]["definition"] = "undefined";
  assert(fixture.inspect()["tableSymbols"].empty());
  fixture.metadata.clear(); fixture.put(fixture.point - 8, word(0));
  std::string words;
  for (std::size_t i = 0; i < 64; ++i) words += word(0);
  fixture.put(fixture.point, words);
  result = fixture.inspect(64);
  assert(result["available"] == true && result["entries"].size() == 64);
  std::size_t bytes = 0;
  for (const auto& [address, size] : fixture.reads) { (void)address; bytes += size; }
  assert(fixture.reads.size() == 5 && bytes == 560);
  assert(fixture.inspect(0)["reason"] == "entry-limit" && fixture.reads.empty());
  assert(fixture.inspect(65)["reason"] == "entry-limit" && fixture.reads.empty());
  // More than four executable modules cannot trigger unbounded symbol reads.
  fixture.put(fixture.point - 8, word(0x3100));
  for (unsigned i = 4; i < 8; ++i) fixture.maps["regions"].push_back(region(i * 0x1000 + 0x1000, i * 0x1000 + 0x2000, "r-xp", i));
  fixture.put(fixture.point, word(0x4100) + word(0x5100) + word(0x6100) + word(0x7100) + word(0x8100));
  result = fixture.inspect();
  assert(result["available"] == true && result["metadata"]["requestedModules"] == 4);
  assert(result["metadata"]["truncated"] == true && result["coverage"] == "truncated");
  assert(fixture.metadataReads.size() == 4 && result["entries"].size() == 5);
}

void symbolMetadataBoundaries() {
  Fixture fixture;
  fixture.metadata[module(1)] = {{"available", false}, {"coverage", "none"}, {"moduleId", module(1)},
    {"source", "linux-proc-maps-elf-symbols"}, {"reason", "metadata-limit"}};
  auto result = fixture.inspect();
  assert(result["available"] == true && result["coverage"] == "truncated");
  assert(result["metadata"]["truncated"] == true && result["reason"] == "symbol-evidence-limit");
  Fixture names;
  auto invalidUtf8 = symbol("", "STT_FUNC", 0x4100, 32, 5);
  invalidUtf8["name"] = nullptr; invalidUtf8["nameBytesHex"] = "6666ff";
  names.metadata[module(3)]["symbols"].push_back(invalidUtf8);
  result = names.inspect();
  assert(result["entries"][0]["functions"].size() == 3);
  assert(result["entries"][0]["functions"][2]["name"].is_null());
  assert(result["entries"][0]["functions"][2]["nameBytesHex"] == "6666ff");
  Fixture aliases;
  for (unsigned i = 10; i < 150; ++i)
    aliases.metadata[module(3)]["symbols"].push_back(symbol("alias", "STT_FUNC", 0x4100, 32, i));
  result = aliases.inspect();
  assert(result["coverage"] == "truncated" && result["entries"].size() == 5);
  std::size_t labels = result["tableSymbols"].size() + result["rttiSymbols"].size();
  for (const auto& entry : result["entries"]) labels += entry["functions"].size();
  assert(labels == 128);
  Fixture limit;
  limit.metadata[module(3)]["symbols"] = Json::array();
  for (unsigned i = 0; i < 4097; ++i)
    limit.metadata[module(3)]["symbols"].push_back(symbol("alias", "STT_FUNC", 0x4100, 32, i));
  result = limit.inspect();
  assert(result["coverage"] == "truncated" && result["metadata"]["requestedModules"] == 3);
  auto invalidMap = limit.maps;
  invalidMap["regions"] = Json::array();
  for (unsigned i = 0; i < 8193; ++i) invalidMap["regions"].push_back(region(i * 16, i * 16 + 8, "rw-p"));
  const auto tooManyMaps = phantom::inspectItaniumVtable(0, 1, invalidMap, {}, {});
  assert(!tooManyMaps["available"] && tooManyMaps["reason"] == "maps-limit");
}
}  // namespace

int main() {
  ordinaryAndSecondaryWords();
  signedOffsetsAndNullRtti();
  mapsAndBoundaries();
  malformedPointersAndReads();
  unknownEvidenceAndBudgets();
  symbolMetadataBoundaries();
  std::cout << "vtable: sampled absolute headers, signed bounds, map permissions, aliases and budgets passed\n";
}
