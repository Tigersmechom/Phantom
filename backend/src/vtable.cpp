#include "phantom/vtable.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <stdexcept>
#include <vector>

namespace phantom {
namespace {
using Json = nlohmann::json;
constexpr std::size_t maxRegions = 8192, maxModules = 4, maxSymbols = 4096, maxLabels = 128;

std::optional<std::uint64_t> number(std::string_view value, int radix = 16) {
  if (radix == 16 && value.starts_with("0x")) value.remove_prefix(2);
  if (value.empty()) return {};
  std::uint64_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, radix);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) return {};
  return parsed;
}
std::optional<std::uint64_t> field(const Json& value, const char* key, int radix = 16) {
  const auto item = value.find(key);
  if (item == value.end() || !item->is_string()) return {};
  return number(item->get_ref<const std::string&>(), radix);
}
bool safeIndex(const Json& value) {
  return value.is_number_integer() && value >= 0 && value <= 9007199254740991ULL;
}
std::optional<std::string> symbolName(const Json& symbol) {
  if (!symbol.contains("name")) return {};
  if (symbol["name"].is_string()) {
    const auto& value = symbol["name"].get_ref<const std::string&>();
    return value.size() <= 1024 ? std::optional<std::string>(value) : std::nullopt;
  }
  if (!symbol["name"].is_null() || !symbol.contains("nameBytesHex") || !symbol["nameBytesHex"].is_string()) return {};
  const auto& value = symbol["nameBytesHex"].get_ref<const std::string&>();
  if (value.size() > 2048 || value.size() % 2 != 0) return {};
  std::string decoded; decoded.reserve(value.size() / 2);
  for (std::size_t i = 0; i < value.size(); i += 2) {
    const auto byte = number(std::string_view(value).substr(i, 2));
    if (!byte) return {};
    decoded += static_cast<char>(*byte);
  }
  return decoded;
}
std::string hex(std::uint64_t value) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  return "0x" + std::string(buffer.data(), result.ptr);
}
std::string bytesHex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result; result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
  return result;
}
std::uint64_t little(std::string_view bytes) {
  std::uint64_t result = 0;
  for (unsigned i = 0; i < 8; ++i) result |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[i])) << (i * 8);
  return result;
}
std::optional<std::uint64_t> add(std::uint64_t a, std::uint64_t b) {
  return a > UINT64_MAX - b ? std::nullopt : std::optional<std::uint64_t>(a + b);
}
// Decode two's-complement ptrdiff_t without implementation-defined unsigned to
// signed conversions or negating INT64_MIN.
std::uint64_t magnitude(std::uint64_t word) { return (word >> 63) ? (~word + 1) : word; }
std::string signedDecimal(std::uint64_t word) {
  return (word >> 63 ? "-" : "") + std::to_string(magnitude(word));
}
std::optional<std::uint64_t> topCandidate(std::uint64_t slot, std::uint64_t offset) {
  const auto amount = magnitude(offset);
  if ((offset >> 63) == 0) return add(slot, amount);
  return slot < amount ? std::nullopt : std::optional<std::uint64_t>(slot - amount);
}

struct Region {
  std::uint64_t start, end;
  bool readable, executable;
  std::string moduleId;
};
class Maps {
 public:
  explicit Maps(const Json& map) {
    if (!map.is_object() || map.value("available", false) != true || map.value("coverage", "") != "complete" ||
        !map.contains("regions") || !map["regions"].is_array()) throw std::invalid_argument("maps-unavailable");
    if (map["regions"].size() > maxRegions) throw std::invalid_argument("maps-limit");
    std::uint64_t previousEnd = 0;
    for (const auto& item : map["regions"]) {
      if (!item.is_object()) throw std::invalid_argument("invalid-maps");
      const auto start = field(item, "startAddressHex"), end = field(item, "endAddressHex");
      if (!start || !end || *start >= *end || *start < previousEnd || !item.contains("permissions") ||
          !item["permissions"].is_string()) throw std::invalid_argument("invalid-maps");
      const auto permission = item["permissions"].get<std::string>();
      if (permission.size() != 4 || (permission[0] != 'r' && permission[0] != '-') ||
          (permission[1] != 'w' && permission[1] != '-') || (permission[2] != 'x' && permission[2] != '-') ||
          (permission[3] != 'p' && permission[3] != 's')) throw std::invalid_argument("invalid-maps");
      Region region{*start, *end, permission[0] == 'r', permission[2] == 'x', {}};
      if (item.value("kind", "") == "file") {
        const auto inode = field(item, "inodeDecimal", 10);
        if (!inode || !item.contains("device") || !item["device"].is_string()) throw std::invalid_argument("invalid-maps");
        const auto device = item["device"].get<std::string>();
        const auto colon = device.find(':');
        if (colon == std::string::npos) throw std::invalid_argument("invalid-maps");
        const auto major = number(std::string_view(device).substr(0, colon));
        const auto minor = number(std::string_view(device).substr(colon + 1));
        if (!major || !minor) throw std::invalid_argument("invalid-maps");
        if (*inode != 0) region.moduleId = "module:" + hex(*major) + ":" + hex(*minor) + ":" + std::to_string(*inode);
      }
      ranges_.push_back(std::move(region)); previousEnd = *end;
    }
  }
  const Region* containing(std::uint64_t address) const {
    const auto it = std::lower_bound(ranges_.begin(), ranges_.end(), address,
      [](const Region& region, std::uint64_t at) { return region.end <= at; });
    return it == ranges_.end() || it->start > address ? nullptr : &*it;
  }
  std::size_t readablePrefix(std::uint64_t address, std::size_t desired) const {
    std::size_t bytes = 0;
    while (bytes < desired) {
      const auto next = add(address, bytes);
      if (!next) break;
      const auto* region = containing(*next);
      if (!region || !region->readable) break;
      bytes += static_cast<std::size_t>(std::min<std::uint64_t>(desired - bytes, region->end - *next));
    }
    return bytes;
  }
  bool readable(std::uint64_t address, std::size_t size) const {
    return size != 0 && add(address, size).has_value() && readablePrefix(address, size) == size;
  }
 private:
  std::vector<Region> ranges_;
};

struct SymbolEvidence {
  Json label;
  std::uint64_t address, size;
};
class Symbols {
 public:
  Symbols(const Maps& maps, const VtableSymbolReader& reader) : maps_(maps), reader_(reader) {}
  std::size_t requestedModules = 0;
  bool truncated = false, unavailable = false;
  std::optional<std::uint64_t> minimumTableEnd;

  std::vector<SymbolEvidence> find(std::uint64_t address, std::string_view kind,
                                   std::optional<std::uint64_t> header = {}) {
    std::vector<SymbolEvidence> found;
    // A header may be the last bytes of a mapped table whose address point is
    // one-past-end. Module provenance comes from the readable header in that
    // case, not from the following allocation.
    const auto* region = maps_.containing(header.value_or(address));
    if (!region || region->moduleId.empty()) { unavailable = true; return found; }
    const auto* entries = get(region->moduleId);
    if (!entries) return found;
    for (const auto& entry : *entries) {
      const auto& label = entry.label;
      if (kind == "table") {
        if (label["kind"] != "vtable" && label["kind"] != "construction-vtable") continue;
        const auto end = add(entry.address, entry.size);
        if (!header || entry.size < 16 || !end || entry.address > *header || address > *end) continue;
        // Output-label retention must not weaken a known table-group bound.
        // Keep examining the bounded metadata cache after labels fill up.
        if (!minimumTableEnd || *end < *minimumTableEnd) minimumTableEnd = *end;
      } else if (label["kind"] != kind || entry.address != address) continue;
      if (labels_ >= maxLabels) {
        truncated = true;
        if (kind == "table") continue;
        break;
      }
      ++labels_; found.push_back(entry);
    }
    return found;
  }
 private:
  const Maps& maps_;
  const VtableSymbolReader& reader_;
  std::size_t labels_ = 0;
  std::map<std::string, std::vector<SymbolEvidence>> cache_;
  const std::vector<SymbolEvidence>* get(const std::string& id) {
    if (const auto saved = cache_.find(id); saved != cache_.end()) return &saved->second;
    if (requestedModules >= maxModules) { truncated = true; unavailable = true; return nullptr; }
    ++requestedModules;
    auto& entries = cache_[id];
    try {
      const auto report = reader_ ? reader_(id) : Json(nullptr);
      if (report.is_object() && report.value("source", "") == "linux-proc-maps-elf-symbols" &&
          report.value("moduleId", "") == id) {
        const auto reason = report.value("reason", "");
        if (reason == "metadata-limit" || reason == "section-header-limit" || reason == "program-header-limit" ||
            reason == "inspection-limit" || reason == "symbol-limit" || reason == "name-limit" ||
            reason == "total-name-limit" || reason == "file-limit" || reason == "note-limit" || reason == "build-id-limit")
          truncated = true;
      }
      if (!report.is_object() || !report.value("available", false) || !report.value("identityVerified", false) ||
          report.value("source", "") != "linux-proc-maps-elf-symbols" || report.value("moduleId", "") != id ||
          !report.contains("symbols") || !report["symbols"].is_array()) { unavailable = true; return &entries; }
      const auto coverage = report.value("coverage", "none");
      if (coverage != "complete" && coverage != "partial" && coverage != "truncated") { unavailable = true; return &entries; }
      if (coverage != "complete") unavailable = true;
      if (coverage == "truncated" || report["symbols"].size() > maxSymbols) truncated = true;
      std::size_t count = 0;
      for (const auto& symbol : report["symbols"]) {
        if (count++ == maxSymbols) break;
        if (!symbol.is_object() ||
            !symbol.contains("type") || !symbol["type"].is_string() ||
            !symbol.contains("runtimeLocations") || !symbol["runtimeLocations"].is_array() ||
            !symbol.contains("tableSectionIndex") || !safeIndex(symbol["tableSectionIndex"]) ||
            !symbol.contains("index") || !safeIndex(symbol["index"])) continue;
        if (symbol.value("definition", "") != "section" || symbol.value("valueKind", "") != "virtual-address" ||
            symbol.value("runtimeMeaning", "") != "address") continue;
        const auto decodedName = symbolName(symbol);
        if (!decodedName) continue;
        const auto& name = *decodedName;
        const auto& type = symbol["type"].get_ref<const std::string&>();
        std::string kind;
        if (type == "STT_OBJECT" && name.size() > 4 && name.starts_with("_ZTV")) kind = "vtable";
        else if (type == "STT_OBJECT" && name.size() > 4 && name.starts_with("_ZTC")) kind = "construction-vtable";
        else if (type == "STT_OBJECT" && name.size() > 4 && name.starts_with("_ZTI")) kind = "rtti";
        else if (type == "STT_FUNC") kind = "function";
        else continue;
        if (name.size() > 1024 || type.size() > 64 || symbol["runtimeLocations"].size() > 128) { truncated = true; continue; }
        const auto size = field(symbol, "sizeHex");
        if (!size) continue;
        for (const auto& location : symbol["runtimeLocations"]) {
          if (entries.size() == maxSymbols) { truncated = true; break; }
          if (!location.is_object() || location.value("status", "") != "mapped") continue;
          const auto address = field(location, "addressHex"), end = field(location, "endAddressHex");
          if (!address || !end || add(*address, *size) != end) continue;
          // A report from another address space/file must not become a label
          // merely because it contains a syntactically valid location.
          const auto* mapped = maps_.containing(*address);
          if (!mapped || mapped->moduleId != id) continue;
          Json label = {{"moduleId", id}, {"tableSectionIndex", symbol["tableSectionIndex"]},
            {"index", symbol["index"]}, {"name", symbol["name"]}, {"type", type}, {"addressHex", hex(*address)},
            {"sizeHex", hex(*size)}, {"kind", kind}};
          if (symbol["name"].is_null()) label["nameBytesHex"] = symbol["nameBytesHex"];
          entries.push_back({std::move(label), *address, *size});
        }
        if (entries.size() == maxSymbols) { truncated = true; break; }
      }
    } catch (const std::exception&) {
      entries.clear(); unavailable = true;
    }
    return &entries;
  }
};

Json labels(const std::vector<SymbolEvidence>& entries) {
  Json result = Json::array();
  for (const auto& entry : entries) result.push_back(entry.label);
  return result;
}
}  // namespace

nlohmann::json inspectItaniumVtable(std::uint64_t slotAddress, std::size_t requested,
    const Json& memoryMap, const VtableMemoryReader& readMemory, const VtableSymbolReader& readSymbols) {
  Json report = {{"available", false}, {"source", "itanium-vtable-memory"},
    {"abi", "itanium-x86_64-absolute-v1"}, {"abiEvidence", "requested-profile"},
    {"lifetime", "unknown"}, {"consistency", "sampled-not-atomic"}, {"sampleStatus", "unconfirmed"},
    {"coverage", "none"}, {"vptrAddressHex", hex(slotAddress)}, {"requestedEntries", requested},
    {"entries", Json::array()}, {"vptrSlot", nullptr}, {"header", nullptr},
    {"tableSymbols", Json::array()}, {"rttiSymbols", Json::array()}, {"tableEnd", "unknown"},
    {"scanStop", "not-started"}, {"metadata", {{"requestedModules", 0}, {"truncated", false}}}};
  const auto fail = [&](const char* reason) { report["reason"] = reason; return report; };
  if (requested == 0 || requested > 64) return fail("entry-limit");
  try {
    const Maps maps(memoryMap);
    const auto read = [&](std::uint64_t address, std::size_t size) -> std::optional<std::string> {
      if (!maps.readable(address, size) || !readMemory) return {};
      try {
        auto bytes = readMemory(address, size);
        if (!bytes || bytes->size() != size) return {};
        return bytes;
      } catch (const std::exception&) { return {}; }
    };
    if (!maps.readable(slotAddress, 8)) return fail("vptr-slot-not-map-readable");
    const auto slot = read(slotAddress, 8);
    if (!slot) return fail("vptr-slot-read-failed");
    const auto addressPoint = little(*slot);
    report["vptrSlot"] = {{"addressHex", hex(slotAddress)}, {"bytesHex", bytesHex(*slot)}, {"valueHex", hex(addressPoint)}};
    if (addressPoint == 0) return fail("null-vptr");
    if (addressPoint < 16) return fail("header-address-underflow");
    if (addressPoint % 8 != 0) return fail("misaligned-address-point");
    const auto headerAddress = addressPoint - 16;
    if (!maps.readable(headerAddress, 16)) return fail("header-not-map-readable");
    const auto header = read(headerAddress, 16);
    if (!header) return fail("header-read-failed");
    const auto offset = little(*header), rtti = little(std::string_view(*header).substr(8));
    const auto top = topCandidate(slotAddress, offset);
    report["header"] = {{"addressHex", hex(headerAddress)}, {"bytesHex", bytesHex(*header)},
      {"offsetToTopDecimal", signedDecimal(offset)}, {"topAddressCandidateHex", top ? Json(hex(*top)) : Json(nullptr)},
      {"rttiAddressHex", hex(rtti)}};
    const std::string candidateIssue = !top ? "offset-to-top-overflow" :
      !maps.readable(*top, 1) ? "top-candidate-not-map-readable" : "";
    if (rtti != 0 && (rtti % 8 != 0 || !maps.readable(rtti, 8))) return fail("rtti-pointer-not-map-readable");
    Symbols symbols(maps, readSymbols);
    const auto tables = symbols.find(addressPoint, "table", headerAddress);
    report["tableSymbols"] = labels(tables);
    if (rtti != 0) report["rttiSymbols"] = labels(symbols.find(rtti, "rtti"));
    std::size_t bytes = requested * 8;
    report["scanStop"] = "requested-limit";
    if (symbols.minimumTableEnd && *symbols.minimumTableEnd - addressPoint < bytes) {
      bytes = static_cast<std::size_t>(*symbols.minimumTableEnd - addressPoint);
      report["scanStop"] = "symbol-group-end";
    }
    const auto readable = maps.readablePrefix(addressPoint, bytes);
    if (readable < bytes) { bytes = readable; report["scanStop"] = "map-boundary"; }
    bytes -= bytes % 8;
    if (bytes != 0) {
      const auto window = read(addressPoint, bytes);
      if (!window) report["scanStop"] = "memory-read-failed";
      else for (std::size_t i = 0; i < bytes / 8; ++i) {
        const auto wordBytes = std::string_view(*window).substr(i * 8, 8);
        const auto value = little(wordBytes);
        const auto* target = maps.containing(value);
        const char* classification = value == 0 ? "null" : target && target->executable ? "executable-address" : "other";
        auto functions = value != 0 && target && target->executable ? symbols.find(value, "function") : std::vector<SymbolEvidence>{};
        report["entries"].push_back({{"index", i}, {"addressHex", hex(addressPoint + i * 8)},
          {"bytesHex", bytesHex(wordBytes)}, {"valueHex", hex(value)}, {"classification", classification},
          {"functions", labels(functions)}});
      }
    }
    report["metadata"] = {{"requestedModules", symbols.requestedModules}, {"truncated", symbols.truncated}};
    // Re-read the original anchors, even if scanning the forward window failed.
    // Changed pointers never cause dereferencing a new unchecked address here.
    const auto slotAfter = read(slotAddress, 8), headerAfter = read(headerAddress, 16);
    if (!slotAfter || !headerAfter) { report["coverage"] = "partial"; return fail("consistency-read-failed"); }
    if (*slotAfter != *slot || *headerAfter != *header) {
      report["sampleStatus"] = "changed"; report["coverage"] = "partial"; return fail("memory-changed");
    }
    report["sampleStatus"] = "stable";
    report["available"] = true;
    const bool incomplete = !candidateIssue.empty() || report["entries"].size() != requested || tables.empty() || symbols.unavailable;
    report["coverage"] = symbols.truncated ? "truncated" : incomplete ? "partial" : "complete";
    if (!candidateIssue.empty()) report["reason"] = candidateIssue;
    else if (symbols.truncated) report["reason"] = "symbol-evidence-limit";
    else if (report["entries"].size() != requested) report["reason"] = "forward-window-incomplete";
    else if (tables.empty() || symbols.unavailable) report["reason"] = "symbol-evidence-unavailable";
    return report;
  } catch (const std::invalid_argument& error) { return fail(error.what()); }
    catch (const Json::exception&) { return fail("invalid-maps"); }
}

}  // namespace phantom
