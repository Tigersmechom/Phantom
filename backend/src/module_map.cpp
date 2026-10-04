#include "phantom/module_map.hpp"

#include "phantom/elf.hpp"
#include "phantom/elf_symbols.hpp"
#include "phantom/memory_map.hpp"
#include "phantom/process_inspection.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {
using Json = nlohmann::json;

Json failure(std::string reason, std::string detail) {
  return {{"available", false}, {"reason", std::move(reason)}, {"detail", std::move(detail)}};
}
Json unavailable(std::string reason, std::string detail) {
  auto result = failure(std::move(reason), std::move(detail));
  result.update({{"source", "linux-proc-maps-elf"}, {"coverage", "none"},
                 {"identityVerified", false}, {"modules", Json::array()}});
  return result;
}
Json symbolsUnavailable(std::string_view moduleId, std::string reason, std::string detail) {
  auto result = failure(std::move(reason), std::move(detail));
  result.update({{"source", "linux-proc-maps-elf-symbols"}, {"coverage", "none"},
    {"identityVerified", false}, {"moduleId", moduleId}, {"contentIdentity", "file-metadata-only"},
    {"sections", Json::array()}, {"symbols", Json::array()}});
  return result;
}

#ifdef __linux__
struct Fd {
  int value = -1;
  explicit Fd(int fd = -1) : value(fd) {}
  ~Fd() { if (value >= 0) ::close(value); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
};

std::optional<std::uint64_t> number(std::string_view value, int radix = 16) {
  if (radix == 16 && value.starts_with("0x")) value.remove_prefix(2);
  if (value.empty()) return {};
  std::uint64_t out = 0;
  const auto parsed = std::from_chars(value.data(), value.data() + value.size(), out, radix);
  if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return {};
  return out;
}
std::uint64_t field(const Json& object, const char* name, int radix = 16) {
  auto value = number(object.at(name).get<std::string>(), radix);
  if (!value) throw std::invalid_argument("invalid numeric maps/ELF field");
  return *value;
}
std::string hex(std::uint64_t value) {
  std::array<char, 16> buffer{};
  auto out = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  return "0x" + std::string(buffer.data(), out.ptr);
}
std::optional<std::uint64_t> add(std::uint64_t a, std::uint64_t b) {
  if (a > UINT64_MAX - b) return {};
  return a + b;
}
std::optional<std::uint64_t> roundUp(std::uint64_t value, std::uint64_t page) {
  if (value % page == 0) return value;
  return add(value, page - value % page);
}

struct Region {
  const Json* dto;
  std::uint64_t start, end, offset, major, minor, inode;
  std::string key;
};
std::vector<Region> regions(const Json& map, std::size_t limit, bool& truncated) {
  const auto& items = map.at("regions");
  if (!items.is_array()) throw std::invalid_argument("maps regions must be an array");
  std::vector<Region> result;
  std::uint64_t previousEnd = 0;
  for (const auto& item : items) {
    if (result.size() == limit) { truncated = true; break; }
    const auto device = item.at("device").get<std::string>();
    const auto colon = device.find(':');
    if (colon == std::string::npos) throw std::invalid_argument("invalid maps device");
    const auto major = number(std::string_view(device).substr(0, colon));
    const auto minor = number(std::string_view(device).substr(colon + 1));
    if (!major || !minor) throw std::invalid_argument("invalid maps device");
    Region region{&item, field(item, "startAddressHex"), field(item, "endAddressHex"),
      field(item, "offsetHex"), *major, *minor, field(item, "inodeDecimal", 10), {}};
    if (region.start >= region.end || region.start < previousEnd)
      throw std::invalid_argument("unordered or empty maps range");
    previousEnd = region.end;
    const auto permission = item.at("permissions").get<std::string>();
    if (permission.size() != 4 || (permission[0] != 'r' && permission[0] != '-') ||
        (permission[1] != 'w' && permission[1] != '-') ||
        (permission[2] != 'x' && permission[2] != '-') ||
        (permission[3] != 'p' && permission[3] != 's'))
      throw std::invalid_argument("invalid maps permissions");
    region.key = hex(*major) + ":" + hex(*minor) + ":" + std::to_string(region.inode);
    result.push_back(region);
  }
  return result;
}

Json processStat(int procFd) {
  Fd fd(::openat(procFd, "stat", O_RDONLY | O_CLOEXEC | O_NONBLOCK));
  if (fd.value < 0) return failure("process-unavailable", "cannot read pinned process stat");
  std::string buffer(65537, '\0');
  std::size_t used = 0;
  while (used < buffer.size()) {
    const auto got = ::read(fd.value, buffer.data() + used, buffer.size() - used);
    if (got > 0) used += static_cast<std::size_t>(got);
    else if (got == 0) break;
    else if (errno != EINTR) return failure("process-unavailable", "cannot read pinned process stat");
  }
  if (used == buffer.size()) return failure("stat-limit", "process stat exceeds read limit");
  buffer.resize(used);
  return parseLinuxProcessStat(buffer);
}

Json processMaps(int procFd) {
  Fd fd(::openat(procFd, "maps", O_RDONLY | O_CLOEXEC | O_NONBLOCK));
  if (fd.value < 0) return failure("maps-unavailable", "cannot read pinned process maps");
  constexpr std::size_t maxBytes = 1024 * 1024;
  std::string bytes(maxBytes + 1, '\0');
  std::size_t used = 0;
  while (used < bytes.size()) {
    const auto got = ::read(fd.value, bytes.data() + used, bytes.size() - used);
    if (got > 0) used += static_cast<std::size_t>(got);
    else if (got == 0) break;
    else if (errno != EINTR) return failure("maps-unavailable", "cannot read pinned process maps");
  }
  bytes.resize(used);
  return parseLinuxMemoryMap(bytes, {maxBytes, 8192}, used > maxBytes);
}

std::optional<std::string> rawPath(const Json& region) {
  if (region.contains("path") && region["path"].is_string()) return region["path"].get<std::string>();
  if (!region.contains("pathBytesHex")) return {};
  auto bytes = region["pathBytesHex"].get<std::string>();
  if (bytes.size() % 2 != 0 || bytes.size() > 32768) return {};
  std::string result;
  for (std::size_t i = 0; i < bytes.size(); i += 2) {
    auto byte = number(std::string_view(bytes).substr(i, 2));
    if (!byte) return {};
    result += static_cast<char>(*byte);
  }
  return result;
}
bool identityMatches(const struct stat& st, const Region& region) {
  return S_ISREG(st.st_mode) && static_cast<std::uint64_t>(st.st_ino) == region.inode &&
    static_cast<std::uint64_t>(::major(st.st_dev)) == region.major &&
    static_cast<std::uint64_t>(::minor(st.st_dev)) == region.minor;
}
bool sameVersion(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
    a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
    a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

int openMappedFile(int procFd, const std::vector<const Region*>& group, Json& evidence,
                   struct stat& version) {
  bool mismatch = false, denied = false;
  int lastError = ENOENT;
  const auto attempt = [&](const std::string& path, const char* via, bool expectedIdentity = true) -> int {
    const int fd = ::openat(procFd, path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
      lastError = errno;
      denied = denied || errno == EACCES || errno == EPERM;
      return -1;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !identityMatches(st, *group.front())) {
      mismatch = mismatch || expectedIdentity;
      ::close(fd);
      return -1;
    }
    version = st;
    evidence = {{"available", true}, {"identityVerified", true}, {"openedVia", via}};
    return fd;
  };
  // One map_files link suffices for this inode. It pins deleted/replaced files
  // when the kernel permits following these links (often capability-gated).
  const auto* first = group.front();
  auto mapName = "map_files/" + hex(first->start).substr(2) + "-" + hex(first->end).substr(2);
  int fd = attempt(mapName, "map-files");
  if (fd >= 0) return fd;
  // exe can still pin the original executable after rename/unlink.
  fd = attempt("exe", "process-exe", false);
  if (fd >= 0) return fd;
  std::set<std::string> tried;
  for (const auto* region : group) {
    const auto path = rawPath(*region->dto);
    // Do not unescape \\012 or strip '(deleted)': both are ambiguous filenames.
    if (tried.size() >= 16) break;
    if (!path || path->empty() || path->front() != '/' || path->find('\0') != std::string::npos ||
        path->size() > 16384 || !tried.insert(*path).second) continue;
    fd = attempt("root" + *path, "process-root");
    if (fd >= 0) return fd;
  }
  const std::string reason = mismatch ? "file-identity-mismatch" : denied ? "read-denied" : "file-unavailable";
  evidence = failure(reason, mismatch ? "no readable file descriptor matches the mapping device/inode" :
    std::error_code(lastError, std::generic_category()).message());
  evidence["identityVerified"] = false;
  return -1;
}

struct Bias {
  bool negative;
  std::uint64_t magnitude;
  std::string key() const { return (negative ? "-" : "") + hex(magnitude); }
  std::optional<std::uint64_t> apply(std::uint64_t address) const {
    if (!negative) return add(address, magnitude);
    if (address < magnitude) return {};
    return address - magnitude;
  }
};
struct Segment {
  const Json* dto;
  std::uint64_t address, offset, fileSize, memorySize, pageAddress, pageOffset, pageFileEnd;
};
std::vector<Segment> segments(const Json& elf, std::uint64_t page) {
  std::vector<Segment> result;
  for (const auto& dto : elf.at("programHeaders")) {
    if (dto.at("type") != "PT_LOAD") continue;
    auto address = field(dto, "virtualAddressHex"), offset = field(dto, "offsetHex");
    auto fileSize = field(dto, "fileSizeHex"), memorySize = field(dto, "memorySizeHex");
    if (address % page != offset % page) throw std::invalid_argument("PT_LOAD is not congruent to the system page size");
    const auto fileEnd = add(offset, fileSize);
    const auto pageEnd = fileEnd ? roundUp(*fileEnd, page) : std::nullopt;
    if (!pageEnd) throw std::invalid_argument("PT_LOAD page-rounded file range overflows");
    result.push_back({&dto, address, offset, fileSize, memorySize,
                      address - address % page, offset - offset % page, *pageEnd});
  }
  return result;
}

bool consistent(const Bias& bias, const std::vector<Segment>& segments,
                const std::vector<const Region*>& group, std::size_t& operations,
                std::size_t operationLimit, bool& truncated) {
  for (const auto& segment : segments) {
    if (segment.fileSize == 0) continue;
    const auto start = bias.apply(segment.pageAddress);
    if (!start) return false;
    const auto end = add(*start, segment.pageFileEnd - segment.pageOffset);
    if (!end) return false;
    for (const auto* region : group) {
      if (operations >= operationLimit) { truncated = true; return false; }
      ++operations;
      const auto a = std::max(*start, region->start), b = std::min(*end, region->end);
      if (a >= b) continue;
      const auto actualOffset = add(region->offset, a - region->start);
      const auto expectedOffset = add(segment.pageOffset, a - *start);
      if (!actualOffset || !expectedOffset || actualOffset != expectedOffset) return false;
    }
  }
  return true;
}

void findInstances(Json& module, const std::vector<Region>& all,
                   const std::vector<const Region*>& group, std::uint64_t page,
                   const ModuleInspectionLimits& limits, std::size_t& emittedRanges,
                   std::size_t& operations, bool& truncated) {
  auto loads = segments(module.at("elf"), page);
  std::map<std::string, Bias> candidates;
  for (const auto* region : group) {
    for (const auto& segment : loads) {
      if (operations >= limits.maxMatchOperations) { truncated = true; break; }
      ++operations;
      if (segment.fileSize == 0) continue;
      const auto regionFileEnd = add(region->offset, region->end - region->start);
      if (!regionFileEnd) continue;
      const auto offset = std::max(region->offset, segment.pageOffset);
      if (offset >= std::min(*regionFileEnd, segment.pageFileEnd)) continue;
      auto actual = add(region->start, offset - region->offset);
      auto original = add(segment.pageAddress, offset - segment.pageOffset);
      if (!actual || !original) continue;
      Bias bias{*actual < *original, *actual < *original ? *original - *actual : *actual - *original};
      if (candidates.contains(bias.key())) continue;
      if (!consistent(bias, loads, group, operations, limits.maxMatchOperations, truncated)) continue;
      if (candidates.size() >= limits.maxInstancesPerModule && !candidates.contains(bias.key())) {
        truncated = true;
        continue;
      }
      candidates.emplace(bias.key(), bias);
    }
    if (operations >= limits.maxMatchOperations) break;
  }
  std::set<std::uint64_t> assigned;
  for (const auto& [key, bias] : candidates) {
    Json instance = {{"loadBiasHex", key}, {"evidence", "PT_LOAD-file-offset"},
      {"coverage", "complete"}, {"segments", Json::array()}};
    bool complete = true;
    for (const auto& segment : loads) {
      const auto start = bias.apply(segment.address);
      const auto end = start ? add(*start, segment.memorySize) : std::nullopt;
      const auto fileEnd = start ? add(*start, segment.fileSize) : std::nullopt;
      if (!start || !end || !fileEnd) { complete = false; continue; }
      Json part = {{"programHeaderIndex", segment.dto->at("index")},
        {"startAddressHex", hex(*start)}, {"endAddressHex", hex(*end)},
        {"fileEndAddressHex", hex(*fileEnd)}, {"flags", segment.dto->at("flags")},
        {"mappedRanges", Json::array()}};
      auto region = std::lower_bound(all.begin(), all.end(), *start,
        [](const Region& item, std::uint64_t address) { return item.end <= address; });
      auto coveredThrough = *start;
      for (; region != all.end() && region->start < *end; ++region) {
        auto a = std::max(*start, region->start), b = std::min(*end, region->end);
        const bool sameFile = region->key == group.front()->key;
        const bool anonymous = region->inode == 0 && region->dto->value("kind", "") == "anonymous";
        if (!sameFile && !anonymous) continue;
        if (anonymous) a = std::max(a, *fileEnd); // Anonymous data only supports the BSS tail.
        if (a >= b) continue;
        if (emittedRanges >= limits.maxMappedRanges) { truncated = true; complete = false; break; }
        ++emittedRanges;
        part["mappedRanges"].push_back({{"startAddressHex", hex(a)}, {"endAddressHex", hex(b)},
          {"permissions", region->dto->at("permissions")}, {"backing", sameFile ? "file" : "anonymous"},
          {"regionStartAddressHex", hex(region->start)}});
        if (sameFile) assigned.insert(region->start);
        if (a > coveredThrough) complete = false;
        coveredThrough = std::max(coveredThrough, b);
      }
      if (coveredThrough != *end) complete = false;
      instance["segments"].push_back(std::move(part));
    }
    instance["coverage"] = complete ? "complete" : "partial";
    module["instances"].push_back(std::move(instance));
  }
  for (const auto* region : group)
    if (!assigned.contains(region->start)) module["unassignedRegionStarts"].push_back(hex(region->start));
}

struct RuntimeRange {
  std::uint64_t start, end;
  Json evidence;
};
struct RuntimeInstance {
  Bias bias;
  std::vector<RuntimeRange> ranges;
};
std::vector<RuntimeInstance> runtimeInstances(const Json& module) {
  std::vector<RuntimeInstance> result;
  for (const auto& item : module.at("instances")) {
    auto biasText = item.at("loadBiasHex").get<std::string>();
    const bool negative = biasText.starts_with('-');
    if (negative) biasText.erase(0, 1);
    auto magnitude = number(biasText);
    if (!magnitude) throw std::invalid_argument("invalid proven load bias");
    RuntimeInstance instance{{negative, *magnitude}, {}};
    for (const auto& segment : item.at("segments"))
      for (const auto& range : segment.at("mappedRanges"))
        instance.ranges.push_back({field(range, "startAddressHex"), field(range, "endAddressHex"), range});
    std::sort(instance.ranges.begin(), instance.ranges.end(), [](const auto& a, const auto& b) {
      return a.start < b.start || (a.start == b.start && a.end < b.end);
    });
    result.push_back(std::move(instance));
  }
  return result;
}

struct RelocationBudget {
  const ModuleSymbolInspectionLimits& limits;
  std::size_t locations = 0, ranges = 0, operations = 0;
  bool truncated = false;
};

// Empty ranges are point evidence only. A zero-size symbol is not expanded to
// the next symbol, and its file size never grants ownership of adjacent bytes.
Json relocate(std::uint64_t address, std::uint64_t size,
              const std::vector<RuntimeInstance>& instances, RelocationBudget& budget) {
  Json locations = Json::array();
  for (const auto& instance : instances) {
    if (budget.locations >= budget.limits.maxRuntimeLocations) { budget.truncated = true; break; }
    ++budget.locations;
    const auto start = instance.bias.apply(address);
    const auto end = start ? add(*start, size) : std::nullopt;
    Json location = {{"loadBiasHex", instance.bias.key()}, {"status", "overflow"},
      {"addressHex", start ? Json(hex(*start)) : Json(nullptr)},
      {"endAddressHex", end ? Json(hex(*end)) : Json(nullptr)}, {"mappedRanges", Json::array()}};
    if (!start || !end) { locations.push_back(std::move(location)); continue; }
    auto coveredThrough = *start;
    bool gap = false, pointMapped = false;
    // Ranges are ordered by start; overlapping PT_LOAD segments are
    // clipped to their union, so an overlay never repeats the same bytes.
    for (const auto& range : instance.ranges) {
      if (range.start > *end || (size != 0 && range.start == *end)) break;
      if (budget.operations >= budget.limits.maxMatchOperations) { budget.truncated = true; break; }
      ++budget.operations;
      if (size == 0) {
        if (range.start <= *start && *start < range.end) { pointMapped = true; break; }
        continue;
      }
      auto a = std::max({*start, range.start, coveredThrough}), b = std::min(*end, range.end);
      if (a >= b) continue;
      if (budget.ranges >= budget.limits.maxMappedRanges) { budget.truncated = true; break; }
      ++budget.ranges;
      auto clipped = range.evidence;
      clipped["startAddressHex"] = hex(a); clipped["endAddressHex"] = hex(b);
      location["mappedRanges"].push_back(std::move(clipped));
      if (a > coveredThrough) gap = true;
      coveredThrough = b;
    }
    location["status"] = budget.truncated ? "unknown" : size == 0 ? (pointMapped ? "mapped" : "unmapped") :
      location["mappedRanges"].empty() ? "unmapped" :
      (!gap && coveredThrough == *end) ? "mapped" : "partial";
    locations.push_back(std::move(location));
    if (budget.truncated) break;
  }
  return locations;
}

void relocateMetadata(Json& report, const ModuleSymbolInspectionLimits& limits, bool& truncated,
                      std::size_t usedRanges, std::size_t usedOperations) {
  const auto instances = runtimeInstances(report.at("module"));
  RelocationBudget budget{limits, 0, usedRanges, usedOperations};
  std::map<std::size_t, const Json*> sections;
  for (auto& section : report["sections"]) {
    sections[section.at("index").get<std::size_t>()] = &section;
    section["runtimeLocations"] = Json::array();
    if (!section.at("flags").at("alloc").get<bool>()) section["runtimeReason"] = "non-allocated-section";
    else if (section.at("flags").at("tls").get<bool>()) section["runtimeReason"] = "tls-requires-thread-address";
    else if (budget.truncated) section["runtimeReason"] = "inspection-limit";
    else {
      section["runtimeLocations"] = relocate(field(section, "addressHex"), field(section, "sizeHex"), instances, budget);
      if (budget.truncated) section["runtimeReason"] = "inspection-limit";
      else if (instances.empty()) section["runtimeReason"] = "no-proven-load-instance";
    }
  }
  for (auto& symbol : report["symbols"]) {
    symbol["runtimeLocations"] = Json::array();
    const auto definition = symbol.at("definition").get<std::string>();
    const auto valueKind = symbol.at("valueKind").get<std::string>();
    if (definition == "undefined") symbol["runtimeMeaning"] = "undefined";
    else if (definition == "absolute") symbol["runtimeMeaning"] = "absolute-value";
    else if (definition == "common") symbol["runtimeMeaning"] = "common";
    else if (valueKind == "tls-offset") symbol["runtimeMeaning"] = "tls-offset";
    else if (definition != "section" || valueKind != "virtual-address")
      symbol["runtimeMeaning"] = "unsupported-definition";
    else {
      const auto index = symbol.at("sectionIndex");
      const auto section = index.is_number_unsigned() || index.is_number_integer() ?
        sections.find(index.get<std::size_t>()) : sections.end();
      if (section == sections.end()) {
        symbol["runtimeMeaning"] = "non-runtime-section";
        symbol["runtimeReason"] = "section-metadata-unavailable";
        continue;
      }
      const auto& dto = *section->second;
      if (!dto.at("flags").at("alloc").get<bool>()) symbol["runtimeMeaning"] = "non-runtime-section";
      else if (dto.at("flags").at("tls").get<bool>()) {
        // Non-STT_TLS symbols can identify the TLS initialization template;
        // their virtual-address value must not become a per-thread offset.
        symbol["runtimeMeaning"] = "non-runtime-section";
        symbol["runtimeReason"] = "tls-requires-thread-address";
      }
      else {
        symbol["runtimeMeaning"] = symbol.at("type") == "STT_GNU_IFUNC" ? "ifunc-resolver" : "address";
        if (budget.truncated) { symbol["runtimeReason"] = "inspection-limit"; continue; }
        const auto address = field(symbol, "valueHex"), size = field(symbol, "sizeHex");
        const auto sectionStart = field(dto, "addressHex"), sectionSize = field(dto, "sizeHex");
        const auto sectionEnd = add(sectionStart, sectionSize), symbolEnd = add(address, size);
        // Out-of-section symbols can be linker/malformed metadata. They never
        // authorize an overlay over a different mapped object or section.
        if (!sectionEnd || !symbolEnd || address < sectionStart || address > *sectionEnd || *symbolEnd > *sectionEnd) {
          symbol["runtimeReason"] = "symbol-outside-section";
          continue;
        }
        symbol["runtimeLocations"] = relocate(address, size, instances, budget);
        if (budget.truncated) symbol["runtimeReason"] = "inspection-limit";
        else if (instances.empty()) symbol["runtimeReason"] = "no-proven-load-instance";
      }
    }
  }
  truncated = truncated || budget.truncated;
}
#endif
}  // namespace

nlohmann::json inspectRuntimeModules(int pid, const Json& memoryMap,
                                     const ModuleInspectionLimits& requested) {
  if (pid <= 0) return unavailable("invalid-process", "positive owned inferior PID required");
#ifndef __linux__
  (void)memoryMap; (void)requested;
  return unavailable("unsupported-platform", "runtime module inspection requires Linux procfs");
#else
  const ModuleInspectionLimits hard;
  const ModuleInspectionLimits limits{std::min(requested.maxModules, hard.maxModules),
    std::min(requested.maxMetadataBytes, hard.maxMetadataBytes),
    std::min(requested.maxRegions, hard.maxRegions),
    std::min(requested.maxSegmentsPerModule, hard.maxSegmentsPerModule),
    std::min(requested.maxInstancesPerModule, hard.maxInstancesPerModule),
    std::min(requested.maxMappedRanges, hard.maxMappedRanges),
    std::min(requested.maxMatchOperations, hard.maxMatchOperations)};
  try {
    if (!memoryMap.value("available", false)) return unavailable("maps-unavailable", "a current maps snapshot is required");
    const auto mapCoverage = memoryMap.value("coverage", "none");
    if (mapCoverage != "complete" && mapCoverage != "truncated")
      return unavailable("maps-unavailable", "maps coverage must be complete or explicitly truncated");
    bool truncated = mapCoverage == "truncated", partial = false;
    auto all = regions(memoryMap, limits.maxRegions, truncated);
    Fd proc(::open(("/proc/" + std::to_string(pid)).c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (proc.value < 0) return unavailable(errno == EACCES || errno == EPERM ? "read-denied" : "process-unavailable",
      "cannot pin the inferior proc directory");
    const auto before = processStat(proc.value);
    if (!before.value("available", false) || before.at("pid") != std::to_string(pid))
      return unavailable("process-unavailable", "cannot verify inferior process identity");
    const long systemPage = ::sysconf(_SC_PAGESIZE);
    if (systemPage <= 0) return unavailable("page-size-unavailable", "cannot obtain system page size");
    const auto page = static_cast<std::uint64_t>(systemPage);
    Json result = {{"available", true}, {"source", "linux-proc-maps-elf"}, {"coverage", "complete"},
      {"identityVerified", true}, {"pid", std::to_string(pid)}, {"pageSizeBytes", std::to_string(page)},
      {"modules", Json::array()}};
    std::map<std::string, std::vector<const Region*>> groups;
    for (const auto& region : all)
      if (region.inode != 0 && region.dto->value("kind", "") == "file") groups[region.key].push_back(&region);
    std::size_t metadataRead = 0, emittedRanges = 0, operations = 0;
    for (const auto& [key, group] : groups) {
      if (result["modules"].size() >= limits.maxModules) { truncated = true; break; }
      const auto& first = *group.front()->dto;
      Json module = {{"id", "module:" + key}, {"device", first.at("device")},
        {"inodeDecimal", first.at("inodeDecimal")}, {"path", first.at("path")},
        {"contentIdentity", "file-metadata-only"},
        {"mappedRegions", Json::array()}, {"instances", Json::array()}, {"unassignedRegionStarts", Json::array()}};
      if (first.contains("pathBytesHex")) module["pathBytesHex"] = first["pathBytesHex"];
      for (const auto* region : group) module["mappedRegions"].push_back(*region->dto);
      struct stat version{};
      Fd file(openMappedFile(proc.value, group, module["file"], version));
      if (file.value < 0) {
        module["elf"] = failure("file-unavailable", "mapped file identity could not be verified");
        partial = true;
      } else {
        ElfInspectionLimits elfLimits;
        elfLimits.maxProgramHeaders = limits.maxSegmentsPerModule;
        elfLimits.maxMetadataBytes = limits.maxMetadataBytes - metadataRead;
        std::size_t used = 0;
        module["elf"] = inspectElfFd(file.value, elfLimits, &used);
        metadataRead += used;
        struct stat after{};
        if (::fstat(file.value, &after) != 0 || !sameVersion(version, after))
          module["elf"] = failure("file-changed", "mapped file metadata changed during inspection");
        if (module["elf"].value("available", false)) {
          if ((module["elf"]["elfType"] == "ET_DYN" || module["elf"]["elfType"] == "ET_EXEC") &&
               module["elf"]["architecture"] == "x86_64") {
            try { findInstances(module, all, group, page, limits, emittedRanges, operations, truncated); }
            catch (const std::invalid_argument& error) {
              module["instanceReason"] = error.what();
              partial = true;
            }
          } else {
            module["instanceReason"] = "runtime relocation supports ELF64 x86_64 ET_EXEC/ET_DYN";
            partial = true;
          }
        } else {
          partial = true;
          if (module["elf"].value("reason", "") == "metadata-limit" ||
              module["elf"].value("reason", "") == "program-header-limit") truncated = true;
        }
      }
      if (module["instances"].empty() && module["unassignedRegionStarts"].empty())
        for (const auto* region : group) module["unassignedRegionStarts"].push_back(hex(region->start));
      if (!module["unassignedRegionStarts"].empty()) partial = true;
      for (const auto& instance : module["instances"])
        if (instance.at("coverage") != "complete") partial = true;
      result["modules"].push_back(std::move(module));
    }
    const auto after = processStat(proc.value);
    if (!after.value("available", false) || before.at("pid") != after.at("pid") ||
        before.at("startTimeTicks") != after.at("startTimeTicks"))
      return unavailable("process-changed", "process identity changed during module inspection");
    result["coverage"] = truncated ? "truncated" : partial ? "partial" : "complete";
    if (truncated) result["reason"] = "inspection-limit-or-truncated-maps";
    return result;
  } catch (const Json::exception&) {
    return unavailable("invalid-maps", "malformed memory-map snapshot");
  } catch (const std::invalid_argument& error) {
    return unavailable("invalid-maps", error.what());
  }
#endif
}

nlohmann::json inspectRuntimeModuleSymbols(int pid, const Json& memoryMap,
    std::string_view moduleId, const ModuleSymbolInspectionLimits& requested) {
  const auto fail = [&](std::string reason, std::string detail) {
    return symbolsUnavailable(moduleId, std::move(reason), std::move(detail));
  };
  if (pid <= 0) return fail("invalid-process", "positive owned inferior PID required");
#ifndef __linux__
  (void)memoryMap; (void)requested;
  return fail("unsupported-platform", "runtime module symbols require Linux procfs");
#else
  const ModuleSymbolInspectionLimits hard;
  const ModuleSymbolInspectionLimits limits{
    std::min(requested.maxMetadataBytes, hard.maxMetadataBytes),
    std::min(requested.maxSections, hard.maxSections),
    std::min(requested.maxSymbols, hard.maxSymbols),
    std::min(requested.maxRuntimeLocations, hard.maxRuntimeLocations),
    std::min(requested.maxMappedRanges, hard.maxMappedRanges),
    std::min(requested.maxMatchOperations, hard.maxMatchOperations)};
  try {
    if (!memoryMap.value("available", false) || memoryMap.value("coverage", "none") != "complete")
      return fail("maps-unavailable", "complete current maps are required for symbol relocation");
    bool truncated = false;
    auto all = regions(memoryMap, 8192, truncated);
    if (truncated) return fail("maps-limit", "maps exceed the module symbol region limit");
    Fd proc(::open(("/proc/" + std::to_string(pid)).c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC));
    if (proc.value < 0) return fail("process-unavailable", "cannot pin the inferior proc directory");
    const auto before = processStat(proc.value);
    if (!before.value("available", false) || before.at("pid") != std::to_string(pid))
      return fail("process-unavailable", "cannot verify inferior process identity");
    const auto mapsBefore = processMaps(proc.value);
    if (!mapsBefore.value("available", false) || mapsBefore.value("coverage", "none") != "complete")
      return fail("maps-unavailable", "cannot verify complete current pinned process maps");
    if (mapsBefore.at("regions") != memoryMap.at("regions"))
      return fail("maps-changed", "provided memory map no longer matches the stopped process");
    std::vector<const Region*> group;
    for (const auto& region : all)
      if (region.inode != 0 && region.dto->value("kind", "") == "file" && "module:" + region.key == moduleId)
        group.push_back(&region);
    if (group.empty()) return fail("module-not-mapped", "module ID is not present in the current maps");
    const auto& first = *group.front()->dto;
    Json module = {{"id", moduleId}, {"device", first.at("device")}, {"inodeDecimal", first.at("inodeDecimal")},
      {"path", first.at("path")}, {"contentIdentity", "file-metadata-only"},
      {"mappedRegions", Json::array()}, {"instances", Json::array()}, {"unassignedRegionStarts", Json::array()}};
    if (first.contains("pathBytesHex")) module["pathBytesHex"] = first.at("pathBytesHex");
    for (const auto* region : group) module["mappedRegions"].push_back(*region->dto);
    struct stat version{};
    Fd file(openMappedFile(proc.value, group, module["file"], version));
    if (file.value < 0) return fail(module["file"].value("reason", "file-unavailable"),
      "mapped file descriptor identity could not be verified");
    ElfInspectionLimits elfLimits;
    elfLimits.maxProgramHeaders = 256;
    elfLimits.maxMetadataBytes = limits.maxMetadataBytes;
    std::size_t elfBytes = 0;
    module["elf"] = inspectElfFd(file.value, elfLimits, &elfBytes);
    if (!module["elf"].value("available", false))
      return fail(module["elf"].value("reason", "elf-unavailable"), module["elf"].value("detail", "ELF metadata unavailable"));
    if ((module["elf"].at("elfType") != "ET_EXEC" && module["elf"].at("elfType") != "ET_DYN") ||
        module["elf"].at("architecture") != "x86_64")
      return fail("unsupported-runtime-elf", "runtime symbol relocation requires ELF64 x86_64 ET_EXEC/ET_DYN");
    const auto page = ::sysconf(_SC_PAGESIZE);
    if (page <= 0) return fail("page-size-unavailable", "cannot obtain system page size");
    ModuleInspectionLimits moduleLimits;
    moduleLimits.maxMappedRanges = limits.maxMappedRanges;
    moduleLimits.maxMatchOperations = limits.maxMatchOperations;
    std::size_t ranges = 0, operations = 0;
    findInstances(module, all, group, static_cast<std::uint64_t>(page), moduleLimits, ranges, operations, truncated);
    ElfSymbolInspectionLimits symbolLimits;
    symbolLimits.maxMetadataBytes = limits.maxMetadataBytes - elfBytes;
    symbolLimits.maxSectionHeaders = limits.maxSections;
    symbolLimits.maxSymbols = limits.maxSymbols;
    auto metadata = inspectElfSymbolsFd(file.value, symbolLimits);
    if (!metadata.value("available", false))
      return fail(metadata.value("reason", "symbols-unavailable"), metadata.value("detail", "ELF section/symbol metadata unavailable"));
    Json result = {{"available", true}, {"source", "linux-proc-maps-elf-symbols"}, {"coverage", "complete"},
      {"identityVerified", true}, {"pid", std::to_string(pid)}, {"moduleId", moduleId},
      {"contentIdentity", "file-metadata-only"}, {"module", std::move(module)},
      {"sections", std::move(metadata["sections"])}, {"symbols", std::move(metadata["symbols"])}};
    metadata.erase("sections"); metadata.erase("symbols");
    truncated = truncated || metadata.value("coverage", "none") == "truncated";
    result["elfMetadata"] = std::move(metadata);
    relocateMetadata(result, limits, truncated, ranges, operations);
    struct stat afterFile{};
    if (::fstat(file.value, &afterFile) != 0 || !sameVersion(version, afterFile))
      return fail("file-changed", "mapped file metadata changed during symbol inspection");
    const auto after = processStat(proc.value);
    if (!after.value("available", false) || before.at("pid") != after.at("pid") ||
        before.at("startTimeTicks") != after.at("startTimeTicks"))
      return fail("process-changed", "process identity changed during symbol inspection");
    const auto mapsAfter = processMaps(proc.value);
    if (!mapsAfter.value("available", false) || mapsAfter.value("coverage", "none") != "complete" ||
        mapsAfter.at("regions") != mapsBefore.at("regions"))
      return fail("maps-changed", "process maps changed during symbol inspection");
    bool partial = result["module"]["instances"].empty() || !result["module"]["unassignedRegionStarts"].empty();
    for (const auto& instance : result["module"]["instances"])
      partial = partial || instance.at("coverage") != "complete";
    result["coverage"] = truncated ? "truncated" : partial ? "partial" : "complete";
    if (truncated) result["reason"] = "inspection-limit";
    return result;
  } catch (const Json::exception&) {
    return fail("invalid-metadata", "malformed memory map or ELF metadata");
  } catch (const std::invalid_argument& error) {
    return fail("invalid-metadata", error.what());
  }
#endif
}

}  // namespace phantom
