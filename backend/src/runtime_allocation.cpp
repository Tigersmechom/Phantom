#include "phantom/runtime_allocation.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <limits>
#include <vector>

namespace phantom {
namespace {
using Json = nlohmann::json;
constexpr std::size_t maximumRegions = 8192;
constexpr std::size_t maximumAllocation = 1024 * 1024;
constexpr std::size_t maximumPathBytes = 16 * 1024 * 1024;

struct Invalid {
  const char* reason;
};
[[noreturn]] void reject(const char* reason) { throw Invalid{reason}; }

const std::string& text(const Json& value) {
  if (!value.is_string()) reject("memory map metadata must use strings");
  return value.get_ref<const std::string&>();
}

std::uint64_t number(std::string_view value, int base) {
  if (value.empty() || value.size() > (base == 16 ? 16u : 20u) ||
      value.find_first_not_of(base == 16 ? "0123456789abcdefABCDEF" : "0123456789") != std::string_view::npos)
    reject("memory map numeric metadata is malformed");
  std::uint64_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, base);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
    reject("memory map numeric metadata overflows");
  return parsed;
}

std::uint64_t hexadecimal(std::string_view value) {
  if (!value.starts_with("0x") || value.size() < 3 || value.size() > 18 ||
      (value.size() > 3 && value[2] == '0') ||
      value.find_first_not_of("0123456789abcdef", 2) != std::string_view::npos)
    reject("memory map hexadecimal metadata is not canonical");
  return number(value.substr(2), 16);
}

bool validUtf8(std::string_view bytes) {
  for (std::size_t i = 0; i < bytes.size();) {
    const auto first = static_cast<unsigned char>(bytes[i++]);
    if (first < 0x80) continue;
    unsigned remaining;
    std::uint32_t scalar;
    std::uint32_t minimum;
    if (first >= 0xc2 && first <= 0xdf) {
      remaining = 1; scalar = first & 0x1f; minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      remaining = 2; scalar = first & 0x0f; minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      remaining = 3; scalar = first & 0x07; minimum = 0x10000;
    } else return false;
    if (remaining > bytes.size() - i) return false;
    while (remaining-- != 0) {
      const auto next = static_cast<unsigned char>(bytes[i++]);
      if ((next & 0xc0) != 0x80) return false;
      scalar = (scalar << 6) | (next & 0x3f);
    }
    if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) return false;
  }
  return true;
}

std::string_view kind(std::string_view path, std::uint64_t inode) {
  if (path == "[heap]") return "heap";
  if (path == "[stack]" || (path.starts_with("[stack:") && path.ends_with(']'))) return "stack";
  if (path.empty()) return inode == 0 ? "anonymous" : "file";
  if ((path.starts_with("[anon:") || path.starts_with("[anon_shmem:")) && path.ends_with(']'))
    return "anonymous";
  if (path.starts_with('[') && path.ends_with(']')) return "special";
  return "file";
}

struct Region {
  std::uint64_t start;
  std::uint64_t end;
  const Json* source;
  bool mergeable;
};

std::vector<Region> validate(const Json& map) {
  if (!map.is_object() || map.size() != 4 || !map.contains("available") ||
      !map.at("available").is_boolean() || map.at("available") != true ||
      map.value("source", Json()) != "linux-proc-maps" || map.value("coverage", Json()) != "complete" ||
      !map.contains("regions") || !map.at("regions").is_array())
    reject("a complete Linux memory map is required");
  const auto& items = map.at("regions");
  if (items.size() > maximumRegions) reject("memory map region limit exceeded");
  std::vector<Region> result;
  result.reserve(items.size());
  std::size_t pathBudget = maximumPathBytes;
  for (const auto& region : items) {
    if (!region.is_object() || region.size() != (region.contains("pathBytesHex") ? 9u : 8u))
      reject("memory map region schema is invalid");
    for (const auto* key : {"startAddressHex", "endAddressHex", "permissions", "offsetHex", "device",
                            "inodeDecimal", "path", "kind"})
      if (!region.contains(key)) reject("memory map region metadata is missing");
    const auto start = hexadecimal(text(region.at("startAddressHex")));
    const auto end = hexadecimal(text(region.at("endAddressHex")));
    if (start >= end || (!result.empty() && start < result.back().end))
      reject("memory map regions are empty, overlapping or unordered");
    const auto& permissions = text(region.at("permissions"));
    if (permissions.size() != 4 || (permissions[0] != 'r' && permissions[0] != '-') ||
        (permissions[1] != 'w' && permissions[1] != '-') ||
        (permissions[2] != 'x' && permissions[2] != '-') ||
        (permissions[3] != 'p' && permissions[3] != 's'))
      reject("memory map permissions are invalid");
    const auto offset = hexadecimal(text(region.at("offsetHex")));
    const auto& device = text(region.at("device"));
    const auto colon = device.find(':');
    if (colon == std::string::npos) reject("memory map device metadata is invalid");
    (void)number(std::string_view(device).substr(0, colon), 16);
    (void)number(std::string_view(device).substr(colon + 1), 16);
    const auto& inodeText = text(region.at("inodeDecimal"));
    if (inodeText.size() > 1 && inodeText[0] == '0') reject("memory map inode metadata is not canonical");
    const auto inode = number(inodeText, 10);

    std::string decodedPath;
    std::string_view path;
    if (region.contains("pathBytesHex")) {
      if (!region.at("path").is_null()) reject("memory map path representations conflict");
      const auto& raw = text(region.at("pathBytesHex"));
      if (raw.empty() || raw.size() % 2 != 0 || raw.size() / 2 > pathBudget ||
          raw.find_first_not_of("0123456789abcdef") != std::string::npos)
        reject("memory map path bytes are invalid or exceed limit");
      const auto nibble = [](char ch) { return ch <= '9' ? ch - '0' : ch - 'a' + 10; };
      decodedPath.reserve(raw.size() / 2);
      for (std::size_t i = 0; i < raw.size(); i += 2)
        decodedPath.push_back(static_cast<char>((nibble(raw[i]) << 4) | nibble(raw[i + 1])));
      path = decodedPath;
      if (validUtf8(path)) reject("memory map byte path is not the canonical parser representation");
    } else if (!region.at("path").is_null()) {
      path = text(region.at("path"));
      if (path.empty() || path.size() > pathBudget || !validUtf8(path))
        reject("memory map path text is invalid or exceeds limit");
    }
    if (!path.empty() && (path.front() == ' ' || path.front() == '\t' ||
        path.find('\0') != std::string_view::npos || path.find('\n') != std::string_view::npos))
      reject("memory map path is not an exact kernel record");
    pathBudget -= path.size();
    if (text(region.at("kind")) != kind(path, inode)) reject("memory map kind disagrees with its metadata");
    const bool mergeable = permissions[3] == 'p' && path.empty() && region.at("path").is_null() &&
        !region.contains("pathBytesHex") && inode == 0 && offset == 0 && device == "00:00";
    result.push_back({start, end, &region, mergeable});
  }
  return result;
}

struct Segment {
  std::uint64_t start;
  std::uint64_t end;
  Json metadata;
  bool mergeable;
};

std::vector<Segment> outside(const std::vector<Region>& regions,
                             std::uint64_t start, std::uint64_t end) {
  std::vector<Segment> result;
  result.reserve(regions.size() + 1);
  const auto append = [&](const Region& region, std::uint64_t low, std::uint64_t high) {
    if (low >= high) return;
    auto metadata = *region.source;
    metadata.erase("startAddressHex");
    metadata.erase("endAddressHex");
    if (!result.empty() && region.mergeable && result.back().mergeable &&
        result.back().end == low && result.back().metadata == metadata) {
      result.back().end = high;
    } else result.push_back({low, high, std::move(metadata), region.mergeable});
  };
  for (const auto& region : regions) {
    if (region.end <= start || region.start >= end) append(region, region.start, region.end);
    else {
      append(region, region.start, std::min(start, region.end));
      append(region, std::max(end, region.start), region.end);
    }
  }
  return result;
}

struct Interval {
  std::uint64_t start;
  std::uint64_t end;
};

Interval interval(std::string_view addressHex, std::size_t byteCount) {
  const auto start = hexadecimal(addressHex);
  if (start == 0 || byteCount == 0 || byteCount > maximumAllocation ||
      byteCount > std::numeric_limits<std::uint64_t>::max() - start)
    reject("runtime allocation interval is invalid or exceeds limit");
  return {start, start + byteCount};
}

std::string privatePermissions(std::string_view permissions) {
  if (permissions != "r--" && permissions != "rw-" && permissions != "r-x")
    reject("runtime memory permissions must be r--, rw- or r-x");
  return std::string(permissions) + 'p';
}

void requireCovered(const std::vector<Region>& regions, Interval target,
                    std::string_view permissions) {
  auto covered = target.start;
  for (const auto& region : regions) {
    if (region.end <= target.start || region.start >= target.end) continue;
    if (region.start > covered || !region.mergeable || region.source->at("permissions") != permissions)
      reject("runtime allocation lacks complete unnamed private anonymous coverage with the required permissions");
    covered = std::min(region.end, target.end);
  }
  if (covered != target.end) reject("runtime allocation interval has missing mapped bytes");
}

void requireOutsideUnchanged(const std::vector<Region>& before,
                             const std::vector<Region>& after, Interval target) {
  const auto normalizedBefore = outside(before, target.start, target.end);
  const auto normalizedAfter = outside(after, target.start, target.end);
  if (normalizedBefore.size() != normalizedAfter.size())
    reject("memory mappings outside the runtime allocation changed");
  for (std::size_t i = 0; i < normalizedBefore.size(); ++i) {
    const auto& a = normalizedBefore[i];
    const auto& b = normalizedAfter[i];
    if (a.start != b.start || a.end != b.end || a.metadata != b.metadata)
      reject("memory coverage or metadata outside the runtime allocation changed");
  }
}
}  // namespace

bool verifyRuntimeAllocationDelta(const Json& before, const Json& after,
                                  std::string_view addressHex, std::size_t byteCount,
                                  bool released, std::string& detail, std::string_view permissions) {
  detail.clear();
  try {
    const auto target = interval(addressHex, byteCount);
    const auto requiredPermissions = privatePermissions(permissions);
    if (!released && permissions != "rw-") reject("runtime allocation must initially be RW");
    const auto beforeRegions = validate(before);
    const auto afterRegions = validate(after);
    const auto& occupied = released ? beforeRegions : afterRegions;
    const auto& vacant = released ? afterRegions : beforeRegions;
    for (const auto& region : vacant)
      if (region.start < target.end && target.start < region.end)
        reject("runtime allocation interval is not a complete hole in the opposite map");
    requireCovered(occupied, target, requiredPermissions);
    requireOutsideUnchanged(beforeRegions, afterRegions, target);
    return true;
  } catch (const Invalid& error) {
    detail = error.reason;
  } catch (...) {
    detail = "runtime allocation map proof could not be validated";
  }
  return false;
}

bool verifyRuntimeProtectionDelta(const Json& before, const Json& after,
                                  std::string_view addressHex, std::size_t byteCount,
                                  std::string_view expectedPermissions,
                                  std::string_view replacementPermissions,
                                  std::string& detail) {
  detail.clear();
  try {
    const auto target = interval(addressHex, byteCount);
    const auto expected = privatePermissions(expectedPermissions);
    const auto replacement = privatePermissions(replacementPermissions);
    const auto beforeRegions = validate(before);
    const auto afterRegions = validate(after);
    requireCovered(beforeRegions, target, expected);
    requireCovered(afterRegions, target, replacement);
    requireOutsideUnchanged(beforeRegions, afterRegions, target);
    return true;
  } catch (const Invalid& error) {
    detail = error.reason;
  } catch (...) {
    detail = "runtime protection map proof could not be validated";
  }
  return false;
}

}  // namespace phantom
