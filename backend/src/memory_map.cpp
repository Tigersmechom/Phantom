#include "phantom/memory_map.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {

MemoryMapLimits boundedLimits(const MemoryMapLimits& limits) {
  return {std::min(limits.maxBytes, std::size_t{16 * 1024 * 1024}),
          std::min(limits.maxRegions, std::size_t{65536})};
}

nlohmann::json unavailable(std::string reason, std::string detail) {
  return {{"available", false}, {"source", "linux-proc-maps"},
          {"coverage", "none"}, {"regions", nlohmann::json::array()},
          {"reason", std::move(reason)}, {"detail", std::move(detail)}};
}

bool horizontalSpace(char ch) { return ch == ' ' || ch == '\t'; }

std::string_view token(std::string_view line, std::size_t& cursor) {
  while (cursor < line.size() && horizontalSpace(line[cursor])) ++cursor;
  const auto start = cursor;
  while (cursor < line.size() && !horizontalSpace(line[cursor])) ++cursor;
  return line.substr(start, cursor - start);
}

std::optional<std::uint64_t> number(std::string_view text, int base) {
  if (text.empty()) return std::nullopt;
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return std::nullopt;
  return value;
}

std::string hex(std::uint64_t value) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  return "0x" + std::string(buffer.data(), result.ptr);
}

std::string bytesHex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) {
    result += digits[byte >> 4];
    result += digits[byte & 15];
  }
  return result;
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
    } else {
      return false;
    }
    if (bytes.size() - i < remaining) return false;
    while (remaining-- != 0) {
      const auto next = static_cast<unsigned char>(bytes[i++]);
      if ((next & 0xc0) != 0x80) return false;
      scalar = (scalar << 6) | (next & 0x3f);
    }
    if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) return false;
  }
  return true;
}

std::string kind(std::string_view path, std::uint64_t inode) {
  if (path == "[heap]") return "heap";
  if (path == "[stack]" || (path.starts_with("[stack:") && path.ends_with(']'))) return "stack";
  if (path.empty()) return inode == 0 ? "anonymous" : "file";
  if ((path.starts_with("[anon:") || path.starts_with("[anon_shmem:")) && path.ends_with(']')) return "anonymous";
  if (path.starts_with('[') && path.ends_with(']')) return "special";
  return "file";
}

}  // namespace

nlohmann::json parseLinuxMemoryMap(std::string_view text, const MemoryMapLimits& requested,
                                  bool inputTruncated) {
  const auto limits = boundedLimits(requested);
  bool truncated = inputTruncated || text.size() > limits.maxBytes;
  text = text.substr(0, limits.maxBytes);
  nlohmann::json regions = nlohmann::json::array();
  std::string truncationReason = truncated ? "byte-limit" : "";
  std::uint64_t previousEnd = 0;
  std::size_t cursor = 0;
  std::size_t lineNumber = 0;
  const auto malformed = [&lineNumber](const char* detail) {
    auto result = unavailable("malformed", detail);
    result["lineNumber"] = lineNumber;
    return result;
  };
  while (cursor < text.size()) {
    if (regions.size() >= limits.maxRegions) {
      truncated = true;
      truncationReason = "region-limit";
      break;
    }
    ++lineNumber;
    const auto newline = text.find('\n', cursor);
    if (newline == std::string_view::npos) {
      if (truncated) break;  // Never publish a byte-limited partial record.
      return malformed("unterminated maps record");
    }
    const auto line = text.substr(cursor, newline - cursor);
    cursor = newline + 1;
    if (line.find('\0') != std::string_view::npos) return malformed("NUL in maps record");
    std::size_t field = 0;
    const auto addresses = token(line, field);
    const auto permissions = token(line, field);
    const auto offsetText = token(line, field);
    const auto device = token(line, field);
    const auto inodeText = token(line, field);
    while (field < line.size() && horizontalSpace(line[field])) ++field;
    const auto path = line.substr(field);

    const auto dash = addresses.find('-');
    if (dash == std::string_view::npos) return malformed("invalid address range");
    const auto start = number(addresses.substr(0, dash), 16);
    const auto end = number(addresses.substr(dash + 1), 16);
    const auto offset = number(offsetText, 16);
    const auto inode = number(inodeText, 10);
    if (!start || !end || !offset || !inode) return malformed("invalid or overflowing numeric field");
    if (*end <= *start || (!regions.empty() && *start < previousEnd)) return malformed("empty, overlapping, or unordered range");
    if (permissions.size() != 4 || (permissions[0] != 'r' && permissions[0] != '-') ||
        (permissions[1] != 'w' && permissions[1] != '-') ||
        (permissions[2] != 'x' && permissions[2] != '-') ||
        (permissions[3] != 'p' && permissions[3] != 's')) return malformed("invalid permissions");
    const auto colon = device.find(':');
    if (colon == std::string_view::npos || !number(device.substr(0, colon), 16) ||
        !number(device.substr(colon + 1), 16)) return malformed("invalid device");

    nlohmann::json region = {{"startAddressHex", hex(*start)}, {"endAddressHex", hex(*end)},
      {"permissions", permissions}, {"offsetHex", hex(*offset)}, {"device", device},
      {"inodeDecimal", std::to_string(*inode)}, {"path", nullptr}, {"kind", kind(path, *inode)}};
    if (!path.empty()) {
      if (validUtf8(path)) region["path"] = path;
      else region["pathBytesHex"] = bytesHex(path);
    }
    regions.push_back(std::move(region));
    previousEnd = *end;
  }
  nlohmann::json result = {{"available", true}, {"source", "linux-proc-maps"},
    {"coverage", truncated ? "truncated" : "complete"}, {"regions", std::move(regions)}};
  if (truncated) result["reason"] = truncationReason;
  return result;
}

nlohmann::json readLinuxMemoryMap(int pid, const MemoryMapLimits& requested) {
  if (pid <= 0) return unavailable("invalid-process", "positive inferior PID required");
#ifndef __linux__
  (void)requested;
  return unavailable("unsupported-platform", "Linux procfs is required");
#else
  const auto limits = boundedLimits(requested);
  const auto failure = [](int error) {
    const char* reason = "io-error";
    if (error == EACCES || error == EPERM) reason = "read-denied";
    else if (error == ENOENT || error == ENOTDIR) reason = "process-unavailable";
    else if (error == ESRCH) reason = "process-exited";
    return unavailable(reason, std::error_code(error, std::generic_category()).message());
  };
  const auto path = "/proc/" + std::to_string(pid) + "/maps";
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return failure(errno);
  struct CloseFd {
    int fd;
    ~CloseFd() { ::close(fd); }
  } closeFd{fd};
  // One extra byte distinguishes an exactly-full file from a limited prefix.
  std::string bytes(limits.maxBytes + 1, '\0');
  std::size_t used = 0;
  int readError = 0;
  while (used < bytes.size()) {
    const auto count = ::read(fd, bytes.data() + used, bytes.size() - used);
    if (count > 0) used += static_cast<std::size_t>(count);
    else if (count == 0) break;
    else if (errno != EINTR) { readError = errno; break; }
  }
  if (readError != 0) return failure(readError);
  if (used == 0) return unavailable("process-unavailable", "process has no mapped address space (it may have exited)");
  bytes.resize(used);
  return parseLinuxMemoryMap(bytes, limits);
#endif
}

}  // namespace phantom
