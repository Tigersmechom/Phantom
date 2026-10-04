#include "phantom/process_inspection.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <sys/personality.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {

using Json = nlohmann::json;

Json unavailable(std::string reason, std::string detail) {
  return {{"available", false}, {"coverage", "none"},
          {"reason", std::move(reason)}, {"detail", std::move(detail)}};
}

Json malformed(std::string detail) { return unavailable("malformed", std::move(detail)); }

std::optional<std::uint64_t> number(std::string_view text, int base = 10) {
  if (text.empty()) return std::nullopt;
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return std::nullopt;
  return value;
}

bool space(char ch) { return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'; }

std::string_view trim(std::string_view text) {
  while (!text.empty() && space(text.front())) text.remove_prefix(1);
  while (!text.empty() && space(text.back())) text.remove_suffix(1);
  return text;
}

std::vector<std::string_view> tokens(std::string_view text) {
  std::vector<std::string_view> result;
  while (!(text = trim(text)).empty()) {
    std::size_t length = 0;
    while (length < text.size() && !space(text[length])) ++length;
    result.push_back(text.substr(0, length));
    text.remove_prefix(length);
  }
  return result;
}

std::string hex(std::uint64_t value) {
  std::array<char, 16> buffer{};
  const auto end = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16).ptr;
  return "0x" + std::string(buffer.data(), end);
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
    } else return false;
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

void byteString(Json& object, const char* field, std::string_view value) {
  object[field] = nullptr;
  if (validUtf8(value)) object[field] = value;
  else object[std::string(field) + "BytesHex"] = bytesHex(value);
}

#ifdef __linux__

struct Fd {
  int value;
  ~Fd() { if (value >= 0) ::close(value); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  explicit Fd(int descriptor) : value(descriptor) {}
};

Json failure(int error) {
  const char* reason = "io-error";
  if (error == EACCES || error == EPERM) reason = "read-denied";
  else if (error == ENOENT || error == ENOTDIR) reason = "process-unavailable";
  else if (error == ESRCH) reason = "process-exited";
  return unavailable(reason, std::error_code(error, std::generic_category()).message());
}

struct ReadResult { std::string text; Json error; };

ReadResult readFile(int directory, const char* name, std::size_t limit) {
  Fd fd(::openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd.value < 0) return {{}, failure(errno)};
  std::string bytes(limit + 1, '\0');
  std::size_t used = 0;
  while (used < bytes.size()) {
    const auto count = ::read(fd.value, bytes.data() + used, bytes.size() - used);
    if (count > 0) used += static_cast<std::size_t>(count);
    else if (count == 0) break;
    else if (errno != EINTR) return {{}, failure(errno)};
  }
  if (used > limit) return {{}, unavailable("byte-limit", "proc file exceeds capture budget")};
  if (used == 0) return {{}, unavailable("process-unavailable", "proc file is empty")};
  bytes.resize(used);
  return {std::move(bytes), nullptr};
}

Json readLink(int directory, const char* name, std::size_t limit) {
  std::string bytes(limit + 1, '\0');
  ssize_t count;
  do { count = ::readlinkat(directory, name, bytes.data(), bytes.size()); } while (count < 0 && errno == EINTR);
  if (count < 0) return failure(errno);
  if (static_cast<std::size_t>(count) > limit) {
    return unavailable("byte-limit", "proc link exceeds capture budget; partial paths are not published");
  }
  bytes.resize(static_cast<std::size_t>(count));
  Json result = {{"available", true}, {"coverage", "complete"}};
  byteString(result, "path", bytes);
  return result;
}

Json statusSnapshot(const ReadResult& read) {
  if (!read.error.is_null()) return read.error;
  Json result = {{"available", true}, {"coverage", "complete"}};
  std::size_t cursor = 0;
  while (cursor < read.text.size()) {
    const auto newline = read.text.find('\n', cursor);
    if (newline == std::string::npos) return malformed("unterminated status record");
    const auto line = std::string_view(read.text).substr(cursor, newline - cursor);
    cursor = newline + 1;
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) continue;
    const auto key = line.substr(0, colon);
    const auto value = trim(line.substr(colon + 1));
    const auto setInteger = [&](const char* field, std::uint64_t maximum, bool stringValue) {
      const auto parsed = number(value);
      if (!parsed || *parsed > maximum || result.contains(field)) return false;
      if (stringValue) result[field] = std::to_string(*parsed);
      else result[field] = *parsed;
      return true;
    };
    if (key == "State") {
      if (value.empty() || !validUtf8(value) || result.contains("state")) return malformed("invalid status state");
      result["state"] = value;
    } else if (key == "Threads") {
      if (!setInteger("threads", std::numeric_limits<int>::max(), false)) return malformed("invalid thread count");
    } else if (key == "TracerPid") {
      if (!setInteger("tracerPid", std::numeric_limits<int>::max(), true)) return malformed("invalid tracer PID");
    } else if (key == "Seccomp") {
      if (!setInteger("seccomp", std::numeric_limits<unsigned>::max(), false)) return malformed("invalid seccomp mode");
    } else if (key == "NoNewPrivs") {
      const auto parsed = number(value);
      if (!parsed || *parsed > 1 || result.contains("noNewPrivs")) return malformed("invalid no-new-privileges flag");
      result["noNewPrivs"] = *parsed == 1;
    } else if (key == "Uid" || key == "Gid") {
      const auto field = key == "Uid" ? "uid" : "gid";
      const auto ids = tokens(value);
      if (ids.size() != 4 || result.contains(field)) return malformed("invalid identity fields");
      constexpr std::array<const char*, 4> names = {"real", "effective", "saved", "filesystem"};
      result[field] = Json::object();
      for (std::size_t i = 0; i < ids.size(); ++i) {
        const auto parsed = number(ids[i]);
        if (!parsed || *parsed > std::numeric_limits<std::uint32_t>::max()) return malformed("invalid numeric identity");
        result[field][names[i]] = std::to_string(*parsed);
      }
    }
  }
  for (const auto* field : {"state", "threads", "tracerPid", "seccomp", "noNewPrivs", "uid", "gid"}) {
    if (!result.contains(field)) result["coverage"] = "partial";
  }
  return result;
}

Json personalitySnapshot(const ReadResult& read) {
  if (!read.error.is_null()) return read.error;
  const auto mask = number(trim(read.text), 16);
  if (!mask || *mask > std::numeric_limits<std::uint32_t>::max()) return malformed("invalid personality mask");
  return {{"available", true}, {"coverage", "complete"}, {"maskHex", hex(*mask)},
          {"addrNoRandomize", (*mask & ADDR_NO_RANDOMIZE) != 0}};
}

Json memorySnapshot(const ReadResult& read) {
  if (!read.error.is_null()) return read.error;
  constexpr std::array<std::pair<std::string_view, const char*>, 10> keys = {{
    {"Rss", "rss"}, {"Pss", "pss"}, {"Shared_Clean", "sharedClean"},
    {"Shared_Dirty", "sharedDirty"}, {"Private_Clean", "privateClean"},
    {"Private_Dirty", "privateDirty"}, {"Anonymous", "anonymous"},
    {"Swap", "swap"}, {"SwapPss", "swapPss"}, {"Locked", "locked"}}};
  Json counters = Json::object();
  std::size_t cursor = 0;
  while (cursor < read.text.size()) {
    const auto newline = read.text.find('\n', cursor);
    if (newline == std::string::npos) return malformed("unterminated memory record");
    const auto line = std::string_view(read.text).substr(cursor, newline - cursor);
    cursor = newline + 1;
    const auto colon = line.find(':');
    if (colon == std::string_view::npos) continue;
    for (const auto& [key, field] : keys) {
      if (line.substr(0, colon) != key) continue;
      const auto values = tokens(line.substr(colon + 1));
      if (values.size() != 2 || values[1] != "kB" || counters.contains(field)) return malformed("invalid memory units");
      const auto value = number(values[0]);
      if (!value || *value > std::numeric_limits<std::uint64_t>::max() / 1024) return malformed("invalid memory counter");
      counters[field] = std::to_string(*value * 1024);
    }
  }
  if (counters.empty()) return malformed("no recognized memory counters");
  const bool complete = counters.size() == keys.size();
  return {{"available", true}, {"coverage", complete ? "complete" : "partial"},
          {"countersBytes", std::move(counters)}};
}

Json descriptorSnapshot(int proc, const ProcessInspectionLimits& limits) {
  const int fd = ::openat(proc, "fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return failure(errno);
  DIR* directory = ::fdopendir(fd);
  if (directory == nullptr) {
    const auto error = errno;
    ::close(fd);
    return failure(error);
  }
  struct CloseDir { DIR* value; ~CloseDir() { ::closedir(value); } } close{directory};
  Json entries = Json::array();
  std::string coverage = "complete";
  std::string reason;
  while (true) {
    errno = 0;
    const auto* entry = ::readdir(directory);
    if (entry == nullptr) {
      if (errno != 0) {
        if (entries.empty()) return failure(errno);
        coverage = "partial";
        reason = "directory-read-error";
      }
      break;
    }
    const std::string_view name(entry->d_name);
    if (name == "." || name == "..") continue;
    const auto descriptor = number(name);
    if (!descriptor || *descriptor > std::numeric_limits<int>::max()) {
      coverage = "partial";
      reason = "malformed-descriptor";
      break;
    }
    if (entries.size() >= limits.maxDescriptors) {
      coverage = "truncated";
      reason = "descriptor-limit";
      break;
    }
    auto target = readLink(fd, entry->d_name, limits.maxLinkBytes);
    if (!target["available"].get<bool>()) coverage = "partial";
    target["descriptor"] = *descriptor;
    entries.push_back(std::move(target));
  }
  std::sort(entries.begin(), entries.end(), [](const Json& left, const Json& right) {
    return left["descriptor"].get<int>() < right["descriptor"].get<int>();
  });
  Json result = {{"available", true}, {"coverage", coverage}, {"entries", std::move(entries)}};
  if (!reason.empty()) result["reason"] = std::move(reason);
  return result;
}

Json systemSnapshot() {
  utsname info{};
  if (::uname(&info) < 0) return failure(errno);
  const long pageSize = ::sysconf(_SC_PAGESIZE);
  Json result = {{"available", true}, {"coverage", pageSize > 0 ? "complete" : "partial"}};
  byteString(result, "kernelRelease", info.release);
  byteString(result, "machine", info.machine);
  if (pageSize > 0) result["pageSizeBytes"] = std::to_string(pageSize);
  return result;
}
#endif

}  // namespace

Json parseLinuxProcessStat(std::string_view text) {
  if (text.size() > 64 * 1024) return unavailable("byte-limit", "stat file exceeds hard limit");
  if (text.find('\0') != std::string_view::npos) return malformed("NUL in stat record");
  const auto open = text.find('(');
  const auto close = text.rfind(')');
  if (open == std::string_view::npos || close == std::string_view::npos || close <= open ||
      open == 0 || !space(text[open - 1]) || close + 1 >= text.size() || !space(text[close + 1])) {
    return malformed("invalid stat command delimiters");
  }
  const auto pid = number(trim(text.substr(0, open)));
  if (!pid || *pid == 0 || *pid > std::numeric_limits<int>::max()) return malformed("invalid stat PID");
  const auto fields = tokens(text.substr(close + 1));
  // fields[0] is kernel field 3; starttime is field 22.
  if (fields.size() < 20 || fields[0].size() != 1 ||
      std::string_view("RSDZTtXxKWPI").find(fields[0]) == std::string_view::npos) {
    return malformed("missing stat identity or invalid state");
  }
  const auto startTime = number(fields[19]);
  if (!startTime) return malformed("invalid stat start time");
  Json result = {{"available", true}, {"coverage", "complete"}, {"pid", std::to_string(*pid)},
    {"state", fields[0]}, {"startTimeTicks", std::to_string(*startTime)},
    {"addressEvidence", "kernel-reported-may-be-redacted"}, {"addresses", Json::object()}};
  byteString(result, "command", text.substr(open + 1, close - open - 1));
  constexpr std::array<std::pair<std::size_t, const char*>, 10> addresses = {{
    {26, "startCodeHex"}, {27, "endCodeHex"}, {28, "startStackHex"},
    {45, "startDataHex"}, {46, "endDataHex"}, {47, "startBrkHex"},
    {48, "argStartHex"}, {49, "argEndHex"}, {50, "envStartHex"}, {51, "envEndHex"}}};
  for (const auto& [index, name] : addresses) {
    if (fields.size() <= index - 3) {
      result["coverage"] = "partial";
      result["addresses"][name] = nullptr;
      continue;
    }
    const auto value = number(fields[index - 3]);
    if (!value) return malformed("invalid stat address");
    result["addresses"][name] = hex(*value);
  }
  return result;
}

Json inspectOwnedProcess(int pid, const ProcessInspectionLimits& requested) {
  const auto failed = [pid](Json error) {
    error["source"] = "linux-procfs";
    error["pid"] = std::to_string(pid);
    error["identityVerified"] = false;
    return error;
  };
  if (pid <= 0) return failed(unavailable("invalid-process", "positive inferior PID required"));
#ifndef __linux__
  (void)requested;
  return failed(unavailable("unsupported-platform", "Linux procfs is required"));
#else
  const ProcessInspectionLimits limits{std::min(requested.maxFileBytes, std::size_t{64 * 1024}),
    std::min(requested.maxDescriptors, std::size_t{128}), std::min(requested.maxLinkBytes, std::size_t{4096})};
  const auto path = "/proc/" + std::to_string(pid);
  Fd proc(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (proc.value < 0) return failed(failure(errno));
  auto initialRead = readFile(proc.value, "stat", limits.maxFileBytes);
  if (!initialRead.error.is_null()) return failed(std::move(initialRead.error));
  auto initialStat = parseLinuxProcessStat(initialRead.text);
  if (!initialStat["available"].get<bool>()) return failed(std::move(initialStat));
  if (initialStat["pid"] != std::to_string(pid)) return failed(unavailable("identity-changed", "stat PID does not match requested process"));

  Json result = {{"available", true}, {"source", "linux-procfs"}, {"pid", std::to_string(pid)},
    {"coverage", "complete"}, {"identityVerified", false}, {"stat", initialStat},
    {"personality", personalitySnapshot(readFile(proc.value, "personality", limits.maxFileBytes))},
    {"status", statusSnapshot(readFile(proc.value, "status", limits.maxFileBytes))},
    {"executable", readLink(proc.value, "exe", limits.maxLinkBytes)},
    {"fileDescriptors", descriptorSnapshot(proc.value, limits)},
    {"memory", memorySnapshot(readFile(proc.value, "smaps_rollup", limits.maxFileBytes))},
    {"system", systemSnapshot()}};

  auto finalRead = readFile(proc.value, "stat", limits.maxFileBytes);
  if (!finalRead.error.is_null()) return failed(std::move(finalRead.error));
  auto finalStat = parseLinuxProcessStat(finalRead.text);
  if (!finalStat["available"].get<bool>()) return failed(std::move(finalStat));
  if (initialStat["pid"] != finalStat["pid"] || initialStat["startTimeTicks"] != finalStat["startTimeTicks"]) {
    return failed(unavailable("identity-changed", "process identity changed during capture"));
  }
  result["identityVerified"] = true;
  for (const auto* section : {"stat", "personality", "status", "executable", "fileDescriptors", "memory", "system"}) {
    if (!result[section]["available"].get<bool>() || result[section]["coverage"] != "complete") result["coverage"] = "partial";
  }
  return result;
#endif
}

}  // namespace phantom
