#include "phantom/runtime_allocation.hpp"
#include "phantom/memory_map.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <sstream>
#include <string>

#ifdef __linux__
#include <cerrno>
#include <csignal>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
using Json = nlohmann::json;

std::string hex(std::uint64_t value) {
  std::ostringstream result;
  result << "0x" << std::hex << value;
  return result.str();
}

Json map(std::string_view text) {
  auto result = phantom::parseLinuxMemoryMap(text);
  assert(result.at("available") == true && result.at("coverage") == "complete");
  return result;
}

void check(const Json& before, const Json& after, bool expected,
           std::string_view address = "0x4000", std::size_t bytes = 0x2000,
           bool released = false, std::string_view permissions = "rw-") {
  std::string detail = "previous failure must not escape a successful proof";
  const bool result = phantom::verifyRuntimeAllocationDelta(before, after, address, bytes, released,
                                                           detail, permissions);
  if (result != expected) std::fprintf(stderr, "runtime allocation delta: expected %d, got %d: %s\n",
                                      expected, result, detail.c_str());
  assert(result == expected);
  assert(expected ? detail.empty() : !detail.empty());
}

void protect(const Json& before, const Json& after, bool expected,
             std::string_view oldPermissions = "rw-", std::string_view newPermissions = "r--",
             std::string_view address = "0x4000", std::size_t bytes = 0x2000) {
  std::string detail = "previous failure must not escape a successful proof";
  const bool result = phantom::verifyRuntimeProtectionDelta(before, after, address, bytes,
      oldPermissions, newPermissions, detail);
  if (result != expected) std::fprintf(stderr, "runtime protection delta: expected %d, got %d: %s\n",
                                      expected, result, detail.c_str());
  assert(result == expected);
  assert(expected ? detail.empty() : !detail.empty());
}

const std::string lower = "1000-2000 r-xp 1000 08:02 9007199254740993 /tmp/file with spaces (deleted)\n";
const std::string upper = "8000-9000 rw-p 0 00:00 0 [heap]\n"
    "9000-a000 ---p 0 00:00 0 [stack]\n"
    "ffffffffff600000-ffffffffff601000 --xp 0 00:00 0 [vsyscall]\n";

void intervalTests() {
  const auto empty = map("");
  const auto exact = map("4000-6000 rw-p 0 00:00 0\n");
  check(empty, exact, true);
  check(exact, empty, true, "0x4000", 0x2000, true);
  check(exact, exact, false);
  check(empty, empty, false);
  check(empty, exact, false, "0x4000", 0);
  check(empty, exact, false, "0x4000", 1024 * 1024 + 1);
  check(empty, exact, false, "0x4000", std::numeric_limits<std::size_t>::max());
  check(empty, exact, false, "0xfffffffffffff000", 0x2000);
  for (const auto address : {"", "4000", "0X4000", "0x04000", "0x400G", "0x0", "0x10000000000000000"})
    check(empty, exact, false, address);
  const auto maximum = map("4000-104000 rw-p 0 00:00 0\n");
  check(empty, maximum, true, "0x4000", 1024 * 1024);
  const auto before = map(lower + "3000-4000 rw-p 0 00:00 0\n6000-7000 rw-p 0 00:00 0\n" + upper);
  const auto merged = map(lower + "3000-7000 rw-p 0 00:00 0\n" + upper);
  check(before, merged, true);
  check(merged, before, true, "0x4000", 0x2000, true);
  const auto split = map(lower + "3000-4000 rw-p 0 00:00 0\n4000-5000 rw-p 0 00:00 0\n"
      "5000-6000 rw-p 0 00:00 0\n6000-7000 rw-p 0 00:00 0\n" + upper);
  check(before, split, true);
  check(split, before, true, "0x4000", 0x2000, true);
  const auto oneSide = map(lower + "3000-4000 r--p 0 00:00 0\n6000-7000 rw-p 0 00:00 0\n" + upper);
  const auto oneMerged = map(lower + "3000-4000 r--p 0 00:00 0\n4000-7000 rw-p 0 00:00 0\n" + upper);
  check(oneSide, oneMerged, true);
  check(oneMerged, oneSide, true, "0x4000", 0x2000, true);

  // Holes and extra changed bytes may not hide inside a covering VMA or its
  // apparent merged extent. Exact end/start boundaries remain half-open.
  check(before, map(lower + "3000-5000 rw-p 0 00:00 0\n6000-7000 rw-p 0 00:00 0\n" + upper), false);
  check(before, map(lower + "3000-4800 rw-p 0 00:00 0\n4900-7000 rw-p 0 00:00 0\n" + upper), false);
  check(before, map(lower + "2000-7000 rw-p 0 00:00 0\n" + upper), false);
  check(before, map(lower + "3000-8000 rw-p 0 00:00 0\n" + upper), false);
  check(before, map(lower + "3000-7000 rw-p 0 00:00 0\n7000-8000 ---p 0 00:00 0\n" + upper), false);
  check(map(lower + "3000-4100 rw-p 0 00:00 0\n6000-7000 rw-p 0 00:00 0\n" + upper), merged, false);
  check(merged, map(lower + "3000-4000 rw-p 0 00:00 0\n5000-7000 rw-p 0 00:00 0\n" + upper), false,
        "0x4000", 0x2000, true);

  for (const auto record : {"4000-6000 rw-s 0 00:00 0\n", "4000-6000 r--p 0 00:00 0\n",
                            "4000-6000 rwxp 0 00:00 0\n", "4000-6000 rw-p 1000 00:00 0\n",
                            "4000-6000 rw-p 0 08:02 0\n", "4000-6000 rw-p 0 00:00 2\n",
                            "4000-6000 rw-p 0 00:00 0 [anon:tag]\n",
                            "4000-6000 rw-p 0 00:00 0 [heap]\n",
                            "4000-6000 rw-p 0 00:00 0 /file\n",
                            "4000-6000 rw-p 0 0:0 0\n"}) {
    check(empty, map(record), false);
    check(map(record), empty, false, "0x4000", 0x2000, true);
  }

  // Non-target file, stack, named anonymous and shared boundaries cannot be
  // normalized away, even when their coverage and apparent flags match.
  for (const auto suffix : {"rw-p 0 00:00 0 [anon:arena]\n", "rw-p 0 00:00 0 [stack]\n",
                           "rw-s 0 00:00 0\n", "r--p 0 08:02 9 /file\n",
                           "rw-p 1000 00:00 0\n", "rw-p 0 0:0 0\n"}) {
    const auto unsplit = map(std::string("1000-3000 ") + suffix);
    const auto changed = map(std::string("1000-2000 ") + suffix + "2000-3000 " + suffix +
                             "4000-6000 rw-p 0 00:00 0\n");
    check(unsplit, changed, false);
  }
}

void schemaTests() {
  const auto before = map(lower + upper);
  const auto after = map(lower + "4000-6000 rw-p 0 00:00 0\n" + upper);
  check(before, after, true);
  for (const auto& value : Json::array({nullptr, false, 1, "maps", Json::array()})) {
    check(value, after, false);
    check(before, value, false);
  }
  const Json mapChanges = {{"available", 1}, {"source", "other"}, {"coverage", "truncated"},
                           {"regions", Json::object()}, {"reason", "byte-limit"}};
  for (const auto& [key, value] : mapChanges.items()) {
    auto changed = before;
    changed[key] = value;
    check(changed, after, false);
  }
  for (const auto* key : {"startAddressHex", "endAddressHex", "permissions", "offsetHex", "device",
                          "inodeDecimal", "path", "kind"}) {
    auto changed = before;
    changed["regions"][0].erase(key);
    check(changed, after, false);
  }
  const Json malformedChanges = {{"startAddressHex", "0x10000000000000000"},
      {"endAddressHex", "0x02000"}, {"offsetHex", "0X1000"}, {"inodeDecimal", "18446744073709551616"},
      {"device", "0:0:0"}, {"permissions", "rw-?"}, {"kind", "anonymous"}, {"extra", true}};
  for (const auto& [key, value] : malformedChanges.items()) {
    auto changed = before;
    changed["regions"][0][key] = value;
    check(changed, after, false);
  }
  for (const auto& bad : Json::array({nullptr, false, 0, 1.25, "", "-1", "01"})) {
    auto changed = before;
    changed["regions"][0]["inodeDecimal"] = bad;
    check(changed, after, false);
  }
  for (const auto* key : {"startAddressHex", "endAddressHex", "offsetHex", "device", "permissions", "kind"}) {
    auto changed = before;
    changed["regions"][0][key] = 1;
    check(changed, after, false);
  }
  for (const auto& path : {std::string(""), std::string("/tmp/a\nb"), std::string("/tmp/a\0b", 8),
                           std::string(" /tmp/file"), std::string("/tmp/\xff")}) {
    auto changed = before;
    changed["regions"][0]["path"] = path;
    check(changed, after, false);
  }
  for (const auto raw : {"", "f", "FG", "2f66696c65", "ff00", "ff0a"}) {
    auto changed = before;
    changed["regions"][0]["path"] = nullptr;
    changed["regions"][0]["pathBytesHex"] = raw;
    check(changed, after, false);
  }
  auto conflict = before;
  conflict["regions"][0]["pathBytesHex"] = "ff";
  check(conflict, after, false);
  auto unordered = after;
  std::swap(unordered["regions"][0], unordered["regions"][1]);
  check(before, unordered, false);
  auto overlapping = after;
  overlapping["regions"][1]["startAddressHex"] = "0x1000";
  check(before, overlapping, false);
  auto zero = before;
  zero["regions"][0]["endAddressHex"] = zero["regions"][0]["startAddressHex"];
  check(zero, after, false);
}

void preservedMetadataTests() {
  const auto before = map(lower + upper);
  const auto after = map(lower + "4000-6000 rw-p 0 00:00 0\n" + upper);
  const Json changes = {{"startAddressHex", "0x1100"}, {"endAddressHex", "0x2100"},
      {"offsetHex", "0x2000"}, {"inodeDecimal", "9007199254740994"}, {"device", "08:03"},
      {"permissions", "r--p"}, {"path", "/tmp/file with spaces"}};
  for (const auto& [key, value] : changes.items()) {
    auto changed = after;
    changed["regions"][0][key] = value;
    check(before, changed, false);
  }
  const std::string opaque = "1000-2000 r--p 0 08:02 17 /tmp/\xff\\012tail  \n";
  const auto rawBefore = map(opaque + upper);
  auto rawAfter = map(opaque + "4000-6000 rw-p 0 00:00 0\n" + upper);
  assert(rawBefore["regions"][0]["path"].is_null());
  check(rawBefore, rawAfter, true);
  check(rawAfter, rawBefore, true, "0x4000", 0x2000, true);
  rawAfter["regions"][0]["pathBytesHex"] = "2f746d702ffe";
  check(rawBefore, rawAfter, false);
  const auto unicodeBefore = map("1000-2000 r--p 0 08:02 17 /tmp/Ж 😀\\012file  \n");
  const auto unicodeAfter = map("1000-2000 r--p 0 08:02 17 /tmp/Ж 😀\\012file  \n4000-6000 rw-p 0 00:00 0\n");
  check(unicodeBefore, unicodeAfter, true);
}

void regionLimitTests() {
  auto before = map("");
  auto row = map("1000-2000 rw-p 0 00:00 0\n").at("regions")[0];
  for (std::uint64_t i = 0; i < 8192; ++i) {
    row["startAddressHex"] = hex(0x1000 + i * 0x2000);
    row["endAddressHex"] = hex(0x2000 + i * 0x2000);
    before["regions"].push_back(row);
  }
  const auto start = 0x2000 + std::uint64_t{8191} * 0x2000;
  auto after = before;
  after["regions"].back()["endAddressHex"] = hex(start + 0x1000);
  check(before, after, true, hex(start), 0x1000);
  auto protectedMap = before;
  protectedMap["regions"][0]["permissions"] = "r--p";
  protect(before, protectedMap, true, "rw-", "r--", "0x1000", 0x1000);
  row["startAddressHex"] = hex(start + 0x2000);
  row["endAddressHex"] = hex(start + 0x3000);
  before["regions"].push_back(row);
  after["regions"].push_back(row);
  check(before, after, false, hex(start), 0x1000);
  protect(before, protectedMap, false, "rw-", "r--", "0x1000", 0x1000);
  protectedMap["regions"].push_back(row);
  protect(protectedMap, before, false, "r--", "rw-", "0x1000", 0x1000);
}

void protectionTests() {
  const auto empty = map("");
  const auto rw = map("4000-6000 rw-p 0 00:00 0\n");
  const auto ro = map("4000-6000 r--p 0 00:00 0\n");
  // Cover every transition, including a syscall whose requested permissions
  // already match. Both halves must be uniformly covered by the recorded mode.
  for (const auto oldPermissions : {"r--", "rw-", "r-x"}) {
    const auto before = map(lower + "4000-5000 " + oldPermissions + "p 0 00:00 0\n"
        "5000-6000 " + oldPermissions + "p 0 00:00 0\n" + upper);
    check(before, map(lower + upper), true, "0x4000", 0x2000, true, oldPermissions);
    check(map(lower + upper), before, std::string_view(oldPermissions) == "rw-",
          "0x4000", 0x2000, false, oldPermissions);
    for (const auto newPermissions : {"r--", "rw-", "r-x"}) {
      const auto after = map(lower + "4000-6000 " + newPermissions + "p 0 00:00 0\n" + upper);
      protect(before, after, true, oldPermissions, newPermissions);
      protect(after, before, true, newPermissions, oldPermissions);
      for (const auto incorrect : {"r--", "rw-", "r-x"}) {
        if (std::string_view(incorrect) != oldPermissions)
          protect(before, after, false, incorrect, newPermissions);
        if (std::string_view(incorrect) != newPermissions)
          protect(before, after, false, oldPermissions, incorrect);
      }
    }
  }
  for (const auto invalid : {"", "r", "r--p", "rw-p", "rwx", "--x", "---", "-w-", "RW-", "rw- "}) {
    protect(rw, ro, false, invalid, "r--");
    protect(rw, ro, false, "rw-", invalid);
    check(rw, empty, false, "0x4000", 0x2000, true, invalid);
  }
  const auto merged = map(lower + "3000-7000 rw-p 0 00:00 0\n" + upper);
  const auto split = map(lower + "3000-4000 rw-p 0 00:00 0\n4000-6000 r--p 0 00:00 0\n"
      "6000-7000 rw-p 0 00:00 0\n" + upper);
  protect(merged, split, true);
  protect(split, merged, true, "r--", "rw-");
  // A change can merge the target with existing RO neighbours, or be confined
  // to a single side of a VMA. No outside byte may change permissions.
  const auto roNeighbours = map(lower + "3000-4000 r--p 0 00:00 0\n4000-6000 rw-p 0 00:00 0\n"
      "6000-7000 r--p 0 00:00 0\n" + upper);
  const auto roMerged = map(lower + "3000-7000 r--p 0 00:00 0\n" + upper);
  protect(roNeighbours, roMerged, true);
  protect(roMerged, roNeighbours, true, "r--", "rw-");
  const auto side = map(lower + "3000-4000 rw-p 0 00:00 0\n4000-7000 r--p 0 00:00 0\n" + upper);
  protect(roNeighbours, side, false);
  protect(merged, side, true, "rw-", "r--", "0x4000", 0x3000);

  protect(empty, ro, false);
  protect(rw, empty, false);
  protect(rw, ro, false, "rw-", "r--", "0x4000", 0);
  protect(rw, ro, false, "rw-", "r--", "0x4000", 1024 * 1024 + 1);
  protect(rw, ro, false, "rw-", "r--", "0x4000", std::numeric_limits<std::size_t>::max());
  protect(rw, ro, false, "rw-", "r--", "0xfffffffffffff000", 0x2000);
  for (const auto address : {"", "4000", "0X4000", "0x04000", "0x400G", "0x0", "0x10000000000000000"})
    protect(rw, ro, false, "rw-", "r--", address);
  for (const auto record : {"4000-5000 r--p 0 00:00 0\n", // Short coverage.
      "4000-4fff r--p 0 00:00 0\n5000-6000 r--p 0 00:00 0\n", // One-byte hole.
      "4000-5000 r--p 0 00:00 0\n5000-6000 rw-p 0 00:00 0\n", // Partial update.
      "3fff-6000 r--p 0 00:00 0\n", "4000-6001 r--p 0 00:00 0\n", // Outside byte.
      "4000-6000 rwxp 0 00:00 0\n", "4000-6000 r--s 0 00:00 0\n",
      "4000-6000 r--p 1000 00:00 0\n", "4000-6000 r--p 0 08:02 0\n",
      "4000-6000 r--p 0 00:00 3\n", "4000-6000 r--p 0 00:00 0 [anon:arena]\n",
      "4000-6000 r--p 0 00:00 0 [heap]\n", "4000-6000 r--p 0 00:00 0 /file\n"}) {
    protect(rw, map(record), false);
    protect(map(record), rw, false, "r--", "rw-");
  }
  // Changes in non-target map metadata or file/stack boundaries remain exact,
  // including opaque paths which cannot be encoded as JSON UTF-8 strings.
  const std::string opaque = "1000-2000 r--p 0 08:02 17 /tmp/\xff\\012tail  \n";
  const auto rawBefore = map(opaque + "4000-6000 rw-p 0 00:00 0\n" + upper);
  const auto rawAfter = map(opaque + "4000-6000 r--p 0 00:00 0\n" + upper);
  protect(rawBefore, rawAfter, true);
  auto unordered = rawAfter;
  std::swap(unordered["regions"][0], unordered["regions"][1]);
  protect(rawBefore, unordered, false);
  auto overlapping = rawBefore;
  overlapping["regions"][1]["startAddressHex"] = "0x1000";
  protect(overlapping, rawAfter, false);
  const Json changes = {{"startAddressHex", "0x1100"}, {"endAddressHex", "0x2100"},
      {"offsetHex", "0x1000"}, {"inodeDecimal", "18"}, {"device", "08:03"},
      {"permissions", "r-xp"}, {"pathBytesHex", "2f746d702ffe"}};
  for (const auto& [key, value] : changes.items()) {
    auto changed = rawAfter;
    changed["regions"][0][key] = value;
    protect(rawBefore, changed, false);
  }
  for (const auto suffix : {"rw-p 0 00:00 0 [anon:arena]\n", "rw-p 0 00:00 0 [stack]\n",
                           "rw-s 0 00:00 0\n", "r--p 0 08:02 9 /file\n"}) {
    const auto before = map(std::string("1000-3000 ") + suffix + "4000-6000 rw-p 0 00:00 0\n");
    const auto after = map(std::string("1000-2000 ") + suffix + "2000-3000 " + suffix +
                            "4000-6000 r--p 0 00:00 0\n");
    protect(before, after, false);
  }
  for (const auto& bad : Json::array({nullptr, false, 1, "maps", Json::array()})) {
    protect(bad, ro, false);
    protect(rw, bad, false);
  }
  const Json malformedMaps = {{"coverage", "partial"}, {"available", 1},
      {"source", "other"}, {"regions", Json::object()}, {"extra", true}};
  for (const auto& [key, value] : malformedMaps.items()) {
    auto badBefore = rw, badAfter = ro;
    badBefore[key] = value;
    badAfter[key] = value;
    protect(badBefore, ro, false);
    protect(rw, badAfter, false);
  }
  const Json malformedRegions = {{"endAddressHex", "0x06000"}, {"startAddressHex", 1},
      {"permissions", "r--?"}, {"inodeDecimal", "18446744073709551616"},
      {"device", "00:00:00"}, {"kind", "file"}, {"extra", 1}};
  for (const auto& [key, value] : malformedRegions.items()) {
    auto badBefore = rw, badAfter = ro;
    badBefore["regions"][0][key] = value;
    badAfter["regions"][0][key] = value;
    protect(badBefore, ro, false);
    protect(rw, badAfter, false);
  }
  for (const auto* key : {"startAddressHex", "endAddressHex", "permissions", "offsetHex", "device",
                          "inodeDecimal", "path", "kind"}) {
    auto badBefore = rw, badAfter = ro;
    badBefore["regions"][0].erase(key);
    badAfter["regions"][0].erase(key);
    protect(badBefore, ro, false);
    protect(rw, badAfter, false);
  }
  const auto maximumBefore = map("4000-104000 rw-p 0 00:00 0\n");
  const auto maximumAfter = map("4000-104000 r-xp 0 00:00 0\n");
  protect(maximumBefore, maximumAfter, true, "rw-", "r-x", "0x4000", 1024 * 1024);
}

#ifdef __linux__
void actualKernelTests(char releaseMode) {
  // Read another, waiting process: parsing JSON must not perturb the measured
  // process's heap/maps. Start with two RW edges, fill their hole, then split
  // the merged extent again. No region boundary is assumed to equal ownership.
  int commands[2], replies[2];
  assert(::pipe(commands) == 0 && ::pipe(replies) == 0);
  const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  assert(page > 0 && page * 3 <= 1024 * 1024);
  const auto child = ::fork();
  assert(child >= 0);
  if (child == 0) {
    const auto parent = ::getppid();
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parent) ::_exit(2);
    ::close(commands[1]); ::close(replies[0]);
    void* base = ::mmap(nullptr, page * 5, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) ::_exit(3);
    auto* start = static_cast<char*>(base) + page;
    if (::munmap(start, page * 3) != 0) ::_exit(4);
    const auto address = reinterpret_cast<std::uintptr_t>(start);
    if (::write(replies[1], &address, sizeof(address)) != sizeof(address)) ::_exit(5);
    char command;
    if (::read(commands[0], &command, 1) != 1 || command != '+') ::_exit(6);
    void* filled = ::mmap(start, page * 3, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (filled != start) ::_exit(7);
    for (std::size_t i = 0; i < page * 3; ++i)
      start[i] = static_cast<char>((i * 17 + 3) % 251);
    if (::write(replies[1], "+", 1) != 1) ::_exit(8);
    while (true) {
      if (::read(commands[0], &command, 1) != 1) ::_exit(9);
      if (command == '-') break;
      if (command != 'r' && command != 'w' && command != 'x') ::_exit(13);
      const auto flags = PROT_READ | (command == 'w' ? PROT_WRITE : command == 'x' ? PROT_EXEC : 0);
      if (::mprotect(start, page * 3, flags) != 0) ::_exit(14);
      for (std::size_t i = 0; i < page * 3; ++i)
        if (start[i] != static_cast<char>((i * 17 + 3) % 251)) ::_exit(15);
      if (::write(replies[1], &command, 1) != 1) ::_exit(16);
    }
    if (::munmap(start, page * 3) != 0 || ::write(replies[1], "-", 1) != 1) ::_exit(10);
    // Linux mprotect may modify an earlier VMA and then fail on a later hole.
    // A nonzero syscall return must never be treated as proof of no mutation.
    if (::read(commands[0], &command, 1) != 1 || command != '!') ::_exit(17);
    errno = 0;
    if (::mprotect(base, page * 5, PROT_READ) != -1 || errno != ENOMEM) ::_exit(18);
    if (::write(replies[1], "!", 1) != 1) ::_exit(19);
    if (::read(commands[0], &command, 1) != 1 || command != 'q') ::_exit(11);
    if (::munmap(base, page * 5) != 0) ::_exit(12);
    ::_exit(0);
  }
  ::close(commands[0]); ::close(replies[1]);
  std::uintptr_t address = 0;
  assert(::read(replies[0], &address, sizeof(address)) == sizeof(address));
  const auto before = phantom::readLinuxMemoryMap(child);
  assert(::write(commands[1], "+", 1) == 1);
  char acknowledged = 0;
  assert(::read(replies[0], &acknowledged, 1) == 1 && acknowledged == '+');
  auto allocated = phantom::readLinuxMemoryMap(child);
  check(before, allocated, true, hex(address), page * 3);
  const auto permissions = [](char mode) -> std::string_view {
    return mode == 'w' ? "rw-" : mode == 'x' ? "r-x" : "r--";
  };
  auto oldPermissions = permissions('w');
  // An Euler traversal of the three-mode graph exercises all nine directed
  // transitions. Each actual VMA split/merge is verified from the parent.
  for (const auto mode : std::string("wrrxxwxrw") + releaseMode) {
    assert(::write(commands[1], &mode, 1) == 1);
    assert(::read(replies[0], &acknowledged, 1) == 1 && acknowledged == mode);
    const auto changed = phantom::readLinuxMemoryMap(child);
    protect(allocated, changed, true, oldPermissions, permissions(mode), hex(address), page * 3);
    allocated = changed;
    oldPermissions = permissions(mode);
  }
  assert(::write(commands[1], "-", 1) == 1);
  assert(::read(replies[0], &acknowledged, 1) == 1 && acknowledged == '-');
  const auto released = phantom::readLinuxMemoryMap(child);
  check(allocated, released, true, hex(address), page * 3, true, permissions(releaseMode));
  assert(::write(commands[1], "!", 1) == 1);
  assert(::read(replies[0], &acknowledged, 1) == 1 && acknowledged == '!');
  const auto partial = phantom::readLinuxMemoryMap(child);
  assert(partial != released);
  protect(released, partial, false, "rw-", "r--", hex(address - page), page * 5);
  // Independently verify that the first edge changed and the second stayed RW.
  protect(released, partial, true, "rw-", "r--", hex(address - page), page);
  assert(::write(commands[1], "q", 1) == 1);
  ::close(commands[1]); ::close(replies[0]);
  int status = 0;
  while (::waitpid(child, &status, 0) < 0) assert(errno == EINTR);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#endif
}  // namespace

int main() {
  intervalTests();
  schemaTests();
  preservedMetadataTests();
  regionLimitTests();
  protectionTests();
#ifdef __linux__
  for (const auto mode : {'w', 'r', 'x'}) actualKernelTests(mode);
#endif
  std::puts("runtime memory delta: exact coverage, all protection modes, anonymous merge/split, foreign metadata, malformed/bounded input and real mmap/mprotect/munmap passed");
}
