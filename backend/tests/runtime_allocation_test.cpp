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
           bool released = false) {
  std::string detail = "previous failure must not escape a successful proof";
  const bool result = phantom::verifyRuntimeAllocationDelta(before, after, address, bytes, released, detail);
  if (result != expected) std::fprintf(stderr, "runtime allocation delta: expected %d, got %d: %s\n",
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
  row["startAddressHex"] = hex(start + 0x2000);
  row["endAddressHex"] = hex(start + 0x3000);
  before["regions"].push_back(row);
  after["regions"].push_back(row);
  check(before, after, false, hex(start), 0x1000);
}

#ifdef __linux__
void actualKernelTests() {
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
    if (::write(replies[1], "+", 1) != 1) ::_exit(8);
    if (::read(commands[0], &command, 1) != 1 || command != '-') ::_exit(9);
    if (::munmap(start, page * 3) != 0 || ::write(replies[1], "-", 1) != 1) ::_exit(10);
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
  const auto allocated = phantom::readLinuxMemoryMap(child);
  check(before, allocated, true, hex(address), page * 3);
  assert(::write(commands[1], "-", 1) == 1);
  assert(::read(replies[0], &acknowledged, 1) == 1 && acknowledged == '-');
  const auto released = phantom::readLinuxMemoryMap(child);
  check(allocated, released, true, hex(address), page * 3, true);
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
#ifdef __linux__
  actualKernelTests();
#endif
  std::puts("runtime allocation delta: exact coverage, anonymous merge/split, foreign metadata, malformed/overflow/bounded input and real mmap/munmap passed");
}
