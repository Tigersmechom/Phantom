#include "phantom/memory_map.hpp"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

const std::string first = "00400000-00401000 r-xp 00000000 08:02 9007199254740993 /tmp/a library (deleted)\n";
const std::string second = "00401000-00402000 ---p 00001000 00:00 0\n";

void malformed(const std::string& text) {
  const auto map = phantom::parseLinuxMemoryMap(text);
  assert(map["available"] == false);
  assert(map["coverage"] == "none");
  assert(map["reason"] == "malformed");
  assert(map["regions"].empty());
}

void parserTests() {
  const auto map = phantom::parseLinuxMemoryMap(first + second +
    "00402000-00403000 rw-p 00000000 00:00 0 [heap]\n"
    "00403000-00404000 rw-p 00000000 00:00 0 [stack]\n"
    "00404000-00405000 r-xs 00000000 00:00 0 [vdso]\n"
    "00405000-00406000 rw-s 00000000 00:00 0 [anon_shmem:hello world]\n"
    "00406000-00407000 rw-p 00000000 00:00 0 [anon:arena]\n"
    "00407000-00408000 rw-p 00000000 00:00 0 [stack:42]\n"
    "00408000-00409000 r--p 00000000 00:00 42 /tmp/a\\012b  \n"
    "ffffffffffffe000-fffffffffffff000 r-xp ffffffffffffffff ff:abc 18446744073709551615 [vsyscall]\n");
  assert(map["available"] == true && map["coverage"] == "complete");
  assert(map["regions"].size() == 10);
  const auto& regions = map["regions"];
  assert(regions[0]["startAddressHex"] == "0x400000");
  assert(regions[0]["endAddressHex"] == "0x401000");
  assert(regions[0]["inodeDecimal"] == "9007199254740993");
  assert(regions[0]["path"] == "/tmp/a library (deleted)");
  assert(regions[0]["kind"] == "file");
  assert(regions[1]["path"].is_null() && regions[1]["permissions"] == "---p");
  assert(regions[1]["kind"] == "anonymous");
  assert(regions[2]["kind"] == "heap" && regions[3]["kind"] == "stack");
  assert(regions[4]["kind"] == "special" && regions[4]["permissions"] == "r-xs");
  assert(regions[5]["kind"] == "anonymous" && regions[6]["kind"] == "anonymous");
  assert(regions[7]["kind"] == "stack");
  assert(regions[8]["path"] == "/tmp/a\\012b  ");
  assert(regions[9]["inodeDecimal"] == "18446744073709551615");
  assert(regions[9]["offsetHex"] == "0xffffffffffffffff");
  assert(regions[9]["startAddressHex"] == "0xffffffffffffe000");
  assert(!map.contains("reason"));

  const auto unicode = phantom::parseLinuxMemoryMap("1-2 r--p 0 0:0 1 /tmp/Ж 😀\n");
  assert(unicode["regions"][0]["path"] == "/tmp/Ж 😀");
  assert(!unicode["regions"][0].contains("pathBytesHex"));
  // Linux filenames are bytes. They must never make a response fail JSON dump.
  for (const auto& suffix : {std::string("\xff"), std::string("\xc0\xaf"),
                            std::string("\xed\xa0\x80"), std::string("\xf4\x90\x80\x80"),
                            std::string("\xe2\x82")}) {
    const auto invalid = phantom::parseLinuxMemoryMap("1-2 r--p 0 0:0 1 /tmp/" + suffix + "\n");
    assert(invalid["available"] == true);
    assert(invalid["regions"][0]["path"].is_null());
    assert(invalid["regions"][0]["pathBytesHex"].get<std::string>().starts_with("2f746d702f"));
    assert(!invalid.dump().empty());
  }

  malformed("10000000000000000-10000000000001000 r--p 0 0:0 0\n");
  malformed("gg-ffff r--p 0 0:0 0\n");
  malformed("1-2 r--p 10000000000000000 0:0 0\n");
  malformed("1-2 r--p 0 0:0 18446744073709551616\n");
  malformed("1-2 r--p 0 0:0 -1\n");
  malformed("1-2 r--p 0 bad 0\n");
  malformed("1-2 r--p 0 0:0:0 0\n");
  malformed("1-2 r--? 0 0:0 0\n");
  malformed("1-1 rw-p 0 0:0 0\n");
  malformed("2-1 rw-p 0 0:0 0\n");
  malformed("1-3 rw-p 0 0:0 0\n2-4 rw-p 0 0:0 0\n");
  malformed("4-5 rw-p 0 0:0 0\n1-2 rw-p 0 0:0 0\n");
  malformed(first + "not a maps record\n");
  malformed("1-2 rw-p 0 0:0 0");
  malformed("\n");
  malformed(std::string("1-2 rw-p 0 0:0 0 /tmp/") + '\0' + "file\n");
}

void limitTests() {
  const auto text = first + second;
  const auto bytes = phantom::parseLinuxMemoryMap(text, {first.size() + 4, 100});
  assert(bytes["available"] == true && bytes["coverage"] == "truncated");
  assert(bytes["reason"] == "byte-limit" && bytes["regions"].size() == 1);
  const auto exact = phantom::parseLinuxMemoryMap(text, {text.size(), 2});
  assert(exact["coverage"] == "complete" && exact["regions"].size() == 2);
  const auto region = phantom::parseLinuxMemoryMap(text, {text.size(), 1});
  assert(region["coverage"] == "truncated" && region["reason"] == "region-limit");
  assert(region["regions"].size() == 1);
  const auto partial = phantom::parseLinuxMemoryMap("1-2 rw-p 0", {}, true);
  assert(partial["coverage"] == "truncated" && partial["regions"].empty());
  const auto knownMore = phantom::parseLinuxMemoryMap(first, {}, true);
  assert(knownMore["coverage"] == "truncated" && knownMore["regions"].size() == 1);
  const auto zeroBytes = phantom::parseLinuxMemoryMap(first, {0, 1});
  assert(zeroBytes["coverage"] == "truncated" && zeroBytes["reason"] == "byte-limit");
  const auto zeroRegions = phantom::parseLinuxMemoryMap(first, {first.size(), 0});
  assert(zeroRegions["coverage"] == "truncated" && zeroRegions["reason"] == "region-limit");
  const auto hugeRequest = phantom::parseLinuxMemoryMap(first,
    {std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::size_t>::max()});
  assert(hugeRequest["coverage"] == "complete");
  // A malformed complete line is never hidden by a later byte cutoff.
  const auto malformedPrefix = phantom::parseLinuxMemoryMap("bad\npartial", {8, 10});
  assert(malformedPrefix["reason"] == "malformed");
}

#ifdef __linux__
void systemTests() {
  const long pageSize = ::sysconf(_SC_PAGESIZE);
  assert(pageSize > 0);
  void* guard = ::mmap(nullptr, static_cast<std::size_t>(pageSize), PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(guard != MAP_FAILED);
  const auto map = phantom::readLinuxMemoryMap(::getpid());
  assert(map["available"] == true && map["coverage"] == "complete");
  assert(!map["regions"].empty());
  bool foundGuard = false;
  const auto address = reinterpret_cast<std::uintptr_t>(guard);
  for (const auto& region : map["regions"]) {
    const auto start = std::stoull(region["startAddressHex"].get<std::string>(), nullptr, 16);
    const auto end = std::stoull(region["endAddressHex"].get<std::string>(), nullptr, 16);
    if (start <= address && address < end) {
      assert(region["permissions"] == "---p");
      assert(region["kind"] == "anonymous");
      foundGuard = true;
    }
  }
  assert(foundGuard);
  assert(::munmap(guard, static_cast<std::size_t>(pageSize)) == 0);
  const auto tiny = phantom::readLinuxMemoryMap(::getpid(), {8, 10});
  assert(tiny["available"] == true && tiny["coverage"] == "truncated");
  assert(tiny["reason"] == "byte-limit" && tiny["regions"].empty());
  assert(phantom::readLinuxMemoryMap(0)["reason"] == "invalid-process");
  assert(phantom::readLinuxMemoryMap(-1)["reason"] == "invalid-process");

  const auto child = ::fork();
  assert(child >= 0);
  if (child == 0) ::_exit(0);
  int status = 0;
  assert(::waitpid(child, &status, 0) == child);
  const auto exited = phantom::readLinuxMemoryMap(child);
  assert(exited["available"] == false);
  assert(exited["reason"] == "process-unavailable" || exited["reason"] == "process-exited");

  // An undumpable owned process exercises permissions without reading anyone
  // else's address space. Root/CAP_SYS_PTRACE can legitimately bypass the gate.
  int ready[2];
  int finish[2];
  assert(::pipe(ready) == 0 && ::pipe(finish) == 0);
  const auto protectedChild = ::fork();
  assert(protectedChild >= 0);
  if (protectedChild == 0) {
    ::close(ready[0]); ::close(finish[1]);
    const char ok = ::prctl(PR_SET_DUMPABLE, 0) == 0 ? 'y' : 'n';
    if (::write(ready[1], &ok, 1) != 1) ::_exit(1);
    char signal;
    if (::read(finish[0], &signal, 1) != 1) ::_exit(1);
    ::_exit(0);
  }
  ::close(ready[1]); ::close(finish[0]);
  char ok = 'n';
  assert(::read(ready[0], &ok, 1) == 1 && ok == 'y');
  const auto denied = phantom::readLinuxMemoryMap(protectedChild);
  if (!denied["available"].get<bool>()) {
    // hidepid may deliberately turn a permission failure into ENOENT.
    assert(denied["reason"] == "read-denied" || denied["reason"] == "process-unavailable");
  }
  assert(::write(finish[1], "x", 1) == 1);
  ::close(ready[0]); ::close(finish[1]);
  assert(::waitpid(protectedChild, &status, 0) == protectedChild && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#endif

}  // namespace

int main() {
  parserTests();
  limitTests();
#ifdef __linux__
  systemTests();
#endif
}
