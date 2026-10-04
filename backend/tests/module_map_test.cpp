#include "phantom/module_map.hpp"
#include "phantom/elf.hpp"
#include "phantom/memory_map.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>

#ifdef __linux__
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
using Json = nlohmann::json;
#ifdef __linux__
std::string hex(std::uint64_t value) {
  char data[32];
  std::snprintf(data, sizeof(data), "0x%llx", static_cast<unsigned long long>(value));
  return data;
}
void word(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned width) {
  assert(offset + width <= bytes.size());
  for (unsigned i = 0; i < width; ++i) bytes[offset + i] = static_cast<char>((value >> (8 * i)) & 255);
}
std::string elfFixture(std::size_t page, bool executable = false) {
  std::string bytes(2 * page, '\0');
  bytes.replace(0, 4, "\177ELF", 4);
  word(bytes, 4, 2, 1); word(bytes, 5, 1, 1); word(bytes, 6, 1, 1);
  word(bytes, 16, executable ? 2 : 3, 2); word(bytes, 18, 62, 2); word(bytes, 20, 1, 4);
  word(bytes, 32, 64, 8); word(bytes, 52, 64, 2); word(bytes, 54, 56, 2); word(bytes, 56, 2, 2);
  const std::uint64_t base = executable ? 0x400000 : 0;
  word(bytes, 64, 1, 4); word(bytes, 68, 4, 4); word(bytes, 80, base, 8);
  word(bytes, 96, page, 8); word(bytes, 104, page, 8); word(bytes, 112, page, 8);
  word(bytes, 120, 1, 4); word(bytes, 124, 6, 4); word(bytes, 128, page, 8);
  word(bytes, 136, base + 2 * page, 8); word(bytes, 152, page, 8);
  word(bytes, 160, 3 * page, 8); word(bytes, 168, page, 8);
  return bytes;
}
struct Fixture {
  std::filesystem::path directory, path;
  int fd = -1;
  std::size_t page;
  std::vector<void*> allocations;
  explicit Fixture(const std::string& name = "library with spaces.so", bool executable = false) {
    const auto size = ::sysconf(_SC_PAGESIZE);
    assert(size > 0);
    page = static_cast<std::size_t>(size);
    char temp[] = "/tmp/phantom-module-map-XXXXXX";
    auto* made = ::mkdtemp(temp);
    assert(made);
    directory = made; path = directory / name;
    fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    const auto bytes = elfFixture(page, executable);
    assert(::write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
  }
  ~Fixture() {
    for (auto* allocation : allocations) assert(::munmap(allocation, 5 * page) == 0);
    if (fd >= 0) ::close(fd);
    std::error_code ec; std::filesystem::remove_all(directory, ec);
  }
  std::uint64_t map() {
    void* allocation = ::mmap(nullptr, 5 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(allocation != MAP_FAILED);
    allocations.push_back(allocation);
    auto* base = static_cast<char*>(allocation);
    assert(::mmap(base, page, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0) == base);
    assert(::mmap(base + 2 * page, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
                  fd, static_cast<off_t>(page)) == base + 2 * page);
    assert(::mprotect(base + 3 * page, 2 * page, PROT_READ | PROT_WRITE) == 0);
    return reinterpret_cast<std::uintptr_t>(base);
  }
  std::string inode() const { struct stat st{}; assert(::fstat(fd, &st) == 0); return std::to_string(st.st_ino); }
  Json snapshot() const { return phantom::readLinuxMemoryMap(::getpid()); }
  Json index(const phantom::ModuleInspectionLimits& limits = {}) const {
    return phantom::inspectRuntimeModules(::getpid(), snapshot(), limits);
  }
  const Json& module(const Json& result) const {
    assert(result["available"] == true);
    for (const auto& item : result["modules"]) if (item["inodeDecimal"] == inode()) return item;
    assert(false && "fixture module is missing");
    std::abort();
  }
};

void actualMappings() {
  Fixture fixture;
  const auto first = fixture.map(), second = fixture.map();
  auto result = fixture.index();
  assert(result["source"] == "linux-proc-maps-elf" && result["identityVerified"] == true);
  assert(result["pageSizeBytes"] == std::to_string(fixture.page));
  auto module = fixture.module(result);
  assert(module["file"]["available"] == true && module["file"]["identityVerified"] == true);
  assert(module["contentIdentity"] == "file-metadata-only");
  assert(module["elf"]["available"] == true && module["elf"]["elfType"] == "ET_DYN");
  assert(module["path"] == fixture.path.string());
  assert(module["instances"].size() == 2);
  assert(module["mappedRegions"].size() == 4);
  assert(module["unassignedRegionStarts"].empty());
  for (const auto& instance : module["instances"]) {
    const auto bias = std::stoull(instance["loadBiasHex"].get<std::string>(), nullptr, 16);
    assert(bias == first || bias == second);
    assert(instance["coverage"] == "complete");
    assert(instance["segments"].size() == 2);
    const auto& tail = instance["segments"][1];
    assert(tail["startAddressHex"] == hex(bias + fixture.page * 2));
    assert(tail["fileEndAddressHex"] == hex(bias + fixture.page * 3));
    assert(tail["endAddressHex"] == hex(bias + fixture.page * 5));
    assert(tail["mappedRanges"].size() == 2);
    assert(tail["mappedRanges"][0]["backing"] == "file");
    assert(tail["mappedRanges"][1]["backing"] == "anonymous");
  }
  // Changing permissions splits one file mapping; it does not create a new
  // ELF instance, and both current permissions and ELF segment flags remain.
  assert(::mprotect(reinterpret_cast<void*>(first + 2 * fixture.page), fixture.page, PROT_READ) == 0);
  auto readonly = fixture.module(fixture.index());
  bool checked = false;
  for (const auto& instance : readonly["instances"]) if (instance["loadBiasHex"] == hex(first)) {
    assert(instance["segments"][1]["flags"]["write"] == true);
    assert(instance["segments"][1]["mappedRanges"][0]["permissions"] == "r--p");
    checked = true;
  }
  assert(checked);
  // Removal must be observed from a fresh snapshot; old JSON remains immutable.
  assert(::munmap(fixture.allocations.back(), 5 * fixture.page) == 0);
  fixture.allocations.pop_back();
  assert(fixture.module(fixture.index())["instances"].size() == 1);
  assert(module["instances"].size() == 2);
}

void identityAndNames() {
  Fixture fixture;
  fixture.map();
  auto original = fixture.index();
  assert(fixture.module(original)["elf"]["available"] == true);
  const auto old = fixture.directory / "renamed original.so";
  assert(::rename(fixture.path.c_str(), old.c_str()) == 0);
  { std::ofstream replaced(fixture.path); replaced << "this is not the mapped ELF"; }
  auto moved = fixture.module(fixture.index());
  assert(moved["elf"]["available"] == true);
  assert(moved["path"] == old.string());
  assert(::unlink(old.c_str()) == 0);
  auto deleted = fixture.module(fixture.index());
  assert(deleted["path"].get<std::string>().ends_with(" (deleted)"));
  if (deleted["elf"]["available"] == true) {
    assert(deleted["file"]["openedVia"] == "map-files");
  } else {
    assert(deleted["file"]["identityVerified"] == false);
    assert(deleted["instances"].empty());
  }
  // Stale path input points to a replacement inode. Metadata from that file
  // must never be attributed to the old mapped inode.
  auto stale = fixture.snapshot();
  for (auto& region : stale["regions"]) if (region["inodeDecimal"] == fixture.inode())
    region["path"] = fixture.path.string();
  auto staleResult = fixture.module(phantom::inspectRuntimeModules(::getpid(), stale));
  if (staleResult["elf"]["available"] == true) assert(staleResult["file"]["openedVia"] == "map-files");
  else assert(staleResult["file"]["reason"] == "file-identity-mismatch");

  Fixture literal("literal\\012name.so"); literal.map();
  assert(literal.module(literal.index())["elf"]["available"] == true);
  Fixture invalid(std::string("non-UTF8-") + '\xff' + ".so"); invalid.map();
  auto invalidModule = invalid.module(invalid.index());
  assert(invalidModule["path"].is_null() && invalidModule.contains("pathBytesHex"));
  assert(invalidModule["elf"]["available"] == true);
  assert(!invalidModule.dump().empty());
  Fixture newline("ambiguous\nnewline.so"); newline.map();
  auto newlineModule = newline.module(newline.index());
  if (newlineModule["elf"]["available"] == true) assert(newlineModule["file"]["openedVia"] == "map-files");
  else assert(newlineModule["file"]["available"] == false);
}

void numericalAndLimits() {
  Fixture fixture("fixed.so", true);
  fixture.map();
  auto map = fixture.snapshot();
  Json only = {{"available", true}, {"coverage", "complete"}, {"regions", Json::array()}};
  for (const auto& item : map["regions"]) if (item["inodeDecimal"] == fixture.inode()) only["regions"].push_back(item);
  assert(only["regions"].size() == 2);
  const auto original = std::stoull(only["regions"][0]["startAddressHex"].get<std::string>(), nullptr, 16);
  for (auto& item : only["regions"]) {
    for (const auto* field : {"startAddressHex", "endAddressHex"}) {
      auto address = std::stoull(item[field].get<std::string>(), nullptr, 16);
      item[field] = hex(address - original + 0x20000000000000ULL);
    }
  }
  auto high = fixture.module(phantom::inspectRuntimeModules(::getpid(), only));
  assert(high["instances"].size() == 1);
  assert(high["instances"][0]["loadBiasHex"] == "0x1fffffffc00000");
  assert(high["instances"][0]["coverage"] == "partial");
  for (auto& item : only["regions"]) for (const auto* field : {"startAddressHex", "endAddressHex"}) {
    auto address = std::stoull(item[field].get<std::string>(), nullptr, 16);
    item[field] = hex(address - 0x20000000000000ULL + 0x10000);
  }
  auto negative = fixture.module(phantom::inspectRuntimeModules(::getpid(), only));
  assert(negative["instances"][0]["loadBiasHex"] == "-0x3f0000");
  assert(negative["instances"][0]["segments"][0]["startAddressHex"] == "0x10000");
  only["coverage"] = "truncated";
  assert(phantom::inspectRuntimeModules(::getpid(), only)["coverage"] == "truncated");
  only["regions"][0]["startAddressHex"] = "0x10000000000000000";
  assert(phantom::inspectRuntimeModules(::getpid(), only)["reason"] == "invalid-maps");

  phantom::ModuleInspectionLimits limits;
  limits.maxModules = 0;
  auto result = fixture.index(limits);
  assert(result["coverage"] == "truncated" && result["modules"].empty());
  limits = {}; limits.maxMetadataBytes = 0;
  result = fixture.index(limits);
  assert(result["coverage"] == "truncated");
  assert(fixture.module(result)["elf"]["reason"] == "metadata-limit");
  limits = {}; limits.maxInstancesPerModule = 0;
  assert(fixture.module(fixture.index(limits))["instances"].empty());
  limits = {}; limits.maxMappedRanges = 0;
  result = fixture.index(limits);
  assert(result["coverage"] == "truncated");
  limits = {}; limits.maxMatchOperations = 1;
  assert(fixture.index(limits)["coverage"] == "truncated");
  limits = {}; limits.maxRegions = 1;
  assert(fixture.index(limits)["coverage"] == "truncated");
  limits = {}; limits.maxSegmentsPerModule = 1;
  assert(fixture.module(fixture.index(limits))["elf"]["reason"] == "program-header-limit");
  const auto huge = std::numeric_limits<std::size_t>::max();
  limits = {huge, huge, huge, huge, huge, huge, huge};
  assert(fixture.module(fixture.index(limits))["elf"]["available"] == true);
}

void fdInspection() {
  Fixture fixture;
  std::size_t readBytes = 0;
  assert(::lseek(fixture.fd, 37, SEEK_SET) == 37);
  auto result = phantom::inspectElfFd(fixture.fd, {}, &readBytes);
  assert(result["available"] == true && readBytes == 64 + 2 * 56);
  assert(::lseek(fixture.fd, 0, SEEK_CUR) == 37);
  phantom::ElfInspectionLimits limits; limits.maxMetadataBytes = 64 + 56;
  result = phantom::inspectElfFd(fixture.fd, limits, &readBytes);
  assert(result["reason"] == "metadata-limit" && readBytes == 64 + 56);
  assert(::fcntl(fixture.fd, F_GETFD) >= 0); // borrowed fd stays open on failure
  limits.maxFileBytes = 1;
  assert(phantom::inspectElfFd(fixture.fd, limits, &readBytes)["reason"] == "file-limit");
  assert(::fcntl(fixture.fd, F_GETFD) >= 0);
  assert(phantom::inspectElfFd(-1, {}, &readBytes)["available"] == false && readBytes == 0);
  int descriptors[2]; assert(::pipe(descriptors) == 0);
  assert(phantom::inspectElfFd(descriptors[0])["reason"] == "not-regular-file");
  assert(::fcntl(descriptors[0], F_GETFD) >= 0);
  assert(::close(descriptors[0]) == 0 && ::close(descriptors[1]) == 0);
}

void unavailableEvidence() {
  Fixture fixture;
  fixture.map();
  const auto original = fixture.index();
  assert(fixture.module(original)["elf"]["available"] == true);
  // The mapped inode can be modified in place. We deliberately describe file
  // metadata only; stale COW pages never turn that into a memory content hash.
  assert(::pwrite(fixture.fd, "X", 1, 0) == 1);
  const auto changed = fixture.index();
  const auto& module = fixture.module(changed);
  assert(module["file"]["identityVerified"] == true);
  assert(module["contentIdentity"] == "file-metadata-only");
  assert(module["elf"]["reason"] == "not-elf");
  assert(module["instances"].empty() && !module["mappedRegions"].empty());
  assert(!module["unassignedRegionStarts"].empty());
  assert(changed["coverage"] == "partial");
  assert(fixture.module(original)["elf"]["available"] == true);
  const auto descriptorCount = [] {
    std::size_t count = 0;
    for (const auto& item : std::filesystem::directory_iterator("/proc/self/fd")) {
      (void)item; ++count;
    }
    return count;
  };
  const auto count = descriptorCount();
  for (unsigned i = 0; i < 8; ++i) assert(fixture.index()["available"] == true);
  assert(count == descriptorCount());
  const auto child = ::fork(); assert(child >= 0);
  if (child == 0) ::_exit(0);
  int status = 0; assert(::waitpid(child, &status, 0) == child);
  auto exited = phantom::inspectRuntimeModules(child, fixture.snapshot());
  assert(exited["available"] == false && exited["reason"] == "process-unavailable");
}

void dynamicLoading(const char* path) {
  struct stat st{}; assert(::stat(path, &st) == 0);
  const auto inode = std::to_string(st.st_ino);
  const auto matching = [&inode](const Json& modules) -> const Json* {
    for (const auto& module : modules["modules"])
      if (module["inodeDecimal"] == inode) return &module;
    return nullptr;
  };
  const auto inspect = [] {
    return phantom::inspectRuntimeModules(::getpid(), phantom::readLinuxMemoryMap(::getpid()));
  };
  assert(!matching(inspect()));
  void* handle = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
  assert(handle);
  auto* address = ::dlsym(handle, "phantomModuleFixture");
  assert(address);
  // POSIX specifies the dlsym function-pointer conversion for this API.
  auto function = reinterpret_cast<int (*)()>(address);
  assert(function() == 42);
  const auto loaded = inspect();
  const auto* module = matching(loaded);
  assert(module && (*module)["file"]["identityVerified"] == true);
  assert((*module)["elf"]["available"] == true && (*module)["elf"]["elfType"] == "ET_DYN");
  assert((*module)["instances"].size() == 1);
  assert((*module)["instances"][0]["coverage"] == "complete");
  assert((*module)["unassignedRegionStarts"].empty());
  bool functionMapped = false, bssMapped = false;
  const auto pc = reinterpret_cast<std::uintptr_t>(address);
  for (const auto& segment : (*module)["instances"][0]["segments"]) {
    auto start = std::stoull(segment["startAddressHex"].get<std::string>(), nullptr, 16);
    auto end = std::stoull(segment["endAddressHex"].get<std::string>(), nullptr, 16);
    if (start <= pc && pc < end) {
      assert(segment["flags"]["execute"] == true);
      functionMapped = true;
    }
    for (const auto& range : segment["mappedRanges"])
      if (range["backing"] == "anonymous") bssMapped = true;
  }
  assert(functionMapped && bssMapped);
  assert(::dlclose(handle) == 0);
  assert(!matching(inspect()));
  assert(matching(loaded)); // Retained snapshot is still valid historical data.
}
#endif
}  // namespace

int main(int argc, char** argv) {
#ifdef __linux__
  actualMappings();
  identityAndNames();
  numericalAndLimits();
  fdInspection();
  unavailableEvidence();
  assert(argc == 2);
  dynamicLoading(argv[1]);
  assert(phantom::inspectRuntimeModules(0, Json::object())["reason"] == "invalid-process");
  assert(phantom::inspectRuntimeModules(::getpid(), {{"available", false}})["reason"] == "maps-unavailable");
  assert(phantom::inspectRuntimeModules(::getpid(), {{"available", true}, {"coverage", "complete"},
    {"regions", nullptr}})["reason"] == "invalid-maps");
#endif
  (void)argc; (void)argv;
  std::cout << "runtime module map tests passed\n";
}
