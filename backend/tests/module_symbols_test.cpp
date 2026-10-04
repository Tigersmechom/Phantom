#include "phantom/module_map.hpp"
#include "phantom/memory_map.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef __linux__
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
using Json = nlohmann::json;
#ifdef __linux__
std::string hex(std::uint64_t value) {
  char bytes[32]; std::snprintf(bytes, sizeof(bytes), "0x%llx", static_cast<unsigned long long>(value));
  return bytes;
}
std::uint64_t number(const Json& value) { return std::stoull(value.get<std::string>(), nullptr, 16); }
void word(std::string& bytes, std::size_t at, std::uint64_t value, unsigned width) {
  assert(at + width <= bytes.size());
  for (unsigned i = 0; i < width; ++i) bytes[at + i] = static_cast<char>(value >> (i * 8));
}
struct Child {
  int pid = -1;
  ~Child() { if (pid > 0) { ::kill(pid, SIGKILL); int status; assert(::waitpid(pid, &status, 0) == pid); } }
  void stopped() const { int status; assert(::waitpid(pid, &status, WUNTRACED) == pid); assert(WIFSTOPPED(status)); }
};
std::string moduleId(int pid, const std::filesystem::path& path) {
  struct stat st{}; assert(::stat(path.c_str(), &st) == 0);
  const auto report = phantom::inspectRuntimeModules(pid, phantom::readLinuxMemoryMap(pid));
  assert(report["available"] == true);
  for (const auto& module : report["modules"])
    if (module["inodeDecimal"] == std::to_string(st.st_ino)) return module["id"].get<std::string>();
  assert(false && "expected mapped module missing"); return {};
}
const Json& symbol(const Json& report, const std::string& name) {
  for (const auto& item : report["symbols"]) if (item["name"] == name) return item;
  std::cerr << "Missing symbol " << name << " in " << report.dump() << '\n';
  std::abort();
}
bool hasAddress(const Json& item, std::uint64_t expected) {
  for (const auto& location : item["runtimeLocations"])
    if (location["status"] == "mapped" && location["addressHex"] == hex(expected)) return true;
  return false;
}

void actualLibrary(const std::filesystem::path& library) {
  int descriptors[2]; assert(::pipe(descriptors) == 0);
  Child child; child.pid = ::fork(); assert(child.pid >= 0);
  if (child.pid == 0) {
    ::close(descriptors[0]);
    auto* handle = ::dlopen(library.c_str(), RTLD_NOW | RTLD_LOCAL); assert(handle);
    auto data = reinterpret_cast<std::uintptr_t>(::dlsym(handle, "phantomSymbolData"));
    auto function = reinterpret_cast<std::uintptr_t>(::dlsym(handle, "phantomSymbolFunction"));
    auto getVptr = reinterpret_cast<void* (*)()>(::dlsym(handle, "phantomSymbolVptr"));
    auto getTls = reinterpret_cast<void* (*)()>(::dlsym(handle, "phantomSymbolTlsAddress"));
    assert(data && function && getVptr && getTls);
    const std::uint64_t addresses[] = {data, function, reinterpret_cast<std::uintptr_t>(getVptr()),
      reinterpret_cast<std::uintptr_t>(getTls())};
    assert(::write(descriptors[1], addresses, sizeof(addresses)) == sizeof(addresses));
    ::close(descriptors[1]);
    ::raise(SIGSTOP);
    assert(::dlclose(handle) == 0);
    ::raise(SIGSTOP);
    _exit(0);
  }
  ::close(descriptors[1]);
  std::uint64_t addresses[4]{};
  assert(::read(descriptors[0], addresses, sizeof(addresses)) == sizeof(addresses));
  ::close(descriptors[0]);
  child.stopped();
  const auto id = moduleId(child.pid, library);
  const auto map = phantom::readLinuxMemoryMap(child.pid);
  const auto report = phantom::inspectRuntimeModuleSymbols(child.pid, map, id);
  if (report["available"] != true) std::cerr << report.dump() << '\n';
  assert(report["available"] == true && report["identityVerified"] == true);
  assert(report["source"] == "linux-proc-maps-elf-symbols" && report["coverage"] == "complete");
  assert(report["module"]["elf"]["elfType"] == "ET_DYN");
  assert(hasAddress(symbol(report, "phantomSymbolData"), addresses[0]));
  assert(hasAddress(symbol(report, "phantomSymbolFunction"), addresses[1]));
  const auto& tls = symbol(report, "phantomSymbolTls");
  assert(tls["runtimeMeaning"] == "tls-offset" && tls["runtimeLocations"].empty());
  bool vtable = false, typeinfo = false, tlsSection = false;
  for (const auto& item : report["symbols"]) {
    if (item["classification"] == "vtable" && item["name"] == "_ZTV20PhantomSymbolFixture") {
      assert(item["classificationEvidence"] == "itanium-mangled-prefix");
      for (const auto& location : item["runtimeLocations"])
        if (location["status"] == "mapped" && number(location["addressHex"]) <= addresses[2] &&
            addresses[2] < number(location["endAddressHex"])) vtable = true;
    }
    if (item["classification"] == "typeinfo" && !item["runtimeLocations"].empty()) typeinfo = true;
  }
  for (const auto& section : report["sections"]) if (section["flags"]["tls"] == true) {
    assert(section["runtimeLocations"].empty() && section["runtimeReason"] == "tls-requires-thread-address");
    tlsSection = true;
  }
  assert(vtable && typeinfo && tlsSection);
  assert(phantom::inspectRuntimeModuleSymbols(child.pid, map, "module:missing")["reason"] == "module-not-mapped");
  auto tampered = map; tampered["regions"][0]["permissions"] = "---p";
  assert(phantom::inspectRuntimeModuleSymbols(child.pid, tampered, id)["reason"] == "maps-changed");
  phantom::ModuleSymbolInspectionLimits limits;
  limits.maxMetadataBytes = 0;
  assert(phantom::inspectRuntimeModuleSymbols(child.pid, map, id, limits)["available"] == false);
  limits = {}; limits.maxSymbols = 1;
  auto capped = phantom::inspectRuntimeModuleSymbols(child.pid, map, id, limits);
  assert(capped["available"] == true && capped["coverage"] == "truncated" && capped["symbols"].size() == 1);
  limits = {}; limits.maxRuntimeLocations = 0;
  capped = phantom::inspectRuntimeModuleSymbols(child.pid, map, id, limits);
  assert(capped["coverage"] == "truncated");
  assert(symbol(capped, "phantomSymbolData")["runtimeReason"] == "inspection-limit");
  // A retained JSON snapshot stays a historical fact after dlclose, whereas a
  // new capture using old maps/IDs cannot fabricate a current live overlay.
  assert(::kill(child.pid, SIGCONT) == 0); child.stopped();
  assert(phantom::inspectRuntimeModuleSymbols(child.pid, map, id)["reason"] == "maps-changed");
  const auto removed = phantom::inspectRuntimeModuleSymbols(child.pid, phantom::readLinuxMemoryMap(child.pid), id);
  assert(removed["reason"] == "module-not-mapped");
  assert(hasAddress(symbol(report, "phantomSymbolData"), addresses[0]));
}

std::string syntheticElf() {
  constexpr std::uint64_t base = 0x400000;
  std::string bytes(8192, '\0');
  bytes.replace(0, 4, "\177ELF", 4);
  word(bytes, 4, 2, 1); word(bytes, 5, 1, 1); word(bytes, 6, 1, 1);
  word(bytes, 16, 2, 2); word(bytes, 18, 62, 2); word(bytes, 20, 1, 4);
  word(bytes, 32, 64, 8); word(bytes, 40, 0x1000, 8);
  word(bytes, 52, 64, 2); word(bytes, 54, 56, 2); word(bytes, 56, 1, 2);
  word(bytes, 58, 64, 2); word(bytes, 60, 9, 2); word(bytes, 62, 6, 2);
  word(bytes, 64, 1, 4); word(bytes, 68, 7, 4); word(bytes, 80, base, 8);
  word(bytes, 96, bytes.size(), 8); word(bytes, 104, bytes.size(), 8); word(bytes, 112, 4096, 8);
  std::string names(1, '\0');
  const auto name = [&](const char* text) { const auto offset = names.size(); names += text; names += '\0'; return offset; };
  const auto section = [&](std::size_t index, const char* text, unsigned type, std::uint64_t flags,
                           std::uint64_t offset, std::uint64_t address, std::uint64_t size,
                           unsigned link = 0, std::uint64_t entrySize = 0) {
    const auto at = 0x1000 + index * 64;
    word(bytes, at, name(text), 4); word(bytes, at + 4, type, 4); word(bytes, at + 8, flags, 8);
    word(bytes, at + 16, address, 8); word(bytes, at + 24, offset, 8); word(bytes, at + 32, size, 8);
    word(bytes, at + 40, link, 4); word(bytes, at + 48, 1, 8); word(bytes, at + 56, entrySize, 8);
  };
  section(1, ".text", 1, 6, 0x200, base + 0x200, 0x100);
  section(2, ".data", 1, 3, 0x400, base + 0x400, 0x100);
  section(3, ".tdata", 1, 0x403, 0x500, base + 0x500, 0x10);
  section(4, ".symtab", 2, 0, 0x800, 0, 12 * 24, 5, 24);
  word(bytes, 0x1000 + 4 * 64 + 44, 1, 4);
  std::string strings(1, '\0');
  const auto sym = [&](std::size_t index, const char* text, unsigned type, unsigned sectionIndex,
                       std::uint64_t value, std::uint64_t size) {
    const auto offset = strings.size(); strings += text; strings += '\0';
    const auto at = 0x800 + index * 24;
    word(bytes, at, offset, 4); word(bytes, at + 4, 0x10 | type, 1); word(bytes, at + 6, sectionIndex, 2);
    word(bytes, at + 8, value, 8); word(bytes, at + 16, size, 8);
  };
  sym(1, "data", 1, 2, base + 0x400, 4); sym(2, "tls", 6, 3, 0, 4);
  sym(3, "absolute", 0, 0xfff1, 0x1234, 0); sym(4, "common", 5, 0xfff2, 8, 4);
  sym(5, "undefined", 2, 0, 0, 0); sym(6, "resolver", 10, 1, base + 0x200, 4);
  sym(7, "point", 0, 2, base + 0x404, 0); sym(8, "outside", 1, 2, base + 0x500, 4);
  sym(9, "overflow", 1, 2, UINT64_MAX - 4, 4);
  sym(10, "far", 1, 8, UINT64_MAX - 15, 8);
  sym(11, "tls-template", 3, 3, base + 0x500, 0);
  section(5, ".strtab", 3, 0, 0xb00, 0, strings.size());
  section(6, ".shstrtab", 3, 0, 0xc00, 0, 0);
  section(7, ".debug_info", 1, 0, 0xd00, 0, 16);
  section(8, ".far", 1, 2, 0xe00, UINT64_MAX - 15, 8);
  word(bytes, 0x1000 + 6 * 64 + 32, names.size(), 8);
  bytes.replace(0xb00, strings.size(), strings); bytes.replace(0xc00, names.size(), names);
  return bytes;
}

void signedBiasAndSpecialValues() {
  char name[] = "/tmp/phantom-module-symbols-XXXXXX";
  const int fd = ::mkstemp(name); assert(fd >= 0);
  const auto bytes = syntheticElf(); assert(::write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
  Child child; child.pid = ::fork(); assert(child.pid >= 0);
  if (child.pid == 0) {
    assert(::mmap(reinterpret_cast<void*>(0x100000), bytes.size(), PROT_READ,
      MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0) == reinterpret_cast<void*>(0x100000));
    assert(::mmap(nullptr, bytes.size(), PROT_READ, MAP_PRIVATE, fd, 0) != MAP_FAILED);
    ::raise(SIGSTOP); _exit(0);
  }
  child.stopped();
  const auto map = phantom::readLinuxMemoryMap(child.pid);
  const auto id = moduleId(child.pid, name);
  const auto report = phantom::inspectRuntimeModuleSymbols(child.pid, map, id);
  if (!report.value("available", false)) std::cerr << report.dump() << '\n';
  assert(report["available"] == true && report["coverage"] == "complete");
  assert(report["module"]["instances"].size() == 2);
  const auto& data = symbol(report, "data"); assert(hasAddress(data, 0x100400));
  assert(data["runtimeLocations"].size() == 2);
  for (const auto* name : {"tls", "absolute", "common", "undefined"}) assert(symbol(report, name)["runtimeLocations"].empty());
  assert(symbol(report, "absolute")["runtimeMeaning"] == "absolute-value");
  const auto& tlsTemplate = symbol(report, "tls-template");
  assert(tlsTemplate["valueKind"] == "virtual-address" && tlsTemplate["valueHex"] == "0x400500");
  assert(tlsTemplate["runtimeMeaning"] == "non-runtime-section");
  assert(tlsTemplate["runtimeReason"] == "tls-requires-thread-address" && tlsTemplate["runtimeLocations"].empty());
  assert(symbol(report, "resolver")["runtimeMeaning"] == "ifunc-resolver");
  assert(hasAddress(symbol(report, "resolver"), 0x100200));
  const auto& point = symbol(report, "point"); assert(hasAddress(point, 0x100404));
  for (const auto& location : point["runtimeLocations"]) {
    assert(location["endAddressHex"] == location["addressHex"] && location["mappedRanges"].empty());
  }
  assert(symbol(report, "outside")["runtimeReason"] == "symbol-outside-section");
  assert(symbol(report, "overflow")["runtimeReason"] == "symbol-outside-section");
  bool overflow = false;
  for (const auto& location : symbol(report, "far")["runtimeLocations"]) {
    assert(location["status"] == "overflow" || location["status"] == "unmapped");
    if (location["status"] == "overflow") { assert(location["addressHex"].is_null()); overflow = true; }
  }
  assert(overflow);
  phantom::ModuleSymbolInspectionLimits limits; limits.maxMatchOperations = 8;
  const auto bounded = phantom::inspectRuntimeModuleSymbols(child.pid, map, id, limits);
  assert(bounded["available"] == true && bounded["coverage"] == "truncated");
  bool unknown = false;
  for (const auto& section : bounded["sections"]) for (const auto& location : section["runtimeLocations"])
    if (location["status"] == "unknown") unknown = true;
  for (const auto& item : bounded["symbols"]) for (const auto& location : item["runtimeLocations"])
    if (location["status"] == "unknown") unknown = true;
  assert(unknown); // Exhausted matching budget must not assert unmapped.
  ::close(fd); assert(::unlink(name) == 0);
}
#endif
}  // namespace

int main(int argc, char** argv) {
#ifdef __linux__
  assert(argc == 2);
  actualLibrary(std::filesystem::absolute(argv[1]));
  signedBiasAndSpecialValues();
  assert(phantom::inspectRuntimeModuleSymbols(-1, {}, "module:x")["reason"] == "invalid-process");
  std::cout << "module symbols: verified runtime addresses, vtables, TLS, stale maps, signed biases and bounds passed\n";
#else
  (void)argc; (void)argv;
#endif
}
