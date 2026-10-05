#include "phantom/runtime_helper.hpp"
#include "phantom/process.hpp"
#include "phantom/sha256.hpp"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

std::string read(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  assert(file.good());
  return std::string(std::istreambuf_iterator<char>(file), {});
}

void write(const std::filesystem::path& path, const std::string& text) {
  std::ofstream file(path, std::ios::binary);
  file << text;
  file.close();
  assert(file.good());
}

void rejected(const std::function<void()>& action) {
  bool threw = false;
  try { action(); } catch (const std::exception&) { threw = true; }
  assert(threw);
}

std::uint64_t number(const std::string& bytes, std::size_t at, std::size_t width) {
  assert(at <= bytes.size() && width <= bytes.size() - at && width <= 8);
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < width; ++i)
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[at + i])) << (i * 8);
  return value;
}

void number(std::string& bytes, std::size_t at, std::size_t width, std::uint64_t value) {
  assert(at <= bytes.size() && width <= bytes.size() - at && width <= 8);
  for (std::size_t i = 0; i < width; ++i) bytes[at + i] = static_cast<char>(value >> (i * 8));
}

std::string name(const std::string& bytes, std::size_t at) {
  assert(at < bytes.size());
  const auto end = bytes.find('\0', at);
  assert(end != std::string::npos);
  return bytes.substr(at, end - at);
}

class Fixture final {
 public:
  Fixture() {
    char pattern[] = "/tmp/phantom-runtime-helper-test-XXXXXX";
    assert(::mkdtemp(pattern));
    directory = pattern;
    source = directory / "main with spaces.cpp";
    write(source, "int main() { return 0; }\n");
    helper = phantom::writeRuntimeHelperSource(directory, {"main with spaces.cpp"});
  }
  ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
  phantom::ProcessOutput build(const std::string& compiler, const std::vector<std::string>& flags = {}) {
    std::vector<std::string> arguments = {compiler, "-std=c++20", "-g", "-O2", "-Wall", "-Werror", "-fno-pie", "-no-pie"};
    arguments.insert(arguments.end(), flags.begin(), flags.end());
    arguments.push_back(source.string());
    phantom::appendRuntimeHelperArguments(arguments, helper);
    arguments.push_back("-o");
    arguments.push_back((directory / "program").string());
    phantom::ProcessOptions options;
    options.argv = std::move(arguments);
    auto process = phantom::Process::spawn(options);
    process.close_stdin();
    return process.wait(std::chrono::steady_clock::now() + std::chrono::seconds(10));
  }
  std::filesystem::path directory, source, helper;
};

void preparationTests() {
  Fixture fixture;
  assert(read(fixture.helper) == phantom::runtimeHelperSource());
  assert(phantom::runtimeHelperSha256() == phantom::sha256_hex(phantom::runtimeHelperSource()));
  assert(phantom::runtimeHelperSha256().size() == 64);
  for (const auto* path : {".phantom-runtime-v1", ".phantom-runtime-v1/user.cpp",
                          "dir/../.phantom-runtime-v1/syscall-v1.s", "../outside.cpp", "/absolute.cpp"})
    rejected([&] { (void)phantom::writeRuntimeHelperSource(fixture.directory, {path}); });
  (void)phantom::writeRuntimeHelperSource(fixture.directory, {".phantom-runtime-v1-other.cpp"});

  const auto user = fixture.directory / "user-source.cpp";
  write(user, "user-owned file\n");
  std::filesystem::remove(fixture.helper);
  std::filesystem::create_symlink(user, fixture.helper);
  rejected([&] { (void)phantom::writeRuntimeHelperSource(fixture.directory, {}); });
  assert(read(user) == "user-owned file\n");
  std::filesystem::remove(fixture.helper);
  std::filesystem::create_hard_link(user, fixture.helper);
  (void)phantom::writeRuntimeHelperSource(fixture.directory, {});
  assert(read(user) == "user-owned file\n");
  assert(read(fixture.helper) == phantom::runtimeHelperSource());
  std::filesystem::remove_all(fixture.helper.parent_path());
  const auto other = fixture.directory / "other-directory";
  std::filesystem::create_directory(other);
  std::filesystem::create_directory_symlink(other, fixture.helper.parent_path());
  rejected([&] { (void)phantom::writeRuntimeHelperSource(fixture.directory, {}); });
  assert(std::filesystem::is_empty(other));

  std::vector<std::string> arguments = {"c++", "-O2", "main.cpp"};
  phantom::appendRuntimeHelperArguments(arguments, "/tmp/private helper.s");
  assert((arguments == std::vector<std::string>{"c++", "-O2", "main.cpp", "-x", "assembler",
      "/tmp/private helper.s", "-Wl,--undefined=__phantom_runtime_syscall_v1"}));
  for (const auto* flag : {"-Wl,--allow-multiple-definition", "-Wl,-z,muldefs", "muldefs"}) {
    arguments = {"c++", flag, "main.cpp"};
    rejected([&] { phantom::appendRuntimeHelperArguments(arguments, "/tmp/helper.s"); });
  }
}

void artifactTests() {
  Fixture fixture;
  auto result = fixture.build("c++", {"-ffunction-sections", "-Wl,--gc-sections"});
  assert(result.exit && result.exit->exit_code == 0);
  const auto original = read(fixture.directory / "program");
  const auto manifest = phantom::verifyRuntimeHelperArtifact(original);
  assert(manifest.size() == 5);
  assert(manifest["profile"] == phantom::runtimeHelperProfile);
  assert(manifest["symbol"] == phantom::runtimeHelperSymbol);
  assert(manifest["bytesHex"] == "0f05cc");
  assert(manifest["helperSha256"] == phantom::runtimeHelperSha256());

  // Mutate actual linker output, preserving unrelated metadata. These cases
  // distinguish actual bytes/ELF ownership from a plausible symbol name.
  const auto sectionTable = number(original, 40, 8);
  const auto sectionCount = number(original, 60, 2);
  const auto sectionNamesIndex = number(original, 62, 2);
  const auto sectionNames = number(original, sectionTable + sectionNamesIndex * 64 + 24, 8);
  std::size_t helperSection = 0, helperSymbol = 0, helperOffset = 0, duplicateSymbol = 0;
  for (std::size_t i = 1; i < sectionCount; ++i) {
    const auto at = sectionTable + i * 64;
    if (name(original, sectionNames + number(original, at, 4)) == ".phantom.runtime.v1") {
      helperSection = at;
      helperOffset = number(original, at + 24, 8);
    }
    if (number(original, at + 4, 4) != 2) continue;
    const auto stringsIndex = number(original, at + 40, 4);
    const auto strings = number(original, sectionTable + stringsIndex * 64 + 24, 8);
    const auto symbols = number(original, at + 24, 8);
    const auto count = number(original, at + 32, 8) / 24;
    for (std::size_t j = 1; j < count; ++j) {
      const auto entry = symbols + j * 24;
      if (name(original, strings + number(original, entry, 4)) == phantom::runtimeHelperSymbol)
        helperSymbol = entry;
      else if (duplicateSymbol == 0 && (number(original, entry + 4, 1) >> 4) != 0)
        duplicateSymbol = entry;
    }
  }
  assert(helperSection && helperSymbol && helperOffset && duplicateSymbol);
  {
    auto bytes = original;
    // Another global symbol retains a valid symbol-table position but now
    // repeats the reserved name and definition: matching bytes are not enough.
    bytes.replace(duplicateSymbol, 24, original.substr(helperSymbol, 24));
    rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(bytes); });
  }
  const auto failWord = [&](std::size_t at, std::size_t width, std::uint64_t value) {
    auto bytes = original;
    number(bytes, at, width, value);
    rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(bytes); });
  };
  failWord(4, 1, 1);  // ELF32.
  failWord(5, 1, 2);  // Big-endian.
  failWord(16, 2, 3);  // ET_DYN.
  failWord(18, 2, 183);  // AArch64 despite request architecture.
  failWord(helperSymbol + 4, 1, 0x22);  // Weak function.
  failWord(helperSymbol + 4, 1, 0x1a);  // IFUNC resolver.
  failWord(helperSymbol + 5, 1, 0);  // Interposable symbol.
  failWord(helperSymbol + 6, 2, 0xfff1);  // Absolute, not a section definition.
  failWord(helperSymbol + 16, 8, 2);  // Wrong extent.
  failWord(helperSymbol + 8, 8, number(original, helperSymbol + 8, 8) + 1);
  failWord(helperSection + 4, 4, 8);  // NOBITS cannot carry instructions.
  failWord(helperSection + 8, 8, 7);  // Writable executable section.
  failWord(helperSection + 8, 8, 2);  // Non-executable section.
  failWord(helperSection + 8, 8, 0x406);  // TLS.
  failWord(helperSection + 8, 8, 0x806);  // Compressed.
  failWord(helperSection + 32, 8, 4);  // User content in reserved section.
  failWord(helperSection + 48, 8, 1);  // Wrong alignment.
  failWord(helperSection + 24, 8, helperOffset + 1);  // Segment/section disagreement.
  failWord(helperOffset, 1, 0x90);  // Changed machine instruction.

  const auto programTable = number(original, 32, 8);
  const auto programCount = number(original, 56, 2);
  const auto helperAddress = number(original, helperSymbol + 8, 8);
  std::size_t helperLoad = 0;
  for (std::size_t i = 0; i < programCount; ++i) {
    const auto at = programTable + i * 56;
    const auto base = number(original, at + 16, 8), size = number(original, at + 40, 8);
    if (number(original, at, 4) == 1 && base <= helperAddress && helperAddress - base < size)
      helperLoad = at;
  }
  assert(helperLoad != 0);
  failWord(helperLoad + 4, 4, 7);  // RWX load despite an RX section.
  failWord(helperLoad + 4, 4, 4);  // R-only load despite an RX section.
  {
    auto bytes = original;
    // A second PT_LOAD covering the same bytes creates ambiguous runtime
    // ownership even if both copies report read/execute permissions.
    const auto otherHeader = helperLoad == programTable ? programTable + 56 : programTable;
    bytes.replace(otherHeader, 56, original.substr(helperLoad, 56));
    rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(bytes); });
  }

  result = fixture.build("c++", {"-s"});
  assert(result.exit && result.exit->exit_code == 0);
  rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(read(fixture.directory / "program")); });
  result = fixture.build("c++", {"-fPIE", "-pie"});
  assert(result.exit && result.exit->exit_code == 0);
  rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(read(fixture.directory / "program")); });

  // Defining the reserved symbol in user code must not silently replace the
  // backend-owned helper. The normal linker must report duplicate ownership.
  write(fixture.source, "asm(\".globl __phantom_runtime_syscall_v1\\n__phantom_runtime_syscall_v1: nop\\n\");\nint main(){return 0;}\n");
  result = fixture.build("c++");
  assert(result.exit && result.exit->exit_code != 0);

  rejected([&] { (void)phantom::verifyRuntimeHelperArtifact(""); });
  rejected([&] { (void)phantom::verifyRuntimeHelperArtifact("not an ELF"); });
  std::cout << "runtime helper: source ownership, GC retention and exact ELF manifest checks passed\n";
}

}  // namespace

int main() {
  preparationTests();
  artifactTests();
}
