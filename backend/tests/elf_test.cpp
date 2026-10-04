#include "phantom/elf.hpp"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using Json = nlohmann::json;

void word(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned width) {
  assert(offset + width <= bytes.size());
  for (unsigned i = 0; i < width; ++i) bytes[offset + i] = static_cast<char>((value >> (8 * i)) & 255);
}

std::string fixture(std::uint16_t type = 2) {
  std::string bytes(512, '\0');
  bytes.replace(0, 4, "\177ELF", 4);
  word(bytes, 4, 2, 1); word(bytes, 5, 1, 1); word(bytes, 6, 1, 1);
  word(bytes, 16, type, 2); word(bytes, 18, 62, 2); word(bytes, 20, 1, 4);
  word(bytes, 24, 0x401000, 8); word(bytes, 32, 64, 8);
  word(bytes, 52, 64, 2); word(bytes, 54, 56, 2); word(bytes, 56, 2, 2);
  word(bytes, 64, 1, 4); word(bytes, 68, 5, 4);
  word(bytes, 80, 0x400000, 8); word(bytes, 96, bytes.size(), 8);
  word(bytes, 104, 4096, 8); word(bytes, 112, 4096, 8);
  // GNU build ID: byte order and embedded zero bytes must be preserved.
  word(bytes, 120, 4, 4); word(bytes, 128, 256, 8); word(bytes, 152, 20, 8);
  word(bytes, 168, 4, 8);
  word(bytes, 256, 4, 4); word(bytes, 260, 4, 4); word(bytes, 264, 3, 4);
  bytes.replace(268, 4, "GNU\0", 4); bytes.replace(272, 4, "\0\xff\x80\x01", 4);
  return bytes;
}

class FixtureFile {
 public:
  FixtureFile() {
#ifdef __linux__
    char name[] = "/tmp/phantom-elf-test-XXXXXX";
    const int fd = ::mkstemp(name);
    assert(fd >= 0 && ::close(fd) == 0);
    path = name;
#endif
  }
  ~FixtureFile() { std::error_code error; std::filesystem::remove(path, error); }
  Json inspect(const std::string& bytes, const phantom::ElfInspectionLimits& limits = {}) {
    { std::ofstream file(path, std::ios::binary | std::ios::trunc);
      file.write(bytes.data(), static_cast<std::streamsize>(bytes.size())); assert(file.good()); }
    return phantom::inspectElf(path, limits);
  }
  std::filesystem::path path;
};

void rejected(FixtureFile& file, const std::string& bytes, const std::string& reason,
              const phantom::ElfInspectionLimits& limits = {}) {
  const auto result = file.inspect(bytes, limits);
  assert(result["available"] == false);
  assert(result["reason"] == reason);
  assert(result.contains("detail") && !result["detail"].get<std::string>().empty());
  assert(!result.contains("elfType") && !result.contains("programHeaders"));
}

void parserTests() {
  FixtureFile file;
  const auto bytes = fixture();
  const auto result = file.inspect(bytes);
  assert(result["available"] == true && result["format"] == "ELF");
  assert(result["class"] == 64 && result["endianness"] == "little");
  assert(result["elfType"] == "ET_EXEC" && result["elfTypeValue"] == 2);
  assert(result["architecture"] == "x86_64" && result["machine"] == 62);
  assert(result["entryAddressHex"] == "0x401000" && result["buildId"] == "00ff8001");
  assert(result["programHeaders"].size() == 1);
  const auto& segment = result["programHeaders"][0];
  assert(segment["type"] == "PT_LOAD" && segment["index"] == 0);
  assert(segment["offsetHex"] == "0x0" && segment["virtualAddressHex"] == "0x400000");
  assert(segment["fileSizeHex"] == "0x200" && segment["memorySizeHex"] == "0x1000");
  assert(segment["alignmentHex"] == "0x1000");
  assert(segment["flags"]["read"] == true && segment["flags"]["write"] == false);
  assert(segment["flags"]["execute"] == true);
  assert(file.inspect(fixture(3))["elfType"] == "ET_DYN");
  assert(file.inspect(fixture(1))["elfType"] == "ET_REL");
  assert(file.inspect(fixture(4))["elfType"] == "ET_CORE");
  assert(file.inspect(fixture(0xfe00))["elfType"] == "unknown");

  auto edit = bytes;
  word(edit, 18, 183, 2);
  auto foreign = file.inspect(edit);
  assert(foreign["available"] == true && foreign["architecture"] == "unsupported" && foreign["machine"] == 183);
  edit = bytes; word(edit, 120, 0x6474e551, 4); word(edit, 124, 6, 4);
  assert(file.inspect(edit)["programHeaders"][1]["type"] == "PT_GNU_STACK");
  edit = bytes; word(edit, 120, 0x6474e552, 4);
  assert(file.inspect(edit)["programHeaders"][1]["type"] == "PT_GNU_RELRO");
  edit = bytes; word(edit, 120, 3, 4); word(edit, 152, 12, 8);
  edit.replace(256, 12, "/lib/ld.so\0\0", 12);
  // An internal terminator is not an accepted single interpreter pathname.
  rejected(file, edit, "malformed");
  word(edit, 152, 13, 8); edit.replace(256, 13, "/lib/ld.so.1\0", 13);
  assert(file.inspect(edit)["programHeaders"][1]["type"] == "PT_INTERP");
  edit[268] = 'x'; rejected(file, edit, "malformed");
  word(edit, 152, 1, 8); rejected(file, edit, "malformed");

  edit = bytes; word(edit, 120, 0, 4);
  for (std::size_t i = 124; i < 176; ++i) edit[i] = '\xff';
  assert(file.inspect(edit)["available"] == true);  // PT_NULL ignores arbitrary members.
  assert(file.inspect(edit)["buildId"].is_null());
  edit = fixture(1); word(edit, 56, 0, 2); word(edit, 32, 0, 8);
  assert(file.inspect(edit)["programHeaders"].empty());
  word(edit, 16, 2, 2); rejected(file, edit, "malformed");

  // Check every truncation of all mandatory header/table bytes.
  for (std::size_t n = 0; n < 176; ++n) rejected(file, bytes.substr(0, n), "truncated");
  edit = bytes; edit[0] = '!'; rejected(file, edit, "not-elf");
  edit = bytes; edit[4] = 1; rejected(file, edit, "unsupported-class");
  edit = bytes; edit[5] = 2; rejected(file, edit, "unsupported-endianness");
  edit = bytes; edit[6] = 0; rejected(file, edit, "malformed");
  edit = bytes; word(edit, 20, 2, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 52, 63, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 54, 55, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 32, 16, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 56, 0xffff, 2); rejected(file, edit, "unsupported-extended-numbering");
  edit = bytes; word(edit, 32, UINT64_MAX - 31, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, 72, UINT64_MAX - 8, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, 96, UINT64_MAX, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, 80, UINT64_MAX - 4095, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 104, 511, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 112, 7, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 80, 0x400001, 8); rejected(file, edit, "malformed");
  // Preserve addresses above JavaScript's exact integer range as hex strings.
  edit = bytes; word(edit, 80, 0x20000000001000, 8);
  assert(file.inspect(edit)["programHeaders"][0]["virtualAddressHex"] == "0x20000000001000");

  edit = bytes; word(edit, 256, UINT32_MAX, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 260, UINT32_MAX, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 260, 0, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 152, 11, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 152, 23, 8);  // zero trailing alignment bytes
  assert(file.inspect(edit)["buildId"] == "00ff8001");
  edit[278] = 'x'; rejected(file, edit, "malformed");
  edit = bytes; word(edit, 152, 40, 8); edit.replace(276, 20, bytes.substr(256, 20));
  assert(file.inspect(edit)["buildId"] == "00ff8001");
  edit[295] = '\x02'; rejected(file, edit, "malformed");
  edit = bytes; edit.replace(268, 4, "ABC\0", 4);
  assert(file.inspect(edit)["buildId"].is_null());
  // An eight-byte note starts its descriptor after align(12 + nameSize).
  // Aligning nameSize alone would produce an incorrect descriptor offset.
  edit = bytes; word(edit, 168, 8, 8); word(edit, 152, 48, 8);
  edit.replace(280, 20, bytes.substr(256, 20));
  assert(file.inspect(edit)["buildId"] == "00ff8001");
  word(edit, 168, 16, 8); rejected(file, edit, "unsupported-note-alignment");
  edit = bytes; word(edit, 168, 0, 8);
  assert(file.inspect(edit)["buildId"] == "00ff8001");
}

void limitTests() {
  FixtureFile file;
  const auto bytes = fixture();
  phantom::ElfInspectionLimits limits;
  limits.maxFileBytes = bytes.size() - 1; rejected(file, bytes, "file-limit", limits);
  limits.maxFileBytes = bytes.size(); assert(file.inspect(bytes, limits)["available"] == true);
  limits = {}; limits.maxProgramHeaders = 1; rejected(file, bytes, "program-header-limit", limits);
  limits.maxProgramHeaders = 0; rejected(file, bytes, "program-header-limit", limits);
  limits = {}; limits.maxNoteBytes = 19; rejected(file, bytes, "note-limit", limits);
  limits.maxNoteBytes = 20; assert(file.inspect(bytes, limits)["available"] == true);
  limits = {}; limits.maxBuildIdBytes = 3; rejected(file, bytes, "build-id-limit", limits);
  limits.maxBuildIdBytes = 4; assert(file.inspect(bytes, limits)["available"] == true);
  const auto huge = std::numeric_limits<std::size_t>::max();
  assert(file.inspect(bytes, {huge, huge, huge, huge})["available"] == true);
  auto edit = bytes; word(edit, 56, 4097, 2);
  rejected(file, edit, "program-header-limit", {huge, huge, huge, huge});
  // Cumulative note budget, not just a per-segment budget.
  edit = bytes; word(edit, 56, 3, 2); edit.replace(176, 56, bytes.substr(120, 56));
  limits = {}; limits.maxNoteBytes = 39; rejected(file, edit, "note-limit", limits);
  limits.maxNoteBytes = 40; assert(file.inspect(edit, limits)["available"] == true);
}

void fileTests(const std::filesystem::path& self) {
  const auto actual = phantom::inspectElf(self);
  assert(actual["available"] == true && actual["architecture"] == "x86_64");
  assert(actual["elfType"] == "ET_EXEC" || actual["elfType"] == "ET_DYN");
  assert(!actual["programHeaders"].empty());
  FixtureFile file;
  assert(std::filesystem::remove(file.path));
  assert(phantom::inspectElf(file.path)["reason"] == "file-unavailable");
#ifdef __linux__
  assert(::mkfifo(file.path.c_str(), 0600) == 0);
  assert(phantom::inspectElf(file.path)["reason"] == "not-regular-file");
#endif
  assert(phantom::inspectElf(file.path.parent_path())["reason"] == "not-regular-file");
}

}  // namespace

int main(int argc, char** argv) {
  assert(argc > 0);
  parserTests();
  limitTests();
  fileTests(argv[0]);
}
