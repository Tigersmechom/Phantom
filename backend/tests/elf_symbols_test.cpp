#include "phantom/elf_symbols.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
using Json = nlohmann::json;

void word(std::string& bytes, std::size_t offset, std::uint64_t value, unsigned width) {
  assert(offset <= bytes.size() && width <= bytes.size() - offset);
  for (unsigned i = 0; i < width; ++i) bytes[offset + i] = static_cast<char>((value >> (8 * i)) & 255);
}

// Null, shstrtab, strtab, symtab, data, bss, tls, dynsym, extended indices.
constexpr std::size_t sectionOffset = 64, sections = 9, namesOffset = 768;
constexpr std::size_t symbolNamesOffset = 1024, symbolsOffset = 1280;
constexpr std::size_t symbolCount = 13, dynamicOffset = 1664, extendedOffset = 1728;
constexpr std::size_t dataOffset = 1792;

std::size_t sh(std::size_t index) { return sectionOffset + index * 64; }
std::size_t sym(std::size_t index) { return symbolsOffset + index * 24; }

void section(std::string& bytes, std::size_t index, std::uint32_t name, std::uint32_t type,
             std::uint64_t flags, std::uint64_t address, std::uint64_t offset, std::uint64_t size,
             std::uint32_t link = 0, std::uint32_t info = 0, std::uint64_t entrySize = 0) {
  const auto at = sh(index);
  word(bytes, at, name, 4); word(bytes, at + 4, type, 4); word(bytes, at + 8, flags, 8);
  word(bytes, at + 16, address, 8); word(bytes, at + 24, offset, 8); word(bytes, at + 32, size, 8);
  word(bytes, at + 40, link, 4); word(bytes, at + 44, info, 4); word(bytes, at + 48, 1, 8);
  word(bytes, at + 56, entrySize, 8);
}

void symbol(std::string& bytes, std::size_t index, std::uint32_t name, unsigned binding,
            unsigned type, std::uint16_t sectionIndex, std::uint64_t value, std::uint64_t size,
            unsigned visibility = 0) {
  const auto at = sym(index);
  word(bytes, at, name, 4); word(bytes, at + 4, binding * 16 + type, 1);
  word(bytes, at + 5, visibility, 1); word(bytes, at + 6, sectionIndex, 2);
  word(bytes, at + 8, value, 8); word(bytes, at + 16, size, 8);
}

std::string fixture() {
  std::string bytes(2048, '\0');
  bytes.replace(0, 4, "\177ELF", 4);
  word(bytes, 4, 2, 1); word(bytes, 5, 1, 1); word(bytes, 6, 1, 1);
  word(bytes, 16, 3, 2); word(bytes, 18, 62, 2); word(bytes, 20, 1, 4);
  word(bytes, 40, sectionOffset, 8); word(bytes, 52, 64, 2);
  word(bytes, 58, 64, 2); word(bytes, 60, sections, 2); word(bytes, 62, 1, 2);
  constexpr char names[] = "\0.shstrtab\0.strtab\0.symtab\0.data\0.bss\0.tdata\0.dynsym\0.symtab_shndx\0";
  const std::string sectionNames(names, sizeof(names) - 1);
  bytes.replace(namesOffset, sectionNames.size(), sectionNames);
  std::string symbolNames(1, '\0');
  std::vector<std::uint32_t> nameIndexes;
  for (const std::string name : {"_ZTV1A", "_ZTI1A", "_ZTS1A", "_ZTT1A", "external", "absolute", "common",
                                "tls", "resolver", "reserved", "bad\xff", "extended"}) {
    nameIndexes.push_back(static_cast<std::uint32_t>(symbolNames.size()));
    symbolNames += name; symbolNames += '\0';
  }
  bytes.replace(symbolNamesOffset, symbolNames.size(), symbolNames);
  section(bytes, 1, 1, 3, 0, 0, namesOffset, sectionNames.size());
  section(bytes, 2, 11, 3, 0, 0, symbolNamesOffset, symbolNames.size());
  section(bytes, 3, 19, 2, 0, 0, symbolsOffset, symbolCount * 24, 2, 1, 24);
  section(bytes, 4, 27, 1, 3, 0x20000000000000, dataOffset, 64);
  // SHT_NOBITS is memory-only; its conceptual file offset need not be in file.
  section(bytes, 5, 33, 8, 3, 0x20000000000100, UINT64_MAX, 1024);
  section(bytes, 6, 38, 1, 0x403, 0x20000000000040, dataOffset + 64, 16);
  section(bytes, 7, 45, 11, 2, 0x20000000000180, dynamicOffset, 48, 2, 1, 24);
  section(bytes, 8, 53, 18, 0, 0, extendedOffset, symbolCount * 4, 3, 0, 4);
  symbol(bytes, 1, nameIndexes[0], 1, 1, 4, 0x20000000000000, 16);
  symbol(bytes, 2, nameIndexes[1], 2, 1, 4, 0x20000000000010, 8, 2);
  symbol(bytes, 3, nameIndexes[2], 10, 1, 4, 0x20000000000018, 8, 3);
  symbol(bytes, 4, nameIndexes[3], 1, 1, 4, 0x20000000000020, 8);
  symbol(bytes, 5, nameIndexes[4], 1, 2, 0, 0, 0);
  symbol(bytes, 6, nameIndexes[5], 1, 0, 0xfff1, UINT64_MAX, 0);
  symbol(bytes, 7, nameIndexes[6], 1, 5, 0xfff2, 16, 4096);
  symbol(bytes, 8, nameIndexes[7], 1, 6, 6, 8, 4);
  symbol(bytes, 9, nameIndexes[8], 1, 10, 4, 0x20000000000028, 8);
  symbol(bytes, 10, nameIndexes[9], 1, 0, 0xff20, 17, 0);
  symbol(bytes, 11, nameIndexes[10], 1, 1, 4, 0x20000000000030, 4);
  symbol(bytes, 12, nameIndexes[11], 1, 1, 0xffff, 0x20000000000034, 4);
  word(bytes, extendedOffset + 12 * 4, 4, 4);
  bytes.replace(dynamicOffset + 24, 24, bytes.substr(sym(5), 24));
  return bytes;
}

class FixtureFile {
 public:
  FixtureFile() {
    char name[] = "/tmp/phantom-elf-symbols-test-XXXXXX";
    fd = ::mkstemp(name); assert(fd >= 0); path = name;
  }
  ~FixtureFile() { ::close(fd); std::error_code error; std::filesystem::remove(path, error); }
  Json inspect(const std::string& bytes, const phantom::ElfSymbolInspectionLimits& limits = {},
               std::size_t* count = nullptr) {
    assert(::ftruncate(fd, 0) == 0);
    assert(::pwrite(fd, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()));
    assert(::lseek(fd, 17, SEEK_SET) == 17);
    auto result = phantom::inspectElfSymbolsFd(fd, limits, count);
    assert(::lseek(fd, 0, SEEK_CUR) == 17);  // borrowed offset and lifetime preserved
    assert(::fcntl(fd, F_GETFD) >= 0);
    result.dump();  // Invalid UTF-8 must never reach JSON strings.
    return result;
  }
  int fd = -1;
  std::filesystem::path path;
};

void rejected(FixtureFile& file, const std::string& bytes, const char* reason) {
  const auto result = file.inspect(bytes);
  assert(result["available"] == false && result["coverage"] == "none");
  assert(result["reason"] == reason);
  assert(result["sections"].empty() && result["symbols"].empty() && result["symbolTables"].empty());
}

void validTests() {
  FixtureFile file;
  const auto bytes = fixture();
  auto result = file.inspect(bytes);
  assert(result["available"] == true && result["coverage"] == "complete");
  assert(result["elfType"] == "ET_DYN" && result["sectionCount"] == sections);
  assert(result["symbolCount"] == symbolCount + 2);
  assert(result["sections"].size() == sections && result["symbols"].size() == symbolCount + 2);
  assert(result["symbolTables"].size() == 2);
  assert(result["sections"][4]["addressHex"] == "0x20000000000000");
  assert(result["sections"][5]["fileBacked"] == false && result["sections"][5]["flags"]["alloc"] == true);
  assert(result["sections"][5]["offsetHex"] == "0xffffffffffffffff");
  const auto& values = result["symbols"];
  assert(values[0]["definition"] == "undefined" && values[0]["name"] == "");
  assert(values[1]["classification"] == "vtable" && values[1]["valueKind"] == "virtual-address");
  assert(values[1]["classificationEvidence"] == "itanium-mangled-prefix");
  assert(values[2]["classification"] == "typeinfo" && values[2]["binding"] == "STB_WEAK");
  assert(values[2]["visibility"] == "STV_HIDDEN");
  assert(values[3]["classification"] == "typeinfo-name" && values[3]["binding"] == "STB_GNU_UNIQUE");
  assert(values[3]["visibility"] == "STV_PROTECTED");
  assert(values[4]["classification"] == "vtt");
  assert(values[5]["definition"] == "undefined" && values[5]["sectionIndex"].is_null());
  assert(values[6]["valueKind"] == "absolute" && values[6]["valueHex"] == "0xffffffffffffffff");
  assert(values[7]["valueKind"] == "common-alignment" && values[7]["valueHex"] == "0x10");
  assert(values[8]["valueKind"] == "tls-offset" && values[8]["type"] == "STT_TLS");
  assert(values[9]["type"] == "STT_GNU_IFUNC" && values[9]["valueKind"] == "virtual-address");
  assert(values[10]["definition"] == "reserved" && values[10]["sectionIndex"].is_null());
  assert(values[11]["name"].is_null() && values[11]["nameBytesHex"] == "626164ff");
  assert(values[12]["sectionIndex"] == 4 && values[12]["rawSectionIndex"] == 65535);
  assert(values[14]["table"] == "dynsym" && values[14]["index"] == 1);

  auto edit = bytes;
  word(edit, 60, 0, 2); word(edit, sh(0) + 32, sections, 8);
  word(edit, 62, 0xffff, 2); word(edit, sh(0) + 40, 1, 4);
  result = file.inspect(edit);
  assert(result["available"] == true && result["sectionCount"] == sections);
  assert(result["sections"][1]["name"] == ".shstrtab");

  edit = bytes; word(edit, 16, 1, 2);
  assert(file.inspect(edit)["symbols"][1]["valueKind"] == "section-offset");
  edit = bytes; word(edit, 16, 2, 2);
  assert(file.inspect(edit)["elfType"] == "ET_EXEC");
  edit = bytes; word(edit, 16, 4, 2);
  assert(file.inspect(edit)["symbols"][1]["valueKind"] == "other");

  // Stripping a table does not make the remaining section metadata unavailable.
  edit = bytes; word(edit, sh(3) + 4, 0, 4); word(edit, sh(8) + 4, 0, 4);
  result = file.inspect(edit);
  assert(result["coverage"] == "complete" && result["symbols"].size() == 2);
  edit = bytes; word(edit, 40, 0, 8); word(edit, 60, 0, 2); word(edit, 62, 0, 2);
  result = file.inspect(edit.substr(0, 64));
  assert(result["available"] == true && result["coverage"] == "complete");
  assert(result["sectionCount"] == 0 && result["symbolCount"] == 0 && result["sections"].empty());

  // Valid substring string offsets, unallocated sections, and empty names.
  edit = bytes; word(edit, sym(1), 2, 4);
  assert(file.inspect(edit)["symbols"][1]["name"] == "ZTV1A");
  assert(file.inspect(edit)["symbols"][1]["classification"].is_null());
  edit = bytes; edit[namesOffset + 1] = '\xff';
  result = file.inspect(edit);
  assert(result["sections"][1]["name"].is_null());
  assert(result["sections"][1]["nameBytesHex"] == "ff7368737472746162");
}

void malformedTests() {
  FixtureFile file;
  const auto bytes = fixture();
  for (std::size_t n = 0; n < 64; ++n) rejected(file, bytes.substr(0, n), "truncated");
  rejected(file, bytes.substr(0, sectionOffset + sections * 64 - 1), "truncated");
  auto edit = bytes; edit[0] = '!'; rejected(file, edit, "not-elf");
  edit = bytes; edit[4] = 1; rejected(file, edit, "unsupported-class");
  edit = bytes; edit[5] = 2; rejected(file, edit, "unsupported-endianness");
  edit = bytes; word(edit, 18, 183, 2); rejected(file, edit, "unsupported-machine");
  for (const auto field : {6, 20, 52}) {
    edit = bytes; word(edit, field, 0, field == 20 ? 4 : field == 52 ? 2 : 1);
    rejected(file, edit, "malformed");
  }
  edit = bytes; word(edit, 40, 0, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 40, 32, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 40, UINT64_MAX - 31, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, 58, 63, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 62, sections, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, 62, 4, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(0) + 4, 1, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(4) + 24, UINT64_MAX, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, sh(4) + 32, UINT64_MAX, 8); rejected(file, edit, "truncated");
  edit = bytes; word(edit, sh(5) + 16, UINT64_MAX - 3, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(4) + 48, 3, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(3) + 40, sections, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(3) + 40, 4, 4); rejected(file, edit, "malformed");
  for (const std::uint64_t size : {0, 23, 25}) {
    edit = bytes; word(edit, sh(3) + 56, size, 8); rejected(file, edit, "malformed");
  }
  edit = bytes; word(edit, sh(3) + 32, symbolCount * 24 - 1, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(3) + 44, 0, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(3) + 44, symbolCount + 1, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sym(0) + 8, 1, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sym(1) + 4, 1, 1); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sym(1) + 6, sections, 2); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sym(1) + 8, UINT64_MAX - 3, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(8) + 4, 0, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, extendedOffset + 12 * 4, sections, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, extendedOffset, 1, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(8) + 56, 8, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(8) + 32, symbolCount * 4 - 4, 8); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(8) + 40, 4, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sym(1), UINT32_MAX, 4); rejected(file, edit, "malformed");
  edit = bytes; edit[symbolNamesOffset] = 'x'; rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(2) + 32, 4, 8); rejected(file, edit, "malformed");
  edit = bytes; edit[namesOffset] = 'x'; rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(4), UINT32_MAX, 4); rejected(file, edit, "malformed");
  edit = bytes; word(edit, sh(3) + 8, 0x800, 8); rejected(file, edit, "unsupported-compression");
  edit = bytes; word(edit, sh(2) + 8, 0x800, 8); rejected(file, edit, "unsupported-compression");
  edit = bytes; word(edit, sh(5) + 8, 0x800, 8); rejected(file, edit, "malformed");
}

void limitsTests() {
  FixtureFile file;
  const auto bytes = fixture();
  phantom::ElfSymbolInspectionLimits limits;
  limits.maxSymbols = 3;
  auto result = file.inspect(bytes, limits);
  assert(result["available"] == true && result["coverage"] == "truncated");
  assert(result["reason"] == "symbol-limit" && result["symbols"].size() == 3);
  assert(result["sections"].size() == sections && result["symbolCount"] == symbolCount + 2);
  limits.maxSymbols = 0;
  result = file.inspect(bytes, limits);
  assert(result["available"] == true && result["symbols"].empty() && result["reason"] == "symbol-limit");
  limits = {}; limits.maxSectionHeaders = sections - 1;
  assert(file.inspect(bytes, limits)["reason"] == "section-header-limit");
  limits = {}; limits.maxMetadataBytes = 63;
  std::size_t readCount = 999;
  result = file.inspect(bytes, limits, &readCount);
  assert(result["available"] == false && result["reason"] == "metadata-limit" && readCount == 0);
  limits.maxMetadataBytes = 64 + 64 + sections * 64;
  result = file.inspect(bytes, limits, &readCount);
  assert(result["available"] == true && result["coverage"] == "truncated");
  assert(result["reason"] == "metadata-limit" && readCount == limits.maxMetadataBytes);
  limits = {}; limits.maxFileBytes = bytes.size() - 1;
  assert(file.inspect(bytes, limits)["reason"] == "file-limit");
  limits = {}; limits.maxNameBytes = 4;
  result = file.inspect(bytes, limits);
  assert(result["available"] == true && result["coverage"] == "truncated" && result["reason"] == "name-limit");
  assert(result["sections"].size() == 1 && result["symbols"].empty());
  limits = {}; limits.maxTotalNameBytes = 10;
  result = file.inspect(bytes, limits);
  assert(result["available"] == true && result["reason"] == "total-name-limit");
  assert(result["sections"].size() == 2);
  limits = {}; limits.maxSymbols = symbolCount + 2;
  assert(file.inspect(bytes, limits)["coverage"] == "complete");
  limits.maxSymbols = symbolCount + 1;
  result = file.inspect(bytes, limits);
  assert(result["symbols"].size() == symbolCount + 1 && result["coverage"] == "truncated");
  const auto huge = std::numeric_limits<std::size_t>::max();
  assert(file.inspect(bytes, {huge, huge, huge, huge, huge, huge})["coverage"] == "complete");
  auto edit = bytes; word(edit, 60, 4097, 2);
  assert(file.inspect(edit, {huge, huge, huge, huge, huge, huge})["reason"] == "section-header-limit");
  assert(phantom::inspectElfSymbolsFd(-1)["reason"] == "not-regular-file");
  int pipes[2]; assert(::pipe(pipes) == 0);
  assert(phantom::inspectElfSymbolsFd(pipes[0])["reason"] == "not-regular-file");
  ::close(pipes[0]); ::close(pipes[1]);
}

Json inspectPath(const char* path) {
  const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  auto result = phantom::inspectElfSymbolsFd(fd);
  assert(::close(fd) == 0);
  return result;
}

void realTests(const char* unstripped, const char* stripped) {
  for (const char* path : {unstripped, stripped}) {
    const auto result = inspectPath(path);
    assert(result["available"] == true && result["coverage"] == "complete");
    assert(result["elfType"] == "ET_DYN");
    for (const char* classification : {"vtable", "typeinfo", "typeinfo-name", "vtt"})
      assert(std::any_of(result["symbols"].begin(), result["symbols"].end(), [&](const Json& symbol) {
        return symbol["classification"] == classification && symbol["definition"] == "section";
      }));
    for (const char* name : {"elf_symbol_tls", "elf_symbol_function", "elf_symbol_indirect", "elf_symbol_weak"}) {
      const auto found = std::find_if(result["symbols"].begin(), result["symbols"].end(), [&](const Json& symbol) {
        return symbol["name"] == name && symbol["table"] == "dynsym";
      });
      assert(found != result["symbols"].end());
      if (std::string_view(name) == "elf_symbol_tls")
        assert((*found)["type"] == "STT_TLS" && (*found)["valueKind"] == "tls-offset");
      if (std::string_view(name) == "elf_symbol_indirect") assert((*found)["type"] == "STT_GNU_IFUNC");
      if (std::string_view(name) == "elf_symbol_weak") assert((*found)["binding"] == "STB_WEAK");
    }
    const bool symtab = std::any_of(result["symbolTables"].begin(), result["symbolTables"].end(), [](const Json& table) {
      return table["kind"] == "symtab";
    });
    assert(symtab == (path == unstripped));
    assert(std::any_of(result["sections"].begin(), result["sections"].end(), [](const Json& section) {
      return section["name"] == ".bss" && section["fileBacked"] == false;
    }));
  }
}
}  // namespace

int main(int argc, char** argv) {
  validTests();
  malformedTests();
  limitsTests();
  assert(argc == 1 || argc == 3);
  if (argc == 3) realTests(argv[1], argv[2]);
}
