#include "phantom/elf_symbols.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {
using Json = nlohmann::json;

Json emptyResult() {
  return {{"available", false}, {"source", "elf-section-symbol-tables"},
          {"coverage", "none"}, {"sections", Json::array()},
          {"symbols", Json::array()}, {"symbolTables", Json::array()}};
}

#ifdef __linux__
struct InspectionError : std::runtime_error {
  std::string reason;
  bool budget;
  InspectionError(std::string why, std::string detail, bool isBudget = false)
      : std::runtime_error(std::move(detail)), reason(std::move(why)), budget(isBudget) {}
};

[[noreturn]] void fail(const char* reason, const char* detail, bool budget = false) {
  throw InspectionError(reason, detail, budget);
}

std::uint64_t little(std::string_view data, std::size_t offset, unsigned width) {
  if (offset > data.size() || width > data.size() - offset)
    fail("truncated", "ELF integer extends beyond its record");
  std::uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i)
    value |= std::uint64_t(static_cast<unsigned char>(data[offset + i])) << (8 * i);
  return value;
}

std::string hex(std::uint64_t value) {
  std::array<char, 16> digits{};
  const auto end = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16).ptr;
  return "0x" + std::string(digits.data(), end);
}

std::string bytesHex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const unsigned char byte : bytes) {
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
    std::uint32_t scalar, minimum;
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

void setName(Json& entry, std::string_view name) {
  if (validUtf8(name)) entry["name"] = name;
  else { entry["name"] = nullptr; entry["nameBytesHex"] = bytesHex(name); }
}

class File {
 public:
  File(int fd, std::size_t maximumBytes, std::size_t metadataLimit, std::size_t* readCount)
      : fd_(fd), metadataLimit_(metadataLimit), readCount_(readCount) {
    if (::fstat(fd_, &before_) != 0 || !S_ISREG(before_.st_mode) || before_.st_size < 0)
      fail("not-regular-file", "ELF symbol inspection requires a regular file descriptor");
    size_ = static_cast<std::uint64_t>(before_.st_size);
    if (size_ > maximumBytes) fail("file-limit", "ELF image exceeds the inspection file-size limit", true);
  }

  void extent(std::uint64_t offset, std::uint64_t count) const {
    if (offset > size_ || count > size_ - offset)
      fail("truncated", "ELF section metadata extends beyond the file");
  }

  std::string read(std::uint64_t offset, std::size_t count) {
    extent(offset, count);
    if (count > metadataLimit_ - metadataRead_)
      fail("metadata-limit", "ELF metadata exceeds the inspection read budget", true);
    std::string data(count, '\0');
    std::size_t used = 0;
    while (used < count) {
      const auto got = ::pread(fd_, data.data() + used, count - used, static_cast<off_t>(offset + used));
      if (got < 0 && errno == EINTR) continue;
      if (got < 0) fail("read-error", "cannot read ELF symbol metadata");
      if (got == 0) fail("truncated", "ELF image changed or was truncated during inspection");
      used += static_cast<std::size_t>(got);
      metadataRead_ += static_cast<std::size_t>(got);
      if (readCount_) *readCount_ += static_cast<std::size_t>(got);
    }
    return data;
  }

  // String pages avoid rereading a shared string table for every symbol while
  // keeping both cumulative I/O and resident cache size inside the read budget.
  char stringByte(std::uint64_t offset) {
    constexpr std::uint64_t pageBytes = 256;
    const auto page = offset / pageBytes * pageBytes;
    auto found = stringPages_.find(page);
    if (found == stringPages_.end()) {
      extent(offset, 1);
      auto bytes = read(page, static_cast<std::size_t>(std::min(pageBytes, size_ - page)));
      found = stringPages_.emplace(page, std::move(bytes)).first;
    }
    return found->second.at(static_cast<std::size_t>(offset - page));
  }

  void verifyUnchanged() const {
    struct stat after{};
    if (::fstat(fd_, &after) != 0 || before_.st_dev != after.st_dev ||
        before_.st_ino != after.st_ino || before_.st_size != after.st_size ||
        before_.st_mtim.tv_sec != after.st_mtim.tv_sec || before_.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before_.st_ctim.tv_sec != after.st_ctim.tv_sec || before_.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
      fail("file-changed", "ELF file metadata changed during symbol inspection");
  }

 private:
  int fd_;
  struct stat before_{};
  std::uint64_t size_ = 0;
  std::size_t metadataLimit_, metadataRead_ = 0;
  std::size_t* readCount_;
  std::map<std::uint64_t, std::string> stringPages_;
};

struct Section {
  std::uint32_t name, type;
  std::uint64_t flags, address, offset, size;
  std::uint32_t link, info;
  std::uint64_t alignment, entrySize;
};

Section parseSection(std::string_view record) {
  return {static_cast<std::uint32_t>(little(record, 0, 4)),
          static_cast<std::uint32_t>(little(record, 4, 4)), little(record, 8, 8),
          little(record, 16, 8), little(record, 24, 8), little(record, 32, 8),
          static_cast<std::uint32_t>(little(record, 40, 4)),
          static_cast<std::uint32_t>(little(record, 44, 4)),
          little(record, 48, 8), little(record, 56, 8)};
}

const char* elfType(std::uint64_t value) {
  switch (value) {
    case 0: return "ET_NONE"; case 1: return "ET_REL"; case 2: return "ET_EXEC";
    case 3: return "ET_DYN"; case 4: return "ET_CORE"; default: return "unknown";
  }
}

const char* sectionType(std::uint32_t type) {
  switch (type) {
    case 0: return "SHT_NULL"; case 1: return "SHT_PROGBITS"; case 2: return "SHT_SYMTAB";
    case 3: return "SHT_STRTAB"; case 4: return "SHT_RELA"; case 5: return "SHT_HASH";
    case 6: return "SHT_DYNAMIC"; case 7: return "SHT_NOTE"; case 8: return "SHT_NOBITS";
    case 9: return "SHT_REL"; case 10: return "SHT_SHLIB"; case 11: return "SHT_DYNSYM";
    case 14: return "SHT_INIT_ARRAY"; case 15: return "SHT_FINI_ARRAY";
    case 16: return "SHT_PREINIT_ARRAY"; case 17: return "SHT_GROUP";
    case 18: return "SHT_SYMTAB_SHNDX"; case 19: return "SHT_RELR";
    case 0x6ffffff6: return "SHT_GNU_HASH"; case 0x6ffffffd: return "SHT_GNU_verdef";
    case 0x6ffffffe: return "SHT_GNU_verneed"; case 0x6fffffff: return "SHT_GNU_versym";
    default: return "unknown";
  }
}

const char* bindingType(unsigned value) {
  switch (value) {
    case 0: return "STB_LOCAL"; case 1: return "STB_GLOBAL"; case 2: return "STB_WEAK";
    case 10: return "STB_GNU_UNIQUE"; default: return "unknown";
  }
}

const char* symbolType(unsigned value) {
  switch (value) {
    case 0: return "STT_NOTYPE"; case 1: return "STT_OBJECT"; case 2: return "STT_FUNC";
    case 3: return "STT_SECTION"; case 4: return "STT_FILE"; case 5: return "STT_COMMON";
    case 6: return "STT_TLS"; case 10: return "STT_GNU_IFUNC"; default: return "unknown";
  }
}

const char* visibilityType(unsigned value) {
  switch (value) {
    case 0: return "STV_DEFAULT"; case 1: return "STV_INTERNAL";
    case 2: return "STV_HIDDEN"; case 3: return "STV_PROTECTED";
    default: return "unknown";
  }
}

bool symbolTable(const Section& section) { return section.type == 2 || section.type == 11; }

class Names {
 public:
  Names(File& file, const std::vector<Section>& sections, const ElfSymbolInspectionLimits& limits)
      : file_(file), sections_(sections), limits_(limits), checked_(sections.size(), false) {}

  std::string get(std::size_t tableIndex, std::uint32_t offset) {
    if (tableIndex == 0) {
      if (offset != 0) fail("malformed", "nonzero ELF name offset without a string table");
      return {};
    }
    const auto& table = sections_.at(tableIndex);
    if (table.type != 3) fail("malformed", "ELF name table is not SHT_STRTAB");
    if ((table.flags & 0x800) != 0)
      fail("unsupported-compression", "compressed ELF string tables are not supported");
    if (!checked_[tableIndex]) {
      if (table.size != 0 && (file_.stringByte(table.offset) != '\0' ||
                             file_.stringByte(table.offset + table.size - 1) != '\0'))
        fail("malformed", "ELF string table must begin and end with a null byte");
      checked_[tableIndex] = true;
    }
    if (offset == 0) return {};
    if (offset >= table.size) fail("malformed", "ELF name offset exceeds its string table");
    std::string name;
    for (std::uint64_t cursor = offset; cursor < table.size; ++cursor) {
      const auto byte = file_.stringByte(table.offset + cursor);
      if (byte == '\0') {
        if (name.size() > limits_.maxTotalNameBytes - totalBytes_)
          fail("total-name-limit", "ELF names exceed the cumulative output-name budget", true);
        totalBytes_ += name.size();
        return name;
      }
      if (name.size() >= limits_.maxNameBytes)
        fail("name-limit", "ELF name exceeds the per-name inspection limit", true);
      name += byte;
    }
    fail("malformed", "unterminated ELF name in its string table");
  }

 private:
  File& file_;
  const std::vector<Section>& sections_;
  const ElfSymbolInspectionLimits& limits_;
  std::vector<bool> checked_;
  std::size_t totalBytes_ = 0;
};

Json sectionJson(std::size_t index, const Section& section, std::string_view name) {
  const bool active = section.type != 0;
  Json result = {{"index", index}, {"type", sectionType(section.type)}, {"typeValue", section.type},
    {"flagsHex", hex(section.flags)}, {"flags", {{"alloc", active && (section.flags & 2) != 0},
      {"write", active && (section.flags & 1) != 0}, {"execute", active && (section.flags & 4) != 0},
      {"tls", active && (section.flags & 0x400) != 0}, {"compressed", active && (section.flags & 0x800) != 0}}},
    {"addressHex", hex(section.address)}, {"offsetHex", hex(section.offset)},
    {"sizeHex", hex(section.size)}, {"alignmentHex", hex(section.alignment)},
    {"entrySizeHex", hex(section.entrySize)}, {"link", section.link}, {"info", section.info},
    {"fileBacked", active && section.type != 8}};
  setName(result, name);
  return result;
}

Json symbolJson(File& file, Names& names, const std::vector<Section>& sections,
                const std::vector<std::size_t>& extendedIndexes, std::uint64_t imageType,
                std::size_t tableIndex, std::uint64_t index, std::string_view bytes) {
  const auto& table = sections[tableIndex];
  const auto nameOffset = static_cast<std::uint32_t>(little(bytes, 0, 4));
  const auto info = static_cast<unsigned>(little(bytes, 4, 1));
  const auto other = static_cast<unsigned>(little(bytes, 5, 1));
  const auto rawSection = little(bytes, 6, 2);
  const auto value = little(bytes, 8, 8), size = little(bytes, 16, 8);
  const auto binding = info >> 4, type = info & 15, visibility = other & 3;
  if (index == 0 && (nameOffset || info || other || rawSection || value || size))
    fail("malformed", "ELF symbol-table entry zero is not the undefined zero symbol");
  if ((index < table.info) != (binding == 0))
    fail("malformed", "ELF symbol binding disagrees with the local-symbol boundary");

  std::uint64_t section = rawSection;
  if (extendedIndexes[tableIndex] != 0) {
    const auto& extended = sections[extendedIndexes[tableIndex]];
    const auto extendedValue = little(file.read(extended.offset + index * 4, 4), 0, 4);
    if (rawSection == 0xffff) {
      if (extendedValue == 0 || extendedValue >= sections.size())
        fail("malformed", "extended ELF symbol section index is outside the section table");
      section = extendedValue;
    } else if (extendedValue != 0) {
      fail("malformed", "unused extended ELF symbol section index is not zero");
    }
  } else if (rawSection == 0xffff) {
    fail("malformed", "SHN_XINDEX symbol has no associated extended-index table");
  }

  const char* definition = "reserved";
  const char* valueKind = "other";
  Json sectionIndex = nullptr;
  if (rawSection == 0xffff || (section != 0 && section < 0xff00)) {
    if (section >= sections.size() || sections[section].type == 0)
      fail("malformed", "ELF symbol refers to an absent or inactive section");
    definition = "section";
    sectionIndex = section;
    valueKind = type == 6 ? "tls-offset" : imageType == 1 ? "section-offset" :
                imageType == 2 || imageType == 3 ? "virtual-address" : "other";
    if (size > std::numeric_limits<std::uint64_t>::max() - value)
      fail("malformed", "ELF symbol value and size overflow a 64-bit range");
  } else if (section == 0) {
    definition = "undefined"; valueKind = "undefined";
  } else if (section == 0xfff1) {
    definition = "absolute"; valueKind = "absolute";
  } else if (section == 0xfff2) {
    definition = "common"; valueKind = "common-alignment";
  }

  const auto name = names.get(table.link, nameOffset);
  Json classification = nullptr;
  if (name.size() > 4) {
    if (name.starts_with("_ZTV")) classification = "vtable";
    else if (name.starts_with("_ZTI")) classification = "typeinfo";
    else if (name.starts_with("_ZTS")) classification = "typeinfo-name";
    else if (name.starts_with("_ZTT")) classification = "vtt";
  }
  Json result = {{"tableSectionIndex", tableIndex}, {"index", index},
    {"table", table.type == 2 ? "symtab" : "dynsym"}, {"valueHex", hex(value)}, {"sizeHex", hex(size)},
    {"binding", bindingType(binding)}, {"bindingValue", binding}, {"type", symbolType(type)},
    {"typeValue", type}, {"visibility", visibilityType(visibility)}, {"visibilityValue", visibility},
    {"otherValue", other}, {"sectionIndex", std::move(sectionIndex)}, {"rawSectionIndex", rawSection},
    {"definition", definition}, {"valueKind", valueKind}, {"classification", classification},
    {"classificationEvidence", classification.is_null() ? Json(nullptr) : Json("itanium-mangled-prefix")}};
  setName(result, name);
  return result;
}

void inspect(File& file, const ElfSymbolInspectionLimits& limits, Json& result) {
  const auto header = file.read(0, 64);
  if (header.compare(0, 4, "\177ELF", 4) != 0) fail("not-elf", "missing ELF magic");
  if (little(header, 4, 1) != 2) fail("unsupported-class", "only ELF64 symbol metadata is supported");
  if (little(header, 5, 1) != 1) fail("unsupported-endianness", "only little-endian ELF is supported");
  if (little(header, 18, 2) != 62) fail("unsupported-machine", "only x86-64 ELF symbol metadata is supported");
  if (little(header, 6, 1) != 1 || little(header, 20, 4) != 1 || little(header, 52, 2) != 64)
    fail("malformed", "invalid ELF version or ELF64 header size");
  const auto imageType = little(header, 16, 2), tableOffset = little(header, 40, 8);
  const auto entrySize = little(header, 58, 2);
  auto sectionCount = little(header, 60, 2), namesIndex = little(header, 62, 2);
  if (tableOffset == 0) {
    if (sectionCount != 0 || namesIndex != 0)
      fail("malformed", "ELF section counts exist without a section header table");
    result["available"] = true; result["coverage"] = "complete";
    result["elfType"] = elfType(imageType); result["sectionCount"] = 0; result["symbolCount"] = 0;
    return;
  }
  if (tableOffset < 64 || entrySize != 64)
    fail("malformed", "invalid ELF64 section header table layout");
  const auto zero = parseSection(file.read(tableOffset, 64));
  if (zero.type != 0) fail("malformed", "ELF section zero is not SHT_NULL");
  if (sectionCount == 0) sectionCount = zero.size;
  if (namesIndex == 0xffff) namesIndex = zero.link;
  if (sectionCount == 0) fail("malformed", "ELF section header table has no null entry");
  if (sectionCount > limits.maxSectionHeaders)
    fail("section-header-limit", "ELF section count exceeds the inspection limit", true);
  if (namesIndex >= sectionCount)
    fail("malformed", "ELF section-name table index is outside the section table");
  // The section cap makes multiplication exact before validating file bounds.
  file.extent(tableOffset, sectionCount * 64);
  const auto tableBytes = file.read(tableOffset, static_cast<std::size_t>(sectionCount * 64));
  std::vector<Section> sections;
  sections.reserve(static_cast<std::size_t>(sectionCount));
  for (std::size_t i = 0; i < sectionCount; ++i) {
    auto section = parseSection(std::string_view(tableBytes).substr(i * 64, 64));
    if (section.type != 0) {
      if (section.type != 8) file.extent(section.offset, section.size);
      if (section.size > std::numeric_limits<std::uint64_t>::max() - section.address)
        fail("malformed", "ELF section address range overflows");
      if (section.alignment > 1 && (section.alignment & (section.alignment - 1)) != 0)
        fail("malformed", "ELF section alignment is not a power of two");
      if (section.type == 8 && (section.flags & 0x800) != 0)
        fail("malformed", "SHT_NOBITS cannot contain compressed file data");
      if (section.link >= sectionCount)
        fail("malformed", "ELF section link is outside the section table");
    }
    sections.push_back(section);
  }
  if (namesIndex != 0 && sections[namesIndex].type != 3)
    fail("malformed", "ELF section-name table is not SHT_STRTAB");

  std::vector<std::size_t> extendedIndexes(sections.size(), 0);
  std::uint64_t symbolCount = 0;
  for (std::size_t i = 1; i < sections.size(); ++i) {
    const auto& section = sections[i];
    if (symbolTable(section)) {
      if ((section.flags & 0x800) != 0)
        fail("unsupported-compression", "compressed ELF symbol tables are not supported");
      if (section.entrySize != 24 || section.size % 24 != 0 || section.size == 0)
        fail("malformed", "invalid ELF64 symbol-table entry size or extent");
      if (section.link == 0 || sections[section.link].type != 3)
        fail("malformed", "ELF symbol-table link is not a string table");
      const auto count = section.size / 24;
      if (section.info == 0 || section.info > count)
        fail("malformed", "ELF symbol-table local-symbol boundary is invalid");
      symbolCount += count;  // <=4096 * 256MiB/24, exactly representable in JSON.
      result["symbolTables"].push_back({{"sectionIndex", i},
        {"kind", section.type == 2 ? "symtab" : "dynsym"}, {"symbolCount", count}});
    } else if (section.type == 18) {
      if (section.link == 0 || !symbolTable(sections[section.link]) ||
          section.entrySize != 4 || section.size % 4 != 0 ||
          section.size / 4 != sections[section.link].size / 24 || extendedIndexes[section.link] != 0)
        fail("malformed", "invalid or duplicate ELF extended symbol-index table");
      if ((section.flags & 0x800) != 0)
        fail("unsupported-compression", "compressed ELF extended-index tables are not supported");
      extendedIndexes[section.link] = i;
    }
  }

  result["available"] = true; result["coverage"] = "complete";
  result["elfType"] = elfType(imageType); result["sectionCount"] = sectionCount;
  result["symbolCount"] = symbolCount;
  Names names(file, sections, limits);
  for (std::size_t i = 0; i < sections.size(); ++i) {
    // SHT_NULL's non-type fields are inactive (section zero can carry counts).
    const auto name = names.get(static_cast<std::size_t>(namesIndex), sections[i].type == 0 ? 0 : sections[i].name);
    result["sections"].push_back(sectionJson(i, sections[i], name));
  }
  for (std::size_t tableIndex = 1; tableIndex < sections.size(); ++tableIndex) {
    const auto& table = sections[tableIndex];
    if (!symbolTable(table)) continue;
    const auto count = table.size / 24;
    std::string chunk;
    for (std::uint64_t index = 0; index < count; ++index) {
      if (result["symbols"].size() >= limits.maxSymbols)
        fail("symbol-limit", "ELF symbol count exceeds the inspection output limit", true);
      constexpr std::size_t chunkEntries = 64;
      if (index % chunkEntries == 0) {
        const auto entries = std::min<std::uint64_t>({chunkEntries, count - index,
          limits.maxSymbols - result["symbols"].size()});
        chunk = file.read(table.offset + index * 24, static_cast<std::size_t>(entries * 24));
      }
      const auto entry = std::string_view(chunk).substr(static_cast<std::size_t>(index % chunkEntries) * 24, 24);
      result["symbols"].push_back(symbolJson(file, names, sections, extendedIndexes, imageType, tableIndex, index, entry));
    }
  }
}
#endif
}  // namespace

Json inspectElfSymbolsFd(int fd, const ElfSymbolInspectionLimits& limits, std::size_t* metadataBytesRead) {
  if (metadataBytesRead) *metadataBytesRead = 0;
  auto result = emptyResult();
#ifdef __linux__
  const ElfSymbolInspectionLimits hard;
  const ElfSymbolInspectionLimits bounded{
    std::min(limits.maxFileBytes, hard.maxFileBytes),
    std::min(limits.maxSectionHeaders, hard.maxSectionHeaders),
    std::min(limits.maxSymbols, hard.maxSymbols),
    std::min(limits.maxMetadataBytes, hard.maxMetadataBytes),
    std::min(limits.maxNameBytes, hard.maxNameBytes),
    std::min(limits.maxTotalNameBytes, hard.maxTotalNameBytes)};
  try {
    File file(fd, bounded.maxFileBytes, bounded.maxMetadataBytes, metadataBytesRead);
    try { inspect(file, bounded, result); }
    catch (const InspectionError& error) {
      if (!error.budget || !result.value("available", false)) throw;
      result["coverage"] = "truncated";
      result["reason"] = error.reason;
      result["detail"] = error.what();
    }
    file.verifyUnchanged();
  } catch (const InspectionError& error) {
    result = emptyResult();
    result["reason"] = error.reason;
    result["detail"] = error.what();
  }
#else
  (void)fd; (void)limits;
  result["reason"] = "platform-unsupported";
  result["detail"] = "ELF symbol inspection is implemented for Linux";
#endif
  return result;
}

}  // namespace phantom
