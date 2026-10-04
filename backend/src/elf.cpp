#include "phantom/elf.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {

using Json = nlohmann::json;

Json unavailable(std::string reason, std::string detail) {
  return {{"available", false}, {"reason", std::move(reason)},
          {"detail", std::move(detail)}};
}

#ifdef __linux__
struct InspectionError : std::runtime_error {
  std::string reason;
  InspectionError(std::string why, std::string detail)
      : std::runtime_error(std::move(detail)), reason(std::move(why)) {}
};

[[noreturn]] void fail(const char* reason, const char* detail) {
  throw InspectionError(reason, detail);
}

std::string hex(std::uint64_t value) {
  std::array<char, 16> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
  return "0x" + std::string(buffer.data(), result.ptr);
}

std::string bytesHex(std::string_view value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(value.size() * 2);
  for (const unsigned char byte : value) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}

std::uint64_t little(std::string_view bytes, std::size_t offset, unsigned width) {
  if (offset > bytes.size() || width > bytes.size() - offset)
    fail("truncated", "ELF integer extends beyond its record");
  std::uint64_t value = 0;
  for (unsigned i = 0; i < width; ++i)
    value |= std::uint64_t(static_cast<unsigned char>(bytes[offset + i])) << (8 * i);
  return value;
}

class File {
 public:
  explicit File(const std::filesystem::path& path, std::size_t maxBytes) {
    // O_NONBLOCK ensures an accidentally supplied FIFO cannot block this read.
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd_ < 0)
      throw InspectionError(errno == EACCES || errno == EPERM ? "read-denied" : "file-unavailable",
                            "cannot open ELF artifact");
    struct stat st{};
    if (::fstat(fd_, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
      ::close(fd_); fd_ = -1;
      fail("not-regular-file", "ELF inspection requires a regular file");
    }
    size_ = static_cast<std::uint64_t>(st.st_size);
    if (size_ > maxBytes) {
      ::close(fd_); fd_ = -1;
      fail("file-limit", "ELF artifact exceeds the inspection file-size limit");
    }
  }
  ~File() { if (fd_ >= 0) ::close(fd_); }
  File(const File&) = delete;
  File& operator=(const File&) = delete;

  void extent(std::uint64_t offset, std::uint64_t count) const {
    if (offset > size_ || count > size_ - offset)
      fail("truncated", "ELF metadata or segment extends beyond the file");
  }

  std::string read(std::uint64_t offset, std::size_t count) const {
    extent(offset, count);
    std::string data(count, '\0');
    std::size_t used = 0;
    while (used < count) {
      const auto got = ::pread(fd_, data.data() + used, count - used,
                               static_cast<off_t>(offset + used));
      if (got < 0 && errno == EINTR) continue;
      if (got < 0) fail("read-error", "cannot read ELF metadata");
      if (got == 0) fail("truncated", "ELF artifact changed or was truncated during inspection");
      used += static_cast<std::size_t>(got);
    }
    return data;
  }

 private:
  int fd_ = -1;
  std::uint64_t size_ = 0;
};

std::string elfType(std::uint64_t type) {
  switch (type) {
    case 0: return "ET_NONE";
    case 1: return "ET_REL";
    case 2: return "ET_EXEC";
    case 3: return "ET_DYN";
    case 4: return "ET_CORE";
    default: return "unknown";
  }
}

std::string programType(std::uint64_t type) {
  switch (type) {
    case 1: return "PT_LOAD";
    case 3: return "PT_INTERP";
    case 0x6474e551: return "PT_GNU_STACK";
    case 0x6474e552: return "PT_GNU_RELRO";
    default: return {};
  }
}

void notes(std::string_view bytes, std::uint64_t alignment,
           const ElfInspectionLimits& limits, Json& buildId) {
  // GNU/Linux uses both four- and eight-byte alignment on ELF64. Follow the
  // segment's alignment, including alignment of the 12-byte note header.
  alignment = std::max<std::uint64_t>(4, alignment);
  if (alignment != 4 && alignment != 8)
    fail("unsupported-note-alignment", "ELF notes require four- or eight-byte alignment");
  const auto aligned = [alignment](std::uint64_t value) {
    return (value + alignment - 1) & ~(alignment - 1);
  };
  std::size_t cursor = 0;
  while (cursor < bytes.size()) {
    if (bytes.size() - cursor < 12) {
      // A segment may include final alignment padding, never a partial record.
      if (bytes.size() - cursor < alignment &&
          std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(cursor), bytes.end(),
                      [](char ch) { return ch == '\0'; })) return;
      fail("malformed", "truncated ELF note header");
    }
    const auto nameSize = little(bytes, cursor, 4);
    const auto descriptorSize = little(bytes, cursor + 4, 4);
    const auto type = little(bytes, cursor + 8, 4);
    const auto recordStart = cursor;
    cursor += 12;
    const auto descriptorOffset = aligned(12 + nameSize);
    const auto nextOffset = aligned(descriptorOffset + descriptorSize);
    if (descriptorOffset > bytes.size() - recordStart)
      fail("malformed", "ELF note name extends beyond the note segment");
    const auto name = bytes.substr(cursor, static_cast<std::size_t>(nameSize));
    cursor = recordStart + static_cast<std::size_t>(descriptorOffset);
    if (nextOffset > bytes.size() - recordStart)
      fail("malformed", "ELF note descriptor extends beyond the note segment");
    if (type == 3 && name == std::string_view("GNU\0", 4)) {
      if (descriptorSize == 0) fail("malformed", "GNU build ID is empty");
      if (descriptorSize > limits.maxBuildIdBytes)
        fail("build-id-limit", "GNU build ID exceeds the inspection limit");
      const auto id = bytesHex(bytes.substr(cursor, static_cast<std::size_t>(descriptorSize)));
      if (!buildId.is_null() && buildId != id)
        fail("malformed", "conflicting GNU build IDs");
      buildId = id;
    }
    cursor = recordStart + static_cast<std::size_t>(nextOffset);
  }
}

Json inspect(const File& file, const ElfInspectionLimits& limits) {
  const auto header = file.read(0, 64);
  if (header.compare(0, 4, "\177ELF", 4) != 0) fail("not-elf", "missing ELF magic");
  if (little(header, 4, 1) != 2) fail("unsupported-class", "only ELF64 metadata is supported");
  if (little(header, 5, 1) != 1) fail("unsupported-endianness", "only little-endian ELF metadata is supported");
  if (little(header, 6, 1) != 1 || little(header, 20, 4) != 1)
    fail("malformed", "unsupported ELF version");
  if (little(header, 52, 2) != 64) fail("malformed", "invalid ELF64 header size");

  const auto type = little(header, 16, 2);
  const auto machine = little(header, 18, 2);
  const auto phOffset = little(header, 32, 8);
  const auto phSize = little(header, 54, 2);
  const auto phCount = little(header, 56, 2);
  if (phCount == 0xffff)
    fail("unsupported-extended-numbering", "extended ELF program header numbering is not supported");
  if (phCount > limits.maxProgramHeaders)
    fail("program-header-limit", "too many ELF program headers");
  if (phCount != 0 && (phSize != 56 || phOffset < 64))
    fail("malformed", "invalid ELF64 program header table layout");
  file.extent(phOffset, phCount * phSize);

  Json result = {{"available", true}, {"format", "ELF"}, {"class", 64},
                 {"endianness", "little"}, {"elfType", elfType(type)}, {"elfTypeValue", type},
                 {"architecture", machine == 62 ? "x86_64" : "unsupported"},
                 {"machine", machine}, {"entryAddressHex", hex(little(header, 24, 8))},
                 {"programHeaders", Json::array()}, {"buildId", nullptr}};
  std::size_t noteBytes = 0;
  bool hasLoad = false;
  bool hasInterpreter = false;
  for (std::uint64_t i = 0; i < phCount; ++i) {
    const auto entry = file.read(phOffset + i * phSize, 56);
    const auto segmentType = little(entry, 0, 4);
    if (segmentType == 0) continue;  // PT_NULL's other members are undefined.
    const auto flags = little(entry, 4, 4);
    const auto offset = little(entry, 8, 8);
    const auto address = little(entry, 16, 8);
    const auto fileSize = little(entry, 32, 8);
    const auto memorySize = little(entry, 40, 8);
    const auto alignment = little(entry, 48, 8);
    if (fileSize != 0) file.extent(offset, fileSize);
    if (memorySize > std::numeric_limits<std::uint64_t>::max() - address)
      fail("malformed", "ELF virtual address range overflows");
    if (alignment > 1 && (alignment & (alignment - 1)) != 0)
      fail("malformed", "ELF segment alignment is not a power of two");
    if (segmentType == 1) {
      hasLoad = true;
      if (fileSize > memorySize) fail("malformed", "ELF load segment file size exceeds memory size");
      if (alignment > 1 && (address % alignment) != (offset % alignment))
        fail("malformed", "ELF load segment address and file offset are incongruent");
    }
    if (segmentType == 3) {
      if (hasInterpreter) fail("malformed", "multiple ELF interpreter segments");
      hasInterpreter = true;
      if (fileSize < 2 || fileSize > 4096)
        fail("malformed", "invalid ELF interpreter path size");
      const auto interpreter = file.read(offset, static_cast<std::size_t>(fileSize));
      if (interpreter.back() != '\0' || interpreter.find('\0') != interpreter.size() - 1)
        fail("malformed", "ELF interpreter path is not a single terminated string");
    }
    const auto label = programType(segmentType);
    if (!label.empty())
      result["programHeaders"].push_back({{"index", i}, {"type", label},
        {"offsetHex", hex(offset)}, {"virtualAddressHex", hex(address)},
        {"fileSizeHex", hex(fileSize)}, {"memorySizeHex", hex(memorySize)},
        {"alignmentHex", hex(alignment)},
        {"flags", {{"read", (flags & 4) != 0}, {"write", (flags & 2) != 0},
                    {"execute", (flags & 1) != 0}}}});
    if (segmentType == 4) {
      if (fileSize > limits.maxNoteBytes - noteBytes)
        fail("note-limit", "ELF notes exceed the inspection limit");
      noteBytes += static_cast<std::size_t>(fileSize);
      notes(file.read(offset, static_cast<std::size_t>(fileSize)), alignment, limits, result["buildId"]);
    }
  }
  if ((type == 2 || type == 3) && !hasLoad)
    fail("malformed", "ELF executable or shared object has no load segment");
  return result;
}
#endif

}  // namespace

nlohmann::json inspectElf(const std::filesystem::path& path, const ElfInspectionLimits& requested) {
#ifdef __linux__
  const ElfInspectionLimits hard;
  const ElfInspectionLimits limits{std::min(requested.maxFileBytes, hard.maxFileBytes),
    std::min(requested.maxProgramHeaders, hard.maxProgramHeaders),
    std::min(requested.maxNoteBytes, hard.maxNoteBytes),
    std::min(requested.maxBuildIdBytes, hard.maxBuildIdBytes)};
  try {
    const File file(path, limits.maxFileBytes);
    return inspect(file, limits);
  } catch (const InspectionError& error) {
    return unavailable(error.reason, error.what());
  }
#else
  (void)path; (void)requested;
  return unavailable("unsupported-platform", "ELF artifact inspection currently requires Linux");
#endif
}

}  // namespace phantom
