#include "phantom/runtime_helper.hpp"

#include "phantom/elf.hpp"
#include "phantom/elf_symbols.hpp"
#include "phantom/sha256.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <system_error>

#ifdef __linux__
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {
using Json = nlohmann::json;
constexpr std::string_view reservedDirectory = ".phantom-runtime-v1";
constexpr std::string_view sectionName = ".phantom.runtime.v1";
constexpr std::size_t helperBytes = 3;
constexpr std::size_t maxArtifactBytes = 256u * 1024u * 1024u;
constexpr std::string_view helperSource = R"ASM(# Phantom linux-x86_64-scratch-v1: trusted syscall site, source version 1.
.pushsection .phantom.runtime.v1,"ax",@progbits
.p2align 4
.globl __phantom_runtime_syscall_v1
.hidden __phantom_runtime_syscall_v1
.type __phantom_runtime_syscall_v1,@function
__phantom_runtime_syscall_v1:
.byte 0x0f,0x05,0xcc
.size __phantom_runtime_syscall_v1,.-__phantom_runtime_syscall_v1
.popsection
.section .note.GNU-stack,"",@progbits
)ASM";

[[noreturn]] void reject(const std::string& detail) {
  throw std::runtime_error("runtime helper: " + detail);
}

std::uint64_t hex(const Json& value) {
  if (!value.is_string()) reject("invalid ELF hexadecimal metadata");
  const auto& text = value.get_ref<const std::string&>();
  if (!text.starts_with("0x") || text.size() < 3 || text.size() > 18)
    reject("invalid ELF hexadecimal metadata");
  std::uint64_t result = 0;
  const auto parsed = std::from_chars(text.data() + 2, text.data() + text.size(), result, 16);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
    reject("invalid ELF hexadecimal metadata");
  return result;
}

bool contains(std::uint64_t base, std::uint64_t size,
              std::uint64_t start, std::uint64_t count) {
  return start >= base && start - base <= size && count <= size - (start - base);
}

#ifdef __linux__
class SealedArtifact final {
 public:
  explicit SealedArtifact(std::string_view bytes) {
    descriptor = static_cast<int>(::syscall(SYS_memfd_create, "phantom-runtime-helper",
                                            MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (descriptor < 0) throw std::system_error(errno, std::generic_category(), "create runtime helper artifact snapshot");
    try {
      std::size_t used = 0;
      while (used < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + used, bytes.size() - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::system_error(written < 0 ? errno : EIO,
            std::generic_category(), "write runtime helper artifact snapshot");
        used += static_cast<std::size_t>(written);
      }
      if (::fcntl(descriptor, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) != 0)
        throw std::system_error(errno, std::generic_category(), "seal runtime helper artifact snapshot");
    } catch (...) {
      (void)::close(descriptor);
      descriptor = -1;
      throw;
    }
  }
  ~SealedArtifact() { if (descriptor >= 0) (void)::close(descriptor); }
  SealedArtifact(const SealedArtifact&) = delete;
  SealedArtifact& operator=(const SealedArtifact&) = delete;
  int descriptor = -1;
};
#endif

}  // namespace

std::string_view runtimeHelperSource() noexcept { return helperSource; }
std::string runtimeHelperSha256() { return sha256_hex(helperSource); }

std::filesystem::path writeRuntimeHelperSource(
    const std::filesystem::path& snapshotRoot,
    const std::unordered_set<std::string>& snapshotRelativePaths) {
  for (const auto& supplied : snapshotRelativePaths) {
    const auto normalized = std::filesystem::path(supplied).lexically_normal();
    if (normalized.empty() || normalized.is_absolute() || normalized.begin()->generic_string() == "..")
      reject("invalid source snapshot path");
    if (normalized.begin()->generic_string() == reservedDirectory)
      reject("source path overlaps the reserved .phantom-runtime-v1 subtree");
  }
  const auto directory = snapshotRoot / reservedDirectory;
  std::filesystem::create_directories(directory);
  const auto path = directory / "syscall-v1.s";
#ifdef __linux__
  // Pin the directory and create a new file rather than truncating an existing
  // inode: a workspace-created hard link must not modify another user file.
  const int directoryFd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directoryFd < 0) reject("reserved helper directory is not a regular directory");
  int outputFd = -1;
  try {
    struct stat existing {};
    if (::fstatat(directoryFd, "syscall-v1.s", &existing, AT_SYMLINK_NOFOLLOW) == 0) {
      if (!S_ISREG(existing.st_mode)) reject("generated helper input is not a regular file");
      if (::unlinkat(directoryFd, "syscall-v1.s", 0) != 0) reject("cannot replace generated helper input");
    } else if (errno != ENOENT) reject("cannot inspect generated helper input");
    outputFd = ::openat(directoryFd, "syscall-v1.s", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (outputFd < 0) reject("cannot create generated helper input");
    std::size_t used = 0;
    while (used < helperSource.size()) {
      const auto written = ::write(outputFd, helperSource.data() + used, helperSource.size() - used);
      if (written < 0 && errno == EINTR) continue;
      if (written <= 0) reject("cannot write generated helper input");
      used += static_cast<std::size_t>(written);
    }
    const int closed = ::close(outputFd);
    outputFd = -1;
    if (closed != 0) reject("cannot finish generated helper input");
    (void)::close(directoryFd);
  } catch (...) {
    if (outputFd >= 0) (void)::close(outputFd);
    (void)::close(directoryFd);
    throw;
  }
#else
  reject("runtime helper source preparation requires Linux");
#endif
  return path;
}

void appendRuntimeHelperArguments(std::vector<std::string>& arguments,
                                  const std::filesystem::path& source) {
  for (const auto& argument : arguments) {
    // Multiple-definition overrides can replace the backend's reserved
    // symbol without a normal linker collision error. There is no supported
    // reason to weaken symbol ownership for this opt-in profile.
    if (argument.find("--allow-multiple-definition") != std::string::npos ||
        argument == "muldefs" || argument.find(",muldefs") != std::string::npos)
      reject("multiple-definition linker overrides are unsupported");
  }
  arguments.emplace_back("-x");
  arguments.emplace_back("assembler");
  arguments.push_back(source.string());
  arguments.emplace_back("-Wl,--undefined=__phantom_runtime_syscall_v1");
}

Json verifyRuntimeHelperArtifact(std::string_view binaryBytes) {
  if (binaryBytes.empty() || binaryBytes.size() > maxArtifactBytes)
    reject("artifact is empty or exceeds 256 MiB");
#ifdef __linux__
  SealedArtifact artifact(binaryBytes);
  const auto elf = inspectElfFd(artifact.descriptor);
  if (!elf.value("available", false) || elf.value("elfType", "") != "ET_EXEC" ||
      elf.value("class", 0) != 64 || elf.value("endianness", "") != "little" ||
      elf.value("machine", 0) != 62 || elf.value("architecture", "") != "x86_64")
    reject("requires an actual ELF64 little-endian x86-64 ET_EXEC artifact");
  const auto metadata = inspectElfSymbolsFd(artifact.descriptor);
  if (!metadata.value("available", false) || metadata.value("coverage", "") != "complete" ||
      metadata.value("elfType", "") != "ET_EXEC")
    reject("complete ELF section and symbol metadata is required");

  Json symbol = nullptr;
  for (const auto& candidate : metadata.at("symbols")) {
    if (candidate.value("name", Json(nullptr)) != runtimeHelperSymbol) continue;
    if (!symbol.is_null()) reject("helper symbol is ambiguous");
    symbol = candidate;
  }
  if (symbol.is_null() || symbol.value("table", "") != "symtab" ||
      symbol.value("binding", "") != "STB_GLOBAL" || symbol.value("type", "") != "STT_FUNC" ||
      symbol.value("visibility", "") != "STV_HIDDEN" || symbol.value("otherValue", 0) != 2 ||
      symbol.value("definition", "") != "section" || symbol.value("valueKind", "") != "virtual-address" ||
      !symbol.at("sectionIndex").is_number_integer() || hex(symbol.at("sizeHex")) != helperBytes)
    reject("a unique hidden global three-byte helper function is required");

  const auto address = hex(symbol.at("valueHex"));
  if (address == 0 || address >= (std::uint64_t{1} << 63) || address % 16 != 0 ||
      address > std::numeric_limits<std::uint64_t>::max() - helperBytes)
    reject("helper address is invalid or unaligned");
  Json section = nullptr;
  for (const auto& candidate : metadata.at("sections")) {
    if (candidate.value("name", Json(nullptr)) != sectionName) continue;
    if (!section.is_null()) reject("reserved helper section is ambiguous");
    section = candidate;
  }
  if (section.is_null() || section.at("index") != symbol.at("sectionIndex") ||
      section.value("type", "") != "SHT_PROGBITS" || hex(section.at("flagsHex")) != 6 ||
      hex(section.at("addressHex")) != address || hex(section.at("sizeHex")) != helperBytes ||
      hex(section.at("alignmentHex")) != 16 || !section.value("fileBacked", false))
    reject("helper must occupy exactly its reserved allocated RX section");
  const auto fileOffset = hex(section.at("offsetHex"));
  if (!contains(0, binaryBytes.size(), fileOffset, helperBytes))
    reject("helper bytes extend outside the artifact");

  std::size_t loads = 0;
  for (const auto& segment : elf.at("programHeaders")) {
    if (segment.at("type") != "PT_LOAD") continue;
    const auto start = hex(segment.at("virtualAddressHex"));
    const auto size = hex(segment.at("memorySizeHex"));
    if (size == 0 || address >= start + size || start >= address + helperBytes) continue;
    if (!contains(start, size, address, helperBytes))
      reject("another load segment partially overlaps the helper");
    ++loads;
    const auto& permissions = segment.at("flags");
    const auto offset = hex(segment.at("offsetHex"));
    if (!permissions.value("read", false) || permissions.value("write", true) ||
        !permissions.value("execute", false) ||
        !contains(start, hex(segment.at("fileSizeHex")), address, helperBytes) ||
        address - start > std::numeric_limits<std::uint64_t>::max() - offset ||
        offset + (address - start) != fileOffset)
      reject("helper load segment is not a matching immutable RX file extent");
  }
  if (loads != 1) reject("helper must belong to exactly one load segment");
  if (binaryBytes.substr(static_cast<std::size_t>(fileOffset), helperBytes) != std::string_view("\x0f\x05\xcc", 3))
    reject("helper opcodes do not match the trusted syscall site");
  return {{"profile", runtimeHelperProfile}, {"symbol", runtimeHelperSymbol},
          {"addressHex", symbol.at("valueHex")}, {"bytesHex", "0f05cc"},
          {"helperSha256", runtimeHelperSha256()}};
#else
  (void)binaryBytes;
  reject("Linux sealed artifact verification is unavailable");
#endif
}

}  // namespace phantom
