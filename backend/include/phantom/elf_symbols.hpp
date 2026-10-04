#pragma once

#include <cstddef>
#include <nlohmann/json.hpp>

namespace phantom {

struct ElfSymbolInspectionLimits {
  std::size_t maxFileBytes = 256 * 1024 * 1024;
  std::size_t maxSectionHeaders = 4096;
  std::size_t maxSymbols = 8192;
  std::size_t maxMetadataBytes = 8 * 1024 * 1024;
  std::size_t maxNameBytes = 1024;
  std::size_t maxTotalNameBytes = 1024 * 1024;
};

// Read ELF64 little-endian x86-64 section and symbol metadata from a borrowed
// regular-file descriptor. Never closes it or changes its offset; never loads
// the image, executes target code, invokes utilities or follows debug links.
// All limits are clamped to the defaults above. metadataBytesRead is reset and
// counts successful pread bytes, including reads made before a failure.
//
// Structural errors produce available=false, coverage=none and empty arrays.
// A budget reached after section metadata has been validated produces a valid
// prefix with available=true, coverage=truncated and reason/detail. Complete
// coverage means all entries in the on-disk section-based symbol tables were
// inspected, not that stripped, generated or dynamically resolved symbols are
// known. A missing section table or .symtab is legitimate, including an ELF
// with only .dynsym. Dynamic tables without sections are not reconstructed.
//
// Names are exact bytes: valid UTF-8 uses name; invalid UTF-8 uses name=null
// and nameBytesHex. Classification uses Itanium mangled-name prefixes only;
// it is neither a validated C++ type nor evidence of a live object or vptr.
// TLS offsets, undefined/common/absolute symbols and GNU IFUNC resolvers retain
// their distinct meanings. The caller must establish runtime file identity and
// load bias; this parser makes no claim about runtime addresses or relocations.
nlohmann::json inspectElfSymbolsFd(int fd,
                                 const ElfSymbolInspectionLimits& limits = {},
                                 std::size_t* metadataBytesRead = nullptr);

}  // namespace phantom
