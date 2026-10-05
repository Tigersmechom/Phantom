#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>

namespace phantom {

inline constexpr std::string_view runtimeHelperProfile = "linux-x86_64-scratch-v1";
inline constexpr std::string_view runtimeHelperSymbol = "__phantom_runtime_syscall_v1";

std::string_view runtimeHelperSource() noexcept;
// SHA-256 of the exact versioned assembly source, not just its three opcodes.
std::string runtimeHelperSha256();

// Reserved internal subtree of the immutable source snapshot. Any user
// document at or below that subtree is rejected rather than overwritten.
std::filesystem::path writeRuntimeHelperSource(
    const std::filesystem::path& snapshotRoot,
    const std::unordered_set<std::string>& snapshotRelativePaths);

// Call after the user's translation units, before the final -o argument.
// Assembly is not preprocessed; language flags and -D cannot rewrite it.
void appendRuntimeHelperArguments(std::vector<std::string>& arguments,
                                  const std::filesystem::path& source);

// Verify the exact bytes already hashed for build identity. A sealed in-memory
// file feeds the existing bounded ELF readers, so a workspace path replacement
// cannot produce a manifest for different bytes. Requires actual ELF64 LE
// x86-64 ET_EXEC and one complete, unique, hidden global FUNC in the dedicated
// immutable RX section, with matching section/load-segment extent and opcodes.
// Returns exactly {profile,symbol,addressHex,bytesHex,helperSha256}; unsupported
// metadata, truncation, stripping, ambiguous ownership or wrong bytes throw.
nlohmann::json verifyRuntimeHelperArtifact(std::string_view binaryBytes);

}  // namespace phantom
