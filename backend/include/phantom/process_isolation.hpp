#pragma once

#include <string_view>
#include <system_error>

namespace phantom {

inline constexpr std::string_view singleProcessIsolationProfile = "single-process-v1";
inline constexpr unsigned char nativeWrapperReady = 1;
inline constexpr unsigned char singleProcessWrapperReady = 2;

// Install an irreversible, inherited Linux x86-64 process-creation filter.
// The current process must not have run target code or created target threads.
// Native fork/vfork/clone/clone3, x32 calls and other syscall ABIs return EPERM;
// ordinary native syscalls are unaffected. This is not an I/O/security sandbox.
// Failure must abort the wrapper: no_new_privs may already have been applied.
std::error_code installSingleProcessIsolation() noexcept;

}  // namespace phantom
