#include "phantom/process_isolation.hpp"

#include <cerrno>
#include <cstddef>

#if defined(__linux__) && defined(__x86_64__) && !defined(__ILP32__)
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

namespace phantom {

std::error_code installSingleProcessIsolation() noexcept {
#if defined(__linux__) && defined(__x86_64__) && !defined(__ILP32__)
  // x32 shares AUDIT_ARCH_X86_64, so checking arch alone would leave an ABI
  // bypass. Reject its syscall-number bit before comparing native numbers.
  constexpr unsigned int x32SyscallBit = 0x40000000U;
  constexpr unsigned int denied = SECCOMP_RET_ERRNO | EPERM;
  static_assert(SYS_clone == 56 && SYS_fork == 57 && SYS_vfork == 58);
  // clone3 has a pointer to its arguments; classic BPF cannot safely inspect
  // that structure. This deliberately single-process profile denies it whole.
  constexpr unsigned int nativeClone3 = 435;
#ifdef SYS_clone3
  static_assert(SYS_clone3 == nativeClone3);
#endif
  sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, x32SyscallBit, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_vfork, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nativeClone3, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, denied),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program{};
  program.len = static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0]));
  program.filter = instructions;
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return {errno, std::generic_category()};
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
    return {errno, std::generic_category()};
  return {};
#else
  return std::make_error_code(std::errc::operation_not_supported);
#endif
}

}  // namespace phantom
