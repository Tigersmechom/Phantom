#include <cerrno>
#include <csignal>
#include <sys/prctl.h>
#include <unistd.h>

// This program is an isolated, backend-owned capability probe. None of these
// symbols or instructions are inserted into a user's build.
extern "C" {
int* phantom_runtime_probe_errno_address = nullptr;
long phantom_runtime_probe_page_size = 0;
volatile std::sig_atomic_t phantom_runtime_probe_signal_count = 0;
}

namespace {
void signalHandler(int) { phantom_runtime_probe_signal_count = 1; }
}

#if defined(__linux__) && defined(__x86_64__)
// There is no call/ret, stack frame, PLT lookup, or libc errno conversion in the
// instruction the debugger executes. int3 is a guard, not the normal endpoint:
// the probe single-steps the syscall and verifies the immediately following PC.
asm(".text\n"
    ".global phantom_runtime_probe_syscall\n"
    ".type phantom_runtime_probe_syscall,@function\n"
    "phantom_runtime_probe_syscall:\n"
    "syscall\n"
    "int3\n"
    ".size phantom_runtime_probe_syscall,.-phantom_runtime_probe_syscall\n");
#endif

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
  return 77;
#else
  const auto parent = ::getppid();
  if (parent <= 1 || ::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      ::getppid() != parent) return 78;

  struct sigaction action {};
  action.sa_handler = signalHandler;
  if (::sigemptyset(&action.sa_mask) != 0 ||
      ::sigaction(SIGUSR1, &action, nullptr) != 0) return 79;
  sigset_t mask;
  if (::sigemptyset(&mask) != 0 || ::sigprocmask(SIG_SETMASK, &mask, nullptr) != 0)
    return 80;

  phantom_runtime_probe_errno_address = &errno;
  phantom_runtime_probe_page_size = ::sysconf(_SC_PAGESIZE);
  errno = 123;
  asm volatile(".global phantom_runtime_probe_entry\n"
               "phantom_runtime_probe_entry: nop" ::: "memory");
  return errno == 123 && phantom_runtime_probe_signal_count == 0 ? 0 : 81;
#endif
}
