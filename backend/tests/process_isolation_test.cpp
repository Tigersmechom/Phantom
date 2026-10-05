#include "phantom/process_isolation.hpp"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#if defined(__linux__) && defined(__x86_64__) && !defined(__ILP32__)
#include <cstddef>
#include <csignal>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
std::string executable;

[[noreturn]] void fail(const char* message) {
  std::fprintf(stderr, "process isolation: %s (errno=%d)\n", message, errno);
  ::_exit(1);
}

void require(bool condition, const char* message) {
  if (!condition) fail(message);
}

void reap(pid_t child) {
  int status = 0;
  while (::waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) fail("waitpid failed");
  }
}

void install() {
  const auto error = phantom::installSingleProcessIsolation();
  require(!error, "install failed");
  require(::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs missing");
  require(::prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER, "seccomp filter missing");
}

void deniedFork() {
  errno = 0;
  const auto child = ::syscall(SYS_fork);
  const int saved = errno;
  if (child == 0) ::_exit(90);
  if (child > 0) reap(static_cast<pid_t>(child));
  require(child == -1 && saved == EPERM, "native fork was not denied with EPERM");
}

void deniedVfork() {
  errno = 0;
  // glibc's wrapper handles the shared-stack return-address protocol if a
  // broken filter accidentally permits vfork. The child immediately exits.
  const auto child = ::vfork();
  if (child == 0) ::_exit(90);
  const int saved = errno;
  if (child > 0) reap(child);
  require(child == -1 && saved == EPERM, "native vfork was not denied with EPERM");
}

int cloneChild(void*) { return 0; }

void deniedClone(unsigned flags) {
  constexpr std::size_t stackSize = 256 * 1024;
  void* stack = ::mmap(nullptr, stackSize, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  require(stack != MAP_FAILED, "cannot allocate clone test stack");
  errno = 0;
  const auto child = ::clone(cloneChild, static_cast<char*>(stack) + stackSize,
                             static_cast<int>(flags | SIGCHLD), nullptr);
  const int saved = errno;
  if (child > 0) reap(child);
  require(::munmap(stack, stackSize) == 0, "cannot release clone test stack");
  require(child == -1 && saved == EPERM, "native clone was not denied with EPERM");
}

void* threadChild(void* value) { return value; }

void deniedPthread() {
  pthread_t thread{};
  const int result = ::pthread_create(&thread, nullptr, threadChild, nullptr);
  if (result == 0) (void)::pthread_join(thread, nullptr);
  require(result == EPERM, "pthread_create was not denied with EPERM");
}

void ordinarySyscalls() {
  require(::syscall(SYS_getpid) == ::getpid(), "ordinary getpid changed");
  int pipe[2]{};
  require(::pipe(pipe) == 0, "ordinary pipe failed");
  const char sent = 'P';
  char received = 0;
  require(::write(pipe[1], &sent, 1) == 1 && ::read(pipe[0], &received, 1) == 1 && received == sent,
          "ordinary read/write changed");
  require(::close(pipe[0]) == 0 && ::close(pipe[1]) == 0, "ordinary close failed");
  const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  auto* memory = static_cast<unsigned char*>(::mmap(nullptr, page, PROT_READ | PROT_WRITE,
                                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  require(memory != MAP_FAILED, "ordinary mmap failed");
  memory[0] = 73;
  require(::mprotect(memory, page, PROT_READ) == 0 && memory[0] == 73,
          "ordinary mprotect failed");
  require(::munmap(memory, page) == 0, "ordinary munmap failed");
}

// Runs after the loader, before main, on the exec inheritance subtest. A filter
// installed only by main would fail this check; no new target code may precede
// installation in the real I/O wrapper either.
__attribute__((constructor)) void checkExecConstructor() {
  if (std::getenv("PHANTOM_ISOLATION_TEST_EXEC") == nullptr) return;
  deniedFork();
  require(::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "constructor lost no_new_privs");
  require(::setenv("PHANTOM_ISOLATION_TEST_CONSTRUCTOR", "passed", 1) == 0,
          "cannot record constructor evidence");
}

void blockInstallationOption(unsigned int option) {
  // A preexisting host filter may deny either setup syscall. The installer
  // must report its actual errno rather than claim success or weaken policy.
  sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, option, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program{};
  program.len = static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0]));
  program.filter = instructions;
  require(::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "cannot prepare refusal test");
  require(::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0, "cannot install refusal test");
  const auto error = phantom::installSingleProcessIsolation();
  require(error == std::error_code(EACCES, std::generic_category()), "setup failure errno was lost");
}

void run(const char* name, void (*test)()) {
  const auto child = ::fork();
  if (child < 0) fail("cannot fork isolated test");
  if (child == 0) {
    const auto parent = ::getppid();
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parent) ::_exit(2);
    test();
    ::_exit(0);
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  int status = 0;
  for (;;) {
    const auto done = ::waitpid(child, &status, WNOHANG);
    if (done == child) break;
    if (done < 0 && errno != EINTR) fail("cannot collect test child");
    if (std::chrono::steady_clock::now() >= deadline) {
      (void)::kill(child, SIGKILL);
      reap(child);
      std::fprintf(stderr, "process isolation: timed out: %s\n", name);
      std::exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    std::fprintf(stderr, "process isolation: failed: %s (wait status=%d)\n", name, status);
    std::exit(1);
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--after-exec") == 0) {
    const auto* evidence = std::getenv("PHANTOM_ISOLATION_TEST_CONSTRUCTOR");
    require(evidence != nullptr && std::strcmp(evidence, "passed") == 0, "constructor did not check inherited filter");
    deniedFork();
    deniedPthread();
    ordinarySyscalls();
    // Avoid sanitizer leak-check helper threads/processes inside the target
    // profile. The unfiltered parent runs normal sanitizer exit checks.
    ::_exit(0);
  }
  char self[4096];
  const auto length = ::readlink("/proc/self/exe", self, sizeof(self));
  require(length > 0 && static_cast<std::size_t>(length) < sizeof(self), "cannot resolve test executable");
  executable.assign(self, static_cast<std::size_t>(length));
  run("native behavior", [] {
    const auto child = ::fork();
    require(child >= 0, "native fork failed");
    if (child == 0) ::_exit(0);
    reap(child);
    pthread_t thread{};
    require(::pthread_create(&thread, nullptr, threadChild, nullptr) == 0, "native pthread_create failed");
    require(::pthread_join(thread, nullptr) == 0, "native pthread_join failed");
  });
  run("fork", [] { install(); deniedFork(); });
  run("vfork", [] { install(); deniedVfork(); });
  run("clone", [] { install(); deniedClone(0); });
  run("shared mm without CLONE_THREAD", [] { install(); deniedClone(CLONE_VM); });
  run("clone3", [] {
    install();
    errno = 0;
    const auto result = ::syscall(435, nullptr, 0);
    require(result == -1 && errno == EPERM, "clone3 was not denied before argument parsing");
  });
  run("pthread_create", [] { install(); deniedPthread(); });
  run("x32 syscall ABI", [] {
    install();
    errno = 0;
    const auto result = ::syscall(0x40000000U | SYS_getpid);
    require(result == -1 && errno == EPERM, "x32 ABI was not denied with EPERM");
  });
  run("int80 syscall ABI", [] {
    install();
    long result = 20;  // i386 getpid: no pointers or architecture-dependent buffers.
    asm volatile("int $0x80" : "+a"(result) : : "r8", "r9", "r10", "r11", "memory", "cc");
    require(result == -EPERM, "int80 ABI was not denied with EPERM");
  });
  run("ordinary native syscalls", [] { install(); ordinarySyscalls(); });
  run("filter cannot be disabled", [] {
    install();
    require(::prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == -1, "no_new_privs was cleared");
    require(::prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED, nullptr) == -1, "seccomp was disabled");
    deniedFork();
  });
  run("exec and constructor inheritance", [] {
    install();
    require(::setenv("PHANTOM_ISOLATION_TEST_EXEC", "1", 1) == 0, "cannot prepare exec test");
    require(::unsetenv("PHANTOM_ISOLATION_TEST_CONSTRUCTOR") == 0, "cannot reset constructor evidence");
    ::execl(executable.c_str(), executable.c_str(), "--after-exec", static_cast<char*>(nullptr));
    fail("ordinary exec failed");
  });
  run("no_new_privs refusal", [] { blockInstallationOption(PR_SET_NO_NEW_PRIVS); });
  run("filter installation refusal", [] { blockInstallationOption(PR_SET_SECCOMP); });
  std::puts("process isolation: native behavior, fork/clone/shared-mm/thread denial, ABI guards, ordinary syscalls, exec/constructor inheritance and setup failures passed");
  return 0;
}
#else
int main() { return 77; }
#endif
