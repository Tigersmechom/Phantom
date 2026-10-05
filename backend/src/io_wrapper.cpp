#include "phantom/process_isolation.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include <csignal>
#include <sys/prctl.h>

namespace {
bool redirect(const std::string& path, int target, int flags) {
  const int descriptor = ::open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  if (descriptor == target) return ::fcntl(target, F_SETFD, 0) == 0;
  const bool ok = ::dup2(descriptor, target) >= 0;
  (void)::close(descriptor);
  return ok;
}

bool signal_ready(const std::string& path, unsigned char marker) {
  const int descriptor = ::open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  ssize_t count;
  do { count = ::write(descriptor, &marker, 1); } while (count < 0 && errno == EINTR);
  (void)::close(descriptor);
  return count == 1;
}

bool apply_environment(const std::string& path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file || file.tellg() < 0 || file.tellg() > 1024 * 1024) return false;
  std::string data(static_cast<std::size_t>(file.tellg()), '\0');
  file.seekg(0);
  if (!file.read(data.data(), static_cast<std::streamsize>(data.size()))) return false;
  std::size_t at = 0;
  while (at < data.size()) {
    const auto end = data.find('\0', at);
    if (end == std::string::npos) return false;
    const auto equal = data.find('=', at);
    if (equal == std::string::npos || equal == at || equal >= end) return false;
    const auto key = data.substr(at, equal - at);
    const auto value = data.substr(equal + 1, end - equal - 1);
    if (::setenv(key.c_str(), value.c_str(), 1) != 0) return false;
    at = end + 1;
  }
  return true;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) return 127;
  const bool isolated = std::string_view(argv[2]) == "--single-process-v1";
  const int target = isolated ? 3 : 2;
  if (argc <= target) return 127;
  const pid_t debugger = ::getppid();
  if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != debugger || debugger == 1)
    return 126;
  const std::string directory = argv[1];
  // The backend retains a bootstrap stdin reader/writer until this handshake.
  // Even empty input therefore connects before the backend closes for EOF.
  if (!redirect(directory + "/stdin", STDIN_FILENO, O_RDONLY) ||
      !redirect(directory + "/stdout", STDOUT_FILENO, O_WRONLY) ||
      !redirect(directory + "/stderr", STDERR_FILENO, O_WRONLY)) return 126;
  // Preserve the native handshake and environment order. The explicit profile
  // only acknowledges readiness after its inherited kernel filter is active.
  if (!isolated && !signal_ready(directory + "/ready", phantom::nativeWrapperReady)) return 126;
  // Preserve the submitted environment exactly, including whitespace and
  // newlines; apply it only after this helper and GDB's shell are loaded.
  if (!apply_environment(directory + "/environment")) return 126;
  if (isolated) {
    const auto error = phantom::installSingleProcessIsolation();
    if (error) {
      std::fprintf(stderr, "phantom: cannot install single-process-v1: %s\n", error.message().c_str());
      return 126;
    }
    if (!signal_ready(directory + "/ready", phantom::singleProcessWrapperReady)) return 126;
  }
  ::execv(argv[target], argv + target);
  return errno == ENOENT ? 127 : 126;
}
