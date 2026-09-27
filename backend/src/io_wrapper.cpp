#include <cerrno>
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

bool signal_ready(const std::string& path) {
  const int descriptor = ::open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  const char marker = 1;
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
  const pid_t debugger = ::getppid();
  if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != debugger || debugger == 1)
    return 126;
  const std::string directory = argv[1];
  // The backend retains a bootstrap stdin reader/writer until this handshake.
  // Even empty input therefore connects before the backend closes for EOF.
  if (!redirect(directory + "/stdin", STDIN_FILENO, O_RDONLY) ||
      !redirect(directory + "/stdout", STDOUT_FILENO, O_WRONLY) ||
      !redirect(directory + "/stderr", STDERR_FILENO, O_WRONLY) ||
      !signal_ready(directory + "/ready")) return 126;
  // Preserve the submitted environment exactly, including whitespace and
  // newlines; apply it only after this helper and GDB's shell are loaded.
  if (!apply_environment(directory + "/environment")) return 126;
  ::execv(argv[2], argv + 2);
  return errno == ENOENT ? 127 : 126;
}
