#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "phantom/process.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <limits>
#include <thread>

extern char** environ;

namespace phantom {
namespace {

struct ExecFailure { int error_number; };

bool contains_nul(std::string_view value) noexcept {
  return value.find('\0') != std::string_view::npos;
}

void close_nointr(int fd) noexcept {
  // Linux releases the descriptor even when close reports EINTR. Retrying
  // could close an unrelated descriptor opened by another thread meanwhile.
  if (fd >= 0) (void)::close(fd);
}

bool set_nonblock(int fd) {
  int flags = ::fcntl(fd, F_GETFL);
  return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool make_pipe_cloexec(int fds[2]) {
  if (::pipe2(fds, O_CLOEXEC) < 0) return false;
  // Do not let the child redirections alias a pipe when its caller had closed
  // one of descriptors 0, 1 or 2 before spawning.
  for (int index = 0; index < 2; ++index) {
    int& fd = fds[index];
    if (fd >= 3) continue;
    int replacement = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (replacement < 0) return false;
    close_nointr(fd);
    fd = replacement;
  }
  return true;
}

void close_extra_fds(int keep_a, int keep_b, int keep_c, int keep_d) noexcept {
  // Keep the exec-status descriptor alive until execve. close_range is both
  // substantially cheaper than walking a guessed descriptor ceiling and
  // covers descriptors above the historical 65536 cap. Split the ranges
  // around the four descriptors we must preserve.
  std::array<int, 4> keep{keep_a, keep_b, keep_c, keep_d};
  std::sort(keep.begin(), keep.end());
#ifdef SYS_close_range
  unsigned start = 3;
  bool close_range_ok = true;
  for (int fd : keep) {
    if (fd < 3 || static_cast<unsigned>(fd) < start) continue;
    if (start < static_cast<unsigned>(fd) &&
        ::syscall(SYS_close_range, start, static_cast<unsigned>(fd) - 1, 0) < 0) {
      close_range_ok = false;
      break;
    }
    start = static_cast<unsigned>(fd) + 1;
  }
  if (close_range_ok && ::syscall(SYS_close_range, start, ~0U, 0) == 0) return;
#endif
  long max_fd = ::sysconf(_SC_OPEN_MAX);
  if (max_fd < 0) max_fd = 1024;
  for (long fd = 3; fd < max_fd; ++fd) {
    if (fd != keep_a && fd != keep_b && fd != keep_c && fd != keep_d) ::close(static_cast<int>(fd));
  }
}

std::vector<std::string> make_environment(const ProcessOptions& o) {
  std::vector<std::string> result;
  if (o.inherit_environment) {
    for (char** p = environ; p && *p; ++p) result.emplace_back(*p);
  }
  for (const auto& [key, value] : o.environment) {
    const std::string prefix = key + "=";
    auto it = std::find_if(result.begin(), result.end(), [&](const std::string& x) {
      return x.compare(0, prefix.size(), prefix) == 0;
    });
    if (it == result.end()) result.push_back(prefix + value);
    else *it = prefix + value;
  }
  return result;
}

int wait_fd(int fd, short events, Deadline deadline, std::stop_token stop) {
  for (;;) {
    if (stop.stop_requested()) return -2;
    int timeout = -1;
    if (deadline != Deadline::max()) {
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - std::chrono::steady_clock::now()).count();
      if (remaining <= 0) return -1;
      timeout = static_cast<int>(std::min<long long>(remaining, 50));
    } else timeout = 50;
    pollfd p{fd, events, 0};
    int rc = ::poll(&p, 1, timeout);
    if (rc > 0) return (p.revents & (events | POLLERR | POLLHUP)) ? 1 : 0;
    if (rc == 0) continue;
    if (errno == EINTR) continue;
    return -3;
  }
}

}  // namespace

ProcessError::ProcessError(ProcessErrorCode code, std::string message, int error_number)
    : std::runtime_error(std::move(message)), code_(code), error_number_(error_number) {}

Process::Process(int pid, int stdin_fd, int stdout_fd, int stderr_fd,
                 std::size_t max_output_bytes)
    : pid_(pid), pgid_(pid), stdin_fd_(stdin_fd), stdout_fd_(stdout_fd),
      stderr_fd_(stderr_fd), max_output_bytes_(max_output_bytes) {}

Process Process::spawn(const ProcessOptions& options) {
  if (options.argv.empty() || options.argv.front().empty())
    throw ProcessError(ProcessErrorCode::spawn, "process argv must not be empty");
  if (options.max_output_bytes == 0)
    throw ProcessError(ProcessErrorCode::spawn, "process output limit must be positive");
  for (const auto& argument : options.argv) {
    if (contains_nul(argument))
      throw ProcessError(ProcessErrorCode::spawn, "process argv contains NUL");
  }
  if (contains_nul(options.cwd))
    throw ProcessError(ProcessErrorCode::spawn, "process cwd contains NUL");
  for (const auto& [key, value] : options.environment) {
    if (key.empty() || key.find('=') != std::string::npos || contains_nul(key) || contains_nul(value))
      throw ProcessError(ProcessErrorCode::spawn, "invalid process environment entry");
  }

  auto environment = make_environment(options);
  std::vector<char*> argv;
  for (const auto& x : options.argv) argv.push_back(const_cast<char*>(x.c_str()));
  argv.push_back(nullptr);
  std::vector<char*> envp;
  for (auto& x : environment) envp.push_back(x.data());
  envp.push_back(nullptr);

  const std::string& program = options.argv.front();
  std::vector<std::string> candidates;
  if (program.find('/') == std::string::npos) {
    std::string path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for (const auto& x : environment) {
      if (x.rfind("PATH=", 0) == 0) { path = x.substr(5); break; }
    }
    std::size_t start = 0;
    while (start <= path.size()) {
      std::size_t end = path.find(':', start); if (end == std::string::npos) end = path.size();
      std::string entry = path.substr(start, end - start);
      // Resolve relative and empty PATH entries in the child's cwd, after
      // chdir. execve itself performs the check, avoiding access()/exec races.
      candidates.push_back((entry.empty() ? "." : entry) + "/" + program);
      if (end == path.size()) break;
      start = end + 1;
    }
  } else candidates.push_back(program);

  int in_pipe[2] = {-1, -1}, out_pipe[2] = {-1, -1}, err_pipe[2] = {-1, -1}, exec_pipe[2] = {-1, -1};
  if (!make_pipe_cloexec(in_pipe) || !make_pipe_cloexec(out_pipe) ||
      !make_pipe_cloexec(err_pipe) || !make_pipe_cloexec(exec_pipe)) {
    int e = errno;
    for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1],
                   exec_pipe[0], exec_pipe[1]}) close_nointr(fd);
    throw ProcessError(ProcessErrorCode::spawn, "pipe failed: " + std::string(std::strerror(e)), e);
  }

  pid_t child = ::fork();
  if (child < 0) {
    int e = errno;
    for (int fd : {in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1],
                   exec_pipe[0], exec_pipe[1]}) close_nointr(fd);
    throw ProcessError(ProcessErrorCode::spawn, "fork failed: " + std::string(std::strerror(e)), e);
  }
  if (child == 0) {
    close_nointr(in_pipe[1]); close_nointr(out_pipe[0]); close_nointr(err_pipe[0]); close_nointr(exec_pipe[0]);
    if (::setpgid(0, 0) < 0) { ExecFailure x{errno}; (void)::write(exec_pipe[1], &x, sizeof(x)); _exit(127); }
    if (!options.cwd.empty() && ::chdir(options.cwd.c_str()) < 0) {
      ExecFailure x{errno}; (void)::write(exec_pipe[1], &x, sizeof(x)); _exit(127);
    }
    if (::dup2(in_pipe[0], STDIN_FILENO) < 0 || ::dup2(out_pipe[1], STDOUT_FILENO) < 0 ||
        ::dup2(err_pipe[1], STDERR_FILENO) < 0) {
      ExecFailure x{errno}; (void)::write(exec_pipe[1], &x, sizeof(x)); _exit(127);
    }
    close_extra_fds(STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, exec_pipe[1]);
    int exec_error = ENOENT;
    for (const auto& candidate : candidates) {
      ::execve(candidate.c_str(), argv.data(), envp.data());
      if (errno == EACCES) exec_error = EACCES;
      else if (errno != ENOENT && errno != ENOTDIR) { exec_error = errno; break; }
    }
    // ENOEXEC deliberately does not invoke a shell: only executable formats
    // understood by the kernel (including shebang scripts) are accepted.
    ExecFailure x{exec_error}; (void)::write(exec_pipe[1], &x, sizeof(x)); _exit(127);
  }

  close_nointr(in_pipe[0]); close_nointr(out_pipe[1]); close_nointr(err_pipe[1]); close_nointr(exec_pipe[1]);
  // The parent closes this descriptor only after the child has either exec'd
  // (CLOEXEC) or sent an errno, making spawn failure deterministic.
  ExecFailure failure{};
  ssize_t got;
  do { got = ::read(exec_pipe[0], &failure, sizeof(failure)); } while (got < 0 && errno == EINTR);
  close_nointr(exec_pipe[0]);
  if (got > 0) {
    int status; (void)::waitpid(child, &status, 0);
    close_nointr(in_pipe[1]); close_nointr(out_pipe[0]); close_nointr(err_pipe[0]);
    throw ProcessError(ProcessErrorCode::spawn,
                       "exec/chdir failed: " + std::string(std::strerror(failure.error_number)),
                       failure.error_number);
  }
  if (got < 0) {
    int e = errno; (void)::kill(-child, SIGKILL); (void)::waitpid(child, nullptr, 0);
    close_nointr(in_pipe[1]); close_nointr(out_pipe[0]); close_nointr(err_pipe[0]);
    throw ProcessError(ProcessErrorCode::spawn, "exec status read failed: " + std::string(std::strerror(e)), e);
  }
  // Avoid a race with a child that calls setpgid immediately after fork.
  (void)::setpgid(child, child);
  // The parent side must never issue a potentially blocking write after a
  // successful POLLOUT check: another writer or a small pipe can consume the
  // available space between poll() and write().
  if (!set_nonblock(in_pipe[1]) || !set_nonblock(out_pipe[0]) || !set_nonblock(err_pipe[0])) {
    int e = errno; (void)::kill(-child, SIGKILL); (void)::waitpid(child, nullptr, 0);
    close_nointr(in_pipe[1]); close_nointr(out_pipe[0]); close_nointr(err_pipe[0]);
    throw ProcessError(ProcessErrorCode::spawn, "fcntl failed: " + std::string(std::strerror(e)), e);
  }
  return Process(child, in_pipe[1], out_pipe[0], err_pipe[0], options.max_output_bytes);
}

Process::Process(Process&& other) noexcept { *this = std::move(other); }

Process& Process::operator=(Process&& other) noexcept {
  if (this == &other) return *this;
  terminate(); close_fds();
  pid_ = std::exchange(other.pid_, -1); pgid_ = std::exchange(other.pgid_, -1);
  stdin_fd_ = std::exchange(other.stdin_fd_, -1); stdout_fd_ = std::exchange(other.stdout_fd_, -1);
  stderr_fd_ = std::exchange(other.stderr_fd_, -1); max_output_bytes_ = other.max_output_bytes_;
  output_bytes_ = other.output_bytes_; captured_out_ = std::move(other.captured_out_);
  captured_err_ = std::move(other.captured_err_); stdout_eof_ = other.stdout_eof_;
  stderr_eof_ = other.stderr_eof_; stdin_closed_ = other.stdin_closed_; child_reaped_ = other.child_reaped_;
  group_signal_allowed_ = other.group_signal_allowed_; exit_ = other.exit_;
  return *this;
}

Process::~Process() { terminate(); close_fds(); }

void Process::close_fds() noexcept {
  close_nointr(stdin_fd_); close_nointr(stdout_fd_); close_nointr(stderr_fd_);
  stdin_fd_ = stdout_fd_ = stderr_fd_ = -1;
}

void Process::reap(bool block) noexcept {
  if (child_reaped_ || pid_ < 0) return;
  int status = 0; pid_t r;
  do { r = ::waitpid(pid_, &status, block ? 0 : WNOHANG); } while (r < 0 && errno == EINTR);
  if (r == pid_) {
    child_reaped_ = true; group_signal_allowed_ = false;
    if (WIFEXITED(status)) exit_.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) exit_.signal = WTERMSIG(status);
  }
}

void Process::interrupt() noexcept {
  std::lock_guard lock(mutex_);
  if (pid_ >= 0 && !child_reaped_ && group_signal_allowed_) (void)::kill(-pgid_, SIGINT);
}

void Process::terminate(std::chrono::milliseconds grace) noexcept {
  std::lock_guard lock(mutex_);
  // Closing stdin first wakes a concurrent writer immediately and prevents it
  // from enqueueing bytes after termination has been requested.
  close_nointr(std::exchange(stdin_fd_, -1));
  stdin_closed_ = true;
  if (pid_ < 0 || child_reaped_) return;
  // Keep the leader unreaped while the group is being killed. A zombie leader
  // pins its PID/PGID identity, so the group cannot be confused with a reused
  // process-group number. This also reaches grandchildren that ignore TERM.
  if (group_signal_allowed_) (void)::kill(-pgid_, SIGTERM);
  auto until = std::chrono::steady_clock::now() + grace;
  while (std::chrono::steady_clock::now() < until) {
    siginfo_t info{};
    if (::waitid(P_PID, static_cast<id_t>(pid_), &info, WEXITED | WNOWAIT | WNOHANG) == 0 && info.si_pid == pid_) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  if (group_signal_allowed_) (void)::kill(-pgid_, SIGKILL);
  reap(true);
}

void Process::close_stdin() noexcept {
  std::lock_guard lock(mutex_);
  close_nointr(std::exchange(stdin_fd_, -1)); stdin_closed_ = true;
}

void Process::write(std::string_view data, Deadline deadline, std::stop_token stop) {
  sigset_t blocked, previous;
  sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE);
  (void)::pthread_sigmask(SIG_BLOCK, &blocked, &previous);
  auto restore_sigpipe = [&] { (void)::pthread_sigmask(SIG_SETMASK, &previous, nullptr); };
  std::size_t pos = 0;
  while (pos < data.size()) {
    int fd = -1;
    {
      std::lock_guard lock(mutex_);
      fd = stdin_fd_;
    }
    if (fd < 0) { restore_sigpipe(); throw ProcessError(ProcessErrorCode::io, "stdin is closed"); }
    int ready = wait_fd(fd, POLLOUT, deadline, stop);
    if (ready == -2) { restore_sigpipe(); terminate(); throw ProcessError(ProcessErrorCode::cancelled, "process write cancelled"); }
    if (ready == -1) { restore_sigpipe(); terminate(); throw ProcessError(ProcessErrorCode::timeout, "process write timed out"); }
    if (ready < 0) { int e = errno; restore_sigpipe(); terminate(); throw ProcessError(ProcessErrorCode::io, "poll(stdin) failed", e); }
    ssize_t n = -1;
    int write_error = 0;
    {
      std::lock_guard lock(mutex_);
      if (stdin_fd_ != fd) {
        write_error = EBADF;
      } else {
        n = ::write(fd, data.data() + pos, data.size() - pos);
        if (n < 0) write_error = errno;
      }
    }
    if (n > 0) { pos += static_cast<std::size_t>(n); continue; }
    if (write_error == EINTR || write_error == EAGAIN || write_error == EWOULDBLOCK) continue;
    if (write_error == EPIPE) { timespec zero{0, 0}; (void)::sigtimedwait(&blocked, nullptr, &zero); }
    restore_sigpipe(); close_stdin(); throw ProcessError(ProcessErrorCode::io, "write(stdin) failed", write_error);
  }
  restore_sigpipe();
}

void Process::fail_and_kill(ProcessErrorCode code, const char* message) {
  terminate(); throw ProcessError(code, message);
}

ProcessOutput Process::drain(bool wait_for_io, std::chrono::milliseconds wait, std::stop_token stop) {
  ProcessOutput result;
  pollfd fds[2]{}; int count = 0;
  if (stdout_fd_ >= 0) fds[count++] = {stdout_fd_, POLLIN, 0};
  if (stderr_fd_ >= 0) fds[count++] = {stderr_fd_, POLLIN, 0};
  if (wait_for_io && count) {
    auto bounded_wait = std::min(wait, std::chrono::milliseconds(50));
    int rc; do { rc = ::poll(fds, count, static_cast<int>(bounded_wait.count())); } while (rc < 0 && errno == EINTR);
    if (rc < 0) throw ProcessError(ProcessErrorCode::io, "poll(stdout/stderr) failed", errno);
  }
  auto read_one = [&](int& fd, bool& eof, std::string& captured, std::string& fresh) {
    std::array<char, 8192> buf{};
    for (;;) {
      ssize_t n = ::read(fd, buf.data(), buf.size());
      if (n > 0) {
        output_bytes_ += static_cast<std::size_t>(n);
        if (output_bytes_ > max_output_bytes_) { close_nointr(fd); fd = -1; fail_and_kill(ProcessErrorCode::output_limit, "process output limit exceeded"); }
        captured.append(buf.data(), static_cast<std::size_t>(n)); fresh.append(buf.data(), static_cast<std::size_t>(n));
      } else if (n == 0) { close_nointr(fd); fd = -1; eof = true; break; }
      else if (errno == EINTR) continue;
      else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      else { int e = errno; throw ProcessError(ProcessErrorCode::io, "read(stdout/stderr) failed", e); }
    }
  };
  if (stdout_fd_ >= 0 && (!wait_for_io || fds[0].revents)) read_one(stdout_fd_, stdout_eof_, captured_out_, result.out);
  if (stderr_fd_ >= 0 && (!wait_for_io || (count == 2 ? fds[1].revents : fds[0].revents))) read_one(stderr_fd_, stderr_eof_, captured_err_, result.err);
  // Delay reaping until both pipes reached EOF. Descendants inherit these
  // descriptors; keeping the leader as a zombie lets terminate() still prove
  // and kill its original process group if an orphan keeps a pipe open.
  if (stdout_eof_ && stderr_eof_) reap(false);
  result.stdout_eof = stdout_eof_; result.stderr_eof = stderr_eof_; if (child_reaped_) result.exit = exit_;
  if (stop.stop_requested()) { terminate(); throw ProcessError(ProcessErrorCode::cancelled, "process polling cancelled"); }
  return result;
}

ProcessOutput Process::poll(std::chrono::milliseconds wait, std::stop_token stop) {
  std::lock_guard lock(mutex_);
  return drain(wait.count() > 0, wait, stop);
}

ProcessOutput Process::wait(Deadline deadline, std::stop_token stop) {
  ProcessOutput current;
  for (;;) {
    if (stop.stop_requested()) { terminate(); throw ProcessError(ProcessErrorCode::cancelled, "process wait cancelled"); }
    if (deadline != Deadline::max() && std::chrono::steady_clock::now() >= deadline) {
      terminate(); throw ProcessError(ProcessErrorCode::timeout, "process wait timed out");
    }
    {
      std::lock_guard lock(mutex_);
      if (child_reaped_ && stdout_eof_ && stderr_eof_) break;
    }
    auto slice = std::chrono::milliseconds(50);
    if (deadline != Deadline::max()) {
      auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
      if (rem < slice) slice = std::max(std::chrono::milliseconds(1), rem);
    }
    ProcessOutput part;
    {
      // Keep the lock only for one bounded poll/read slice. A concurrent
      // terminate/interrupt must be able to close stdin and signal the child
      // while a long-running wait drains output.
      std::lock_guard lock(mutex_);
      part = drain(true, slice, stop);
    }
    current.out += std::move(part.out); current.err += std::move(part.err);
    current.stdout_eof = part.stdout_eof; current.stderr_eof = part.stderr_eof; current.exit = part.exit;
  }
  {
    std::lock_guard lock(mutex_);
    current.out = captured_out_; current.err = captured_err_; current.stdout_eof = current.stderr_eof = true; current.exit = exit_;
    close_fds();
  }
  return current;
}

}  // namespace phantom
