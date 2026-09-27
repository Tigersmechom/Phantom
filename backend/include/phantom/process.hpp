#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <stop_token>
#include <stdexcept>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace phantom {

using Deadline = std::chrono::steady_clock::time_point;

enum class ProcessErrorCode { spawn, io, timeout, cancelled, output_limit };

class ProcessError final : public std::runtime_error {
 public:
  ProcessError(ProcessErrorCode code, std::string message, int error_number = 0);
  ProcessErrorCode code() const noexcept { return code_; }
  int error_number() const noexcept { return error_number_; }

 private:
  ProcessErrorCode code_;
  int error_number_;
};

struct ProcessOptions {
  std::vector<std::string> argv;
  // Empty means inherit the caller's working directory. Relative PATH
  // entries are resolved after changing to this directory.
  std::string cwd;
  std::vector<std::pair<std::string, std::string>> environment;
  bool inherit_environment = true;
  std::size_t max_output_bytes = 4 * 1024 * 1024;
  // Capture mode retains output for wait() up to max_output_bytes in total.
  // Streaming mode returns bytes only through poll(), without a lifetime
  // cap or retention. Each poll reads at most 64 KiB per stream in either mode.
  bool capture_output = true;
};

struct ProcessExit {
  int exit_code = -1;
  int signal = 0;
};

struct ProcessOutput {
  std::string out;
  std::string err;
  bool stdout_eof = false;
  bool stderr_eof = false;
  std::optional<ProcessExit> exit;
};

// Owns one child process and its process group. The object is move-only. All
// descriptors are CLOEXEC and no shell is involved. Methods may be called by a
// worker while another thread requests cancellation through stop_token.
class Process final {
 public:
  static Process spawn(const ProcessOptions& options);
  Process() = delete;
  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;
  Process(Process&& other) noexcept;
  Process& operator=(Process&& other) noexcept;
  ~Process();

  int pid() const noexcept { return pid_; }
  // write is interruptible even when another thread calls interrupt() or
  // terminate(); it never holds the process mutex while waiting for pipe
  // capacity.
  void write(std::string_view data, Deadline deadline = Deadline::max(),
             std::stop_token stop = {});
  void close_stdin() noexcept;
  // poll returns newly-read bytes. In capture mode wait() includes bytes
  // already seen by poll(); in streaming mode wait() discards further output
  // and returns only completion status, without replaying consumed bytes.
  ProcessOutput poll(std::chrono::milliseconds wait = std::chrono::milliseconds(0),
                     std::stop_token stop = {});
  ProcessOutput wait(Deadline deadline = Deadline::max(), std::stop_token stop = {});
  void interrupt() noexcept;
  void terminate(std::chrono::milliseconds grace = std::chrono::milliseconds(100)) noexcept;

 private:
  explicit Process(int pid, int stdin_fd, int stdout_fd, int stderr_fd,
                   std::size_t max_output_bytes, bool capture_output);
  void close_fds() noexcept;
  void reap(bool block) noexcept;
  ProcessOutput drain(bool wait_for_io, std::chrono::milliseconds wait,
                      std::stop_token stop);
  void check_stop_or_deadline(Deadline deadline, std::stop_token stop) const;
  void fail_and_kill(ProcessErrorCode code, const char* message);

  int pid_ = -1;
  int pgid_ = -1;
  int stdin_fd_ = -1;
  int stdout_fd_ = -1;
  int stderr_fd_ = -1;
  std::size_t max_output_bytes_ = 0;
  std::size_t output_bytes_ = 0;
  bool capture_output_ = true;
  std::string captured_out_;
  std::string captured_err_;
  bool stdout_eof_ = false;
  bool stderr_eof_ = false;
  bool stdin_closed_ = false;
  bool child_reaped_ = false;
  bool group_signal_allowed_ = true;
  ProcessExit exit_{};
  mutable std::recursive_mutex mutex_;
};

}  // namespace phantom
