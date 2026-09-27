#include "phantom/service.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

static_assert(__cplusplus >= 202002L, "phantom-backend requires C++20");

namespace {
using phantom::Json;
volatile std::sig_atomic_t caughtSignal = 0;
void signal_handler(int signal) noexcept { caughtSignal = signal; }

void help() {
  std::cout << "phantom-backend " << PHANTOM_BACKEND_VERSION << "\n"
            << "Usage:\n"
            << "  phantom-backend --stdio [--workspace PATH]\n"
            << "  phantom-backend --version\n"
            << "  phantom-backend --self-check\n"
            << "The stdio mode accepts one UTF-8 NDJSON connect/request frame per line.\n"
            << "Protocol: v1-stdio-ndjson; debugger adapter: GDB/MI.\n";
}
void self_check() {
  std::cout << "{\n"
            << "  \"kind\": \"phantom.backend.self-check\",\n"
            << "  \"version\": \"" << PHANTOM_BACKEND_VERSION << "\",\n"
            << "  \"status\": \"ready\",\n"
            << "  \"protocol\": \"v1-stdio-ndjson\",\n"
            << "  \"platform\": \"linux\",\n"
            << "  \"architecture\": \"x86_64\",\n"
            << "  \"cxxStandard\": " << __cplusplus << ",\n"
            << "  \"capabilities\": {\n"
            << "    \"build\": true,\n    \"gdb\": true,\n    \"history\": true,\n"
            << "    \"recordReplay\": false,\n    \"expressionTrace\": false,\n    \"variableWrite\": false\n"
            << "  }\n}\n";
}

// The queue holds wire text, not unbounded JSON DOMs. Both item count and
// allocated string storage are bounded; the reader then applies OS backpressure.
struct Frame {
  std::string wire;
  bool oversized = false;
};
struct Queue {
  static constexpr std::size_t maxItems = 64;
  static constexpr std::size_t maxBytes = 32 * 1024 * 1024;
  std::mutex mutex;
  std::condition_variable wake;
  std::deque<Frame> items;
  std::size_t bytes = 0;
  bool closed = false;

  bool push(Frame frame) {
    const auto charge = frame.wire.capacity();
    std::unique_lock lock(mutex);
    while (!closed && !caughtSignal &&
           (items.size() >= maxItems || charge > maxBytes - bytes)) {
      wake.wait_for(lock, std::chrono::milliseconds(100));
    }
    if (closed || caughtSignal) return false;
    bytes += charge;
    items.push_back(std::move(frame));
    wake.notify_all();
    return true;
  }
  std::optional<Frame> pop() {
    std::unique_lock lock(mutex);
    wake.wait(lock, [&] { return closed || !items.empty(); });
    if (items.empty()) return std::nullopt;
    const auto charge = items.front().wire.capacity();
    Frame frame = std::move(items.front());
    items.pop_front();
    bytes -= charge;
    wake.notify_all();
    return frame;
  }
  void close(bool discard = false) {
    {
      std::lock_guard lock(mutex);
      closed = true;
      if (discard) { items.clear(); bytes = 0; }
    }
    wake.notify_all();
  }
};

// Nonblocking output matters as much as input: a stopped client must not leave
// the worker permanently inside write() when the process receives SIGTERM.
class NonblockingFd {
 public:
  explicit NonblockingFd(int descriptor) : fd(descriptor), flags(::fcntl(fd, F_GETFL)) {
    ready = flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
  }
  ~NonblockingFd() { if (ready) (void)::fcntl(fd, F_SETFL, flags); }
  bool valid() const { return ready; }
 private:
  int fd;
  int flags;
  bool ready = false;
};

Json wireError(std::string code, std::string message) {
  return {{"kind", "error"}, {"ok", false},
          {"error", {{"code", std::move(code)}, {"message", std::move(message)}, {"retryable", false}}}};
}

int stdio_mode(std::filesystem::path workspace) {
  struct sigaction action{};
  action.sa_handler = signal_handler;
  ::sigemptyset(&action.sa_mask);
  ::sigaction(SIGINT, &action, nullptr);
  ::sigaction(SIGTERM, &action, nullptr);
  std::signal(SIGPIPE, SIG_IGN);
  NonblockingFd input(STDIN_FILENO), output(STDOUT_FILENO);
  if (!input.valid() || !output.valid()) {
    std::cerr << "Cannot configure nonblocking stdio transport.\n";
    return 1;
  }
  std::filesystem::path ioWrapper;
  std::error_code executableError;
  const auto executable = std::filesystem::read_symlink("/proc/self/exe", executableError);
  if (!executableError) ioWrapper = executable.parent_path() / "phantom-io-wrapper";
  phantom::BackendService service({std::move(workspace), {}, PHANTOM_BACKEND_VERSION, {}, std::move(ioWrapper)});
  Queue queue;
  std::atomic<std::size_t> pendingFrames{0};
  const auto enqueue = [&](Frame frame) {
    pendingFrames.fetch_add(1);
    if (queue.push(std::move(frame))) return true;
    pendingFrames.fetch_sub(1);
    return false;
  };
  std::atomic<bool> outputFailed{false};
  auto writeFrames = [&](const std::vector<Json>& frames) {
    for (const auto& frame : frames) {
      const auto wire = frame.dump(-1, ' ', false) + '\n';
      std::size_t offset = 0;
      while (offset < wire.size()) {
        if (caughtSignal || outputFailed.load()) return false;
        const auto count = ::write(STDOUT_FILENO, wire.data() + offset, wire.size() - offset);
        if (count > 0) { offset += static_cast<std::size_t>(count); continue; }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          pollfd descriptor{STDOUT_FILENO, POLLOUT, 0};
          const auto result = ::poll(&descriptor, 1, 100);
          if (result >= 0 || errno == EINTR) continue;
        }
        outputFailed.store(true);
        queue.close(true);
        return false;
      }
    }
    return true;
  };
  std::jthread worker([&] {
    while (!caughtSignal && !outputFailed.load()) {
      auto incoming = queue.pop();
      if (!incoming || caughtSignal) break;
      struct PendingFrame {
        std::atomic<std::size_t>& count;
        ~PendingFrame() { count.fetch_sub(1); }
      } pending{pendingFrames};
      try {
        if (incoming->oversized) {
          if (!writeFrames({wireError("LIMIT_EXCEEDED", "NDJSON frame exceeds 16 MiB")})) break;
          continue;
        }
        auto& line = incoming->wire;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto frame = phantom::parse_wire_json(line);
        if (!frame.is_object()) {
          if (!writeFrames({wireError("INVALID_REQUEST", "NDJSON frame must be an object")})) break;
          continue;
        }
        // connect's discriminant is optional in the standalone adapter DTO.
        // Validation rejects ambiguous envelopes and incorrectly typed kinds.
        const bool connect = frame.contains("supportedProtocolVersions") ||
                             (frame.contains("kind") && frame.at("kind") == "connect");
        if (connect) {
          phantom::validate_connect(frame);
          if (!writeFrames(service.connect(frame))) break;
        } else {
          // Validate at the transport boundary before entering the service:
          // errorResponse needs requestId/workspace fields and therefore must
          // never be called with an arbitrary malformed JSON object. A cancel
          // frame must never cause an interrupt before context checks.
          constexpr std::array<std::string_view, 5> required{
              "protocolVersion", "requestId", "workspace", "session", "command"};
          std::string missing;
          for (const auto key : required) {
            if (!frame.contains(key)) {
              if (!missing.empty()) missing += ", ";
              missing += key;
            }
          }
          if (!missing.empty()) {
            if (!writeFrames({wireError("INVALID_REQUEST", "request is missing: " + missing)})) break;
          } else {
            phantom::validate_request(frame);
            const auto publish = [&](const Json& update) {
              if (!writeFrames({update})) service.interrupt(2);
            };
            if (!writeFrames(service.request(frame, publish))) break;
          }
        }
      } catch (const phantom::ValidationError& error) {
        auto response = wireError(error.code, error.what());
        response["error"]["path"] = error.path;
        if (!writeFrames({std::move(response)})) break;
      } catch (const std::exception& error) {
        if (!writeFrames({wireError("INVALID_REQUEST", error.what())})) break;
      }
    }
  });

  std::string buffer;
  buffer.reserve(8192);
  constexpr std::size_t maxFrame = 16 * 1024 * 1024;
  bool discarding = false;
  bool inputFailed = false;
  bool eof = false;
  std::array<char, 8192> chunk{};
  while (!caughtSignal && !outputFailed.load() && !eof) {
    pollfd descriptor{STDIN_FILENO, POLLIN, 0};
    const auto ready = ::poll(&descriptor, 1, 100);
    if (ready < 0) {
      if (errno == EINTR) continue;
      inputFailed = true;
      break;
    }
    if (!ready) continue;
    if (descriptor.revents & POLLNVAL) { inputFailed = true; break; }
    const auto count = ::read(STDIN_FILENO, chunk.data(), chunk.size());
    if (count < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
      inputFailed = true;
      break;
    }
    if (count == 0) { eof = true; break; }
    for (ssize_t index = 0; index < count; ++index) {
      const char ch = chunk[static_cast<std::size_t>(index)];
      if (ch == '\n') {
        if (!discarding) {
          // A control request must interrupt an already-running worker before
          // its own frame reaches the serialized queue. Parsing here is only
          // a bounded look-ahead; the worker parses and validates again before
          // producing the protocol response, so malformed frames still use
          // the normal error path.
          try {
            const auto candidate = phantom::parse_wire_json(buffer);
            if (candidate.is_object() && candidate.contains("command") && candidate.at("command").is_object()) {
              const auto kind = candidate.at("command").value("kind", "");
              if (kind == "cancel" || kind == "pause" || kind == "stop") {
                phantom::validate_request(candidate);
                // With no earlier frame in flight there is no dequeue race.
                // A standalone pause/stop can go straight to the worker.
                (void)service.control(candidate, pendingFrames.load() != 0);
              }
            }
          } catch (...) {
            // The worker owns the canonical validation/error response.
          }
          if (!enqueue({std::move(buffer), false})) break;
        }
        buffer.clear();
        discarding = false;
      } else if (!discarding) {
        if (buffer.size() == maxFrame) {
          // One error represents the entire rejected line. In particular, a
          // valid JSON suffix in this same physical line must never execute.
          discarding = true;
          buffer.clear();
          if (!enqueue({{}, true})) break;
        } else {
          buffer.push_back(ch);
        }
      }
      if (caughtSignal || outputFailed.load()) break;
    }
  }
  // EOF accepts a final nonempty frame without LF. It then cancels an active
  // debugger operation and drains already accepted frames in order; a signal
  // or I/O failure additionally drops queued work.
  if (eof && !discarding && !buffer.empty() && !caughtSignal && !outputFailed.load())
    (void)enqueue({std::move(buffer), false});
  const bool abort = caughtSignal || inputFailed || outputFailed.load();
  if (eof && !abort) service.interrupt(2);
  queue.close(abort);
  if (abort) service.interrupt(2);
  worker.join();
  service.dispose();
  if (caughtSignal) return 128 + caughtSignal;
  return inputFailed || outputFailed.load() ? 1 : 0;
}

} // namespace

int main(int argc, char** argv) {
  std::filesystem::path workspace = std::filesystem::current_path(); bool stdio = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--stdio") stdio = true;
    else if (arg == "--workspace" && i + 1 < argc) workspace = argv[++i];
    else if (arg == "--help" && argc == 2) { help(); return 0; }
    else if (arg == "--version" && argc == 2) { std::cout << "phantom-backend " << PHANTOM_BACKEND_VERSION << '\n'; return 0; }
    else if (arg == "--self-check" && argc == 2) { self_check(); return 0; }
    else { std::cerr << "Unsupported or incomplete option. Use --help.\n"; return 2; }
  }
  if (stdio) return stdio_mode(std::move(workspace));
  help(); return argc == 1 ? 0 : 2;
}
