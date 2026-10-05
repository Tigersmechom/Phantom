#include "phantom/runtime_probe.hpp"

#include "phantom/process.hpp"
#include "phantom/validation.hpp"
#include "runtime_probe_script.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <thread>
#include <string_view>
#include <system_error>

#ifdef __linux__
#include <csignal>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace phantom {
namespace {

constexpr std::string_view profile = "linux-x86_64-syscall-probe-v1";
constexpr std::string_view evidencePrefix = "PHANTOM_RUNTIME_PROBE_V1:";
constexpr std::array<const char*, 14> evidenceFlags = {
    "getpid", "allocated", "writable", "executable", "payloadExecuted",
    "released", "deniedSyscall", "registersRestored", "stackUnchanged",
    "errnoUnchanged", "signalMaskUnchanged", "codeUnchanged",
    "signalStopVerified", "handlerNotRun"};

std::string wireText(const std::string& bytes) {
  return Json::parse(Json(bytes).dump(-1, ' ', false,
      Json::error_handler_t::replace)).get<std::string>();
}

Json notRun(const std::string& detail) {
  return {{"attempted", false}, {"ok", false}, {"status", "not-run"},
          {"exitCode", nullptr}, {"signal", nullptr}, {"stdout", ""},
          {"stderr", ""}, {"detail", detail}};
}

class TemporaryDirectory final {
 public:
  explicit TemporaryDirectory(const std::filesystem::path& parent) {
#ifdef __linux__
    auto pattern = (parent / "phantom-runtime-probe-XXXXXX").string();
    const char* created = ::mkdtemp(pattern.data());
    if (!created)
      throw std::system_error(errno, std::generic_category(), "create runtime probe directory");
    path = created;
#else
    (void)parent;
    throw std::runtime_error("runtime probes require Linux");
#endif
  }
  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
  std::filesystem::path path;
};

struct Stage {
  Json result;
  // Evidence must be parsed before replacing non-UTF-8 diagnostic bytes.
  // Otherwise invalid bytes in a supposedly trusted marker could become
  // different, valid JSON text merely because it was prepared for the wire.
  std::string rawOutput;
};

class ObservedChildren final {
 public:
  ~ObservedChildren() {
#ifdef __linux__
    for (const auto& entry : children_) (void)::close(entry.second);
#endif
  }

  bool observe(int debuggerPid) noexcept {
#ifdef __linux__
    try {
      for (auto entry = children_.begin(); entry != children_.end();) {
        pollfd descriptor{entry->second, POLLIN, 0};
        if (::poll(&descriptor, 1, 0) == 1 && (descriptor.revents & POLLIN)) {
          // A readable pidfd identifies an exited process. Drop its numeric
          // index so a later child with the reused PID gets a fresh handle.
          (void)::close(entry->second);
          entry = children_.erase(entry);
        } else ++entry;
      }
      std::set<int> children;
      std::size_t tasks = 0;
      const auto taskDirectory = std::filesystem::path("/proc") /
          std::to_string(debuggerPid) / "task";
      for (const auto& task : std::filesystem::directory_iterator(taskDirectory)) {
        if (++tasks > 512) return false;
        std::ifstream file(task.path() / "children");
        if (!file) return false;
        std::array<char, 8192> buffer{};
        file.read(buffer.data(), buffer.size());
        const auto count = static_cast<std::size_t>(file.gcount());
        if (count == buffer.size() || file.bad()) return false;
        std::string_view text(buffer.data(), count);
        while (!text.empty()) {
          const auto begin = text.find_first_not_of(" \t\r\n");
          if (begin == std::string_view::npos) break;
          text.remove_prefix(begin);
          int child = 0;
          const auto parsed = std::from_chars(text.data(), text.data() + text.size(), child);
          if (parsed.ec != std::errc{} || child <= 0 || child == debuggerPid ||
              (parsed.ptr != text.data() + text.size() && *parsed.ptr != ' ' && *parsed.ptr != '\n'))
            return false;
          children.insert(child);
          if (children.size() > 64) return false;
          text.remove_prefix(static_cast<std::size_t>(parsed.ptr - text.data()));
        }
      }
      for (const int child : children) {
        if (std::any_of(children_.begin(), children_.end(),
            [child](const auto& entry) { return entry.first == child; })) continue;
        if (children_.size() >= 64) return false;
        const int descriptor = static_cast<int>(::syscall(SYS_pidfd_open, child, 0));
        if (descriptor < 0) {
          if (errno == ESRCH) continue;
          return false;
        }
        // The running debugger can reap a child between /proc sampling and
        // pidfd_open. Re-check current parentage before retaining its handle;
        // never signal a reused numeric PID solely from an earlier sample.
        std::ifstream status(std::filesystem::path("/proc") / std::to_string(child) / "status");
        std::array<char, 16384> buffer{};
        status.read(buffer.data(), buffer.size());
        const auto bytes = static_cast<std::size_t>(status.gcount());
        bool owned = false;
        if (bytes != 0 && bytes < buffer.size() && !status.bad()) {
          std::string_view text(buffer.data(), bytes);
          std::size_t cursor = 0;
          while (cursor < text.size()) {
            const auto end = text.find('\n', cursor);
            if (end == std::string_view::npos) break;
            auto line = text.substr(cursor, end - cursor);
            cursor = end + 1;
            if (!line.starts_with("PPid:")) continue;
            line.remove_prefix(5);
            const auto first = line.find_first_not_of(" \t");
            if (first == std::string_view::npos) break;
            line.remove_prefix(first);
            int parent = 0;
            const auto parsed = std::from_chars(line.data(), line.data() + line.size(), parent);
            owned = parsed.ec == std::errc{} && parsed.ptr == line.data() + line.size() && parent == debuggerPid;
            break;
          }
        }
        if (owned) children_.emplace_back(child, descriptor);
        else (void)::close(descriptor);
      }
      return true;
    } catch (...) {
      return false;
    }
#else
    (void)debuggerPid;
    return false;
#endif
  }

  bool kill() const noexcept {
    bool success = true;
#ifdef __linux__
    std::array<pollfd, 64> descriptors{};
    std::size_t count = 0;
    for (const auto& entry : children_) {
      const int result = static_cast<int>(::syscall(SYS_pidfd_send_signal, entry.second, SIGKILL, nullptr, 0));
      if (result < 0 && errno != ESRCH) success = false;
      descriptors[count++] = {entry.second, POLLIN, 0};
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    std::size_t remaining = count;
    while (remaining != 0) {
      const int result = ::poll(descriptors.data(), static_cast<nfds_t>(count), 5);
      if (result < 0 && errno != EINTR) return false;
      for (std::size_t i = 0; i < count; ++i) {
        if (descriptors[i].fd < 0) continue;
        if (descriptors[i].revents & POLLIN) {
          descriptors[i].fd = -1;
          --remaining;
        } else if (descriptors[i].revents & (POLLERR | POLLNVAL)) return false;
      }
      if (remaining != 0 && std::chrono::steady_clock::now() >= deadline) return false;
    }
#endif
    return success;
  }

 private:
  std::vector<std::pair<int, int>> children_;
};

// GDB puts its inferior in a different process group, including before main()
// can install the fixture's parent-death signal. On interrupted paths, freeze
// the still-owned (unreaped) debugger before examining its direct children.
// This fixture and its script never fork or start a shell. A stopped parent
// cannot race this enumeration with a new fork or a reap/PID reuse.
bool killStoppedDebuggerChildren(int debuggerPid, ObservedChildren& children) noexcept {
#ifdef __linux__
  if (::kill(debuggerPid, SIGSTOP) != 0) return errno == ESRCH;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  bool stopped = false;
  do {
    siginfo_t info{};
    if (::waitid(P_PID, static_cast<id_t>(debuggerPid), &info,
                 WSTOPPED | WEXITED | WNOHANG | WNOWAIT) < 0) return false;
    if (info.si_pid == debuggerPid) {
      if (info.si_code != CLD_STOPPED) return true;
      stopped = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  } while (std::chrono::steady_clock::now() < deadline);
  if (!stopped) return false;
  const bool observed = children.observe(debuggerPid);
  return children.kill() && observed;
#else
  (void)debuggerPid;
  (void)children;
  return false;
#endif
}

Stage run(const std::vector<std::string>& arguments,
          const RuntimeProbeOptions& options, Deadline deadline,
          std::stop_token stop, const std::filesystem::path& work) {
  if (stop.stop_requested()) return {notRun("probe cancelled before this stage"), {}};
  if (std::chrono::steady_clock::now() >= deadline)
    return {notRun("shared probe deadline exhausted"), {}};
  Stage stage{{{"attempted", true}, {"ok", false}, {"status", "spawn-error"},
              {"exitCode", nullptr}, {"signal", nullptr}, {"stdout", ""},
              {"stderr", ""}, {"detail", nullptr}}, {}};
  auto& result = stage.result;
  std::string errors;
  std::optional<Process> process;
  ObservedChildren children;
  bool completed = false;
  bool reaped = false;
  try {
    ProcessOptions processOptions;
    processOptions.argv = arguments;
    processOptions.cwd = work.string();
    processOptions.environment = {{"LC_ALL", "C"}, {"DEBUGINFOD_URLS", ""}};
    processOptions.max_output_bytes = options.maxOutputBytes;
    // Keep cancellation/output-limit cleanup here, while the debugger is
    // alive and still owns a potentially separate-group pre-main inferior.
    processOptions.capture_output = false;
    process.emplace(Process::spawn(processOptions));
    process->close_stdin();
    while (true) {
      if (stop.stop_requested()) {
        result["status"] = "cancelled";
        result["detail"] = "probe cancelled";
        break;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        result["status"] = "timeout";
        result["detail"] = "shared probe deadline exhausted";
        break;
      }
      // Track handles while parentage is still visible. Handles remain safe
      // if GDB later dies and the fixture is reparented before cleanup.
      (void)children.observe(process->pid());
      const auto chunk = process->poll(std::chrono::milliseconds(10));
      reaped = chunk.exit.has_value();
      const auto remaining = options.maxOutputBytes - stage.rawOutput.size() - errors.size();
      const auto outBytes = std::min(remaining, chunk.out.size());
      stage.rawOutput.append(chunk.out.data(), outBytes);
      const auto errBytes = std::min(remaining - outBytes, chunk.err.size());
      errors.append(chunk.err.data(), errBytes);
      if (outBytes != chunk.out.size() || errBytes != chunk.err.size()) {
        result["status"] = "output-limit";
        result["detail"] = "process output limit exceeded";
        break;
      }
      if (chunk.exit && chunk.stdout_eof && chunk.stderr_eof) {
        completed = true;
        result["exitCode"] = chunk.exit->exit_code;
        result["signal"] = chunk.exit->signal;
        const bool success = chunk.exit->exit_code == 0 && chunk.exit->signal == 0;
        result["ok"] = success;
        result["status"] = success ? "succeeded" : "exit-error";
        break;
      }
    }
  } catch (const ProcessError& error) {
    switch (error.code()) {
      case ProcessErrorCode::timeout: result["status"] = "timeout"; break;
      case ProcessErrorCode::cancelled: result["status"] = "cancelled"; break;
      case ProcessErrorCode::output_limit: result["status"] = "output-limit"; break;
      case ProcessErrorCode::spawn: result["status"] = "spawn-error"; break;
      case ProcessErrorCode::io: result["status"] = "io-error"; break;
    }
    result["detail"] = wireText(error.what());
  } catch (const std::exception& error) {
    result["status"] = "io-error";
    result["detail"] = wireText(error.what());
  }
  if (process && !completed) {
    const bool frozen = reaped || killStoppedDebuggerChildren(process->pid(), children);
    const bool killed = children.kill();
    const bool cleaned = frozen && killed;
    if (!cleaned)
      result["detail"] = "probe interrupted; could not confirm separate-group inferior cleanup";
    // Keep the group leader unreaped until all owned descendants have been
    // signalled; Process then terminates/reaps the debugger's original group.
    process->terminate();
  } else if (process) {
    // This is also needed if the debugger exits unexpectedly before the
    // fixture reaches its parent-death setup. Normal completed fixture
    // handles are already dead and pidfd_send_signal reports ESRCH.
    if (!children.kill()) {
      result["ok"] = false;
      result["status"] = "io-error";
      result["detail"] = "could not confirm observed inferior cleanup";
    }
  }
  result["stdout"] = wireText(stage.rawOutput);
  result["stderr"] = wireText(errors);
  return stage;
}

bool integer(const Json& value, std::uint64_t minimum, std::uint64_t maximum) {
  if (!value.is_number_integer() ||
      (!value.is_number_unsigned() && value.get<std::int64_t>() < 0)) return false;
  const auto number = value.get<std::uint64_t>();
  return number >= minimum && number <= maximum;
}

Json parseEvidence(std::string_view output) {
  std::optional<std::string_view> marker;
  std::size_t cursor = 0;
  while (cursor < output.size()) {
    const auto end = output.find('\n', cursor);
    const auto line = output.substr(cursor, end == std::string_view::npos
        ? output.size() - cursor : end - cursor);
    if (line.starts_with(evidencePrefix)) {
      // Accept exactly one complete line, never a duplicate record or a
      // successful-looking prefix cut off by timeout/output truncation.
      if (marker || end == std::string_view::npos) return nullptr;
      marker = line.substr(evidencePrefix.size());
    }
    if (end == std::string_view::npos) break;
    cursor = end + 1;
  }
  if (!marker) return nullptr;
  try {
    ValidationLimits limits;
    limits.maxWireBytes = 4096;
    limits.maxDepth = 2;
    limits.maxNodes = 64;
    limits.maxObjectMembers = 32;
    limits.maxArrayElements = 0;
    limits.maxStringBytes = 128;
    const auto evidence = parse_wire_json(*marker, limits);
    if (!evidence.is_object() || evidence.size() != evidenceFlags.size() + 6 ||
        evidence.value("profile", Json(nullptr)) != profile ||
        !evidence.contains("pid") ||
        !integer(evidence.at("pid"), 1, std::numeric_limits<int>::max()) ||
        !evidence.contains("pageSize") || !integer(evidence.at("pageSize"), 4096, 1024 * 1024) ||
        !evidence.contains("registerCount") || !integer(evidence.at("registerCount"), 32, 512) ||
        !evidence.contains("stackBytes") || !integer(evidence.at("stackBytes"), 4096, 1024 * 1024) ||
        !evidence.contains("scratchAddressHex") || !evidence.at("scratchAddressHex").is_string())
      return nullptr;
    const auto pageSize = evidence.at("pageSize").get<std::uint64_t>();
    if ((pageSize & (pageSize - 1)) != 0) return nullptr;
    const auto& address = evidence.at("scratchAddressHex").get_ref<const std::string&>();
    if (address.size() < 3 || address.size() > 18 || !address.starts_with("0x") ||
        address[2] == '0' || address.find_first_not_of("0123456789abcdef", 2) != std::string::npos)
      return nullptr;
    std::uint64_t parsedAddress = 0;
    const auto parsed = std::from_chars(address.data() + 2, address.data() + address.size(), parsedAddress, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != address.data() + address.size() ||
        parsedAddress % pageSize != 0 ||
        parsedAddress >= (std::uint64_t{1} << 63) ||
        parsedAddress > std::numeric_limits<std::uint64_t>::max() - pageSize)
      return nullptr;
    for (const auto* flag : evidenceFlags)
      if (!evidence.contains(flag) || !evidence.at(flag).is_boolean()) return nullptr;
    return evidence;
  } catch (const std::exception&) {
    return nullptr;
  }
}

bool verified(const Json& evidence) {
  if (!evidence.is_object()) return false;
  for (const auto* flag : evidenceFlags)
    if (evidence.at(flag) != true) return false;
  return true;
}

std::string stageFailure(const Json& stage, Deadline deadline) {
  if (stage.value("attempted", false)) return stage.value("status", "failed");
  return std::chrono::steady_clock::now() >= deadline ? "timeout" : "not-tested";
}

}  // namespace

Json probeRuntime(const RuntimeProbeOptions& options, std::stop_token stop) {
  const auto start = std::chrono::steady_clock::now();
  Json result = {{"scope", "isolated-runtime-fixture"}, {"profile", profile},
                {"available", false}, {"reason", "not-tested"},
                {"elapsedMs", 0}, {"cancelled", false},
                {"gdbVersion", notRun("not tested")},
                {"execution", notRun("version check has not succeeded")},
                {"evidence", nullptr},
                {"limitations", {
                  "Only the shipped disposable Linux x86-64 fixture is tested; no live user session is modified.",
                  "Success does not authorize runtime injection, arbitrary syscalls, inferior function calls or recorder interventions.",
                  "A prelinked syscall site and a bounded scratch allocation are used; writable executable pages are never requested.",
                  "Register, stack, errno and signal-mask checks cover the fixture and declared ranges, not arbitrary C++ state or external effects.",
                  "Signals, seccomp, CET, loader settings and kernel permissions can make another target unsupported.",
                  "Probe processes and temporary files are discarded; no reusable target allocation or injected code is returned."}}};
  const auto finish = [&] {
    result["elapsedMs"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    result["cancelled"] = stop.stop_requested();
    if (stop.stop_requested()) {
      result["available"] = false;
      result["reason"] = "cancelled";
    }
    return result;
  };
  if (options.timeout < std::chrono::milliseconds(1) || options.timeout > std::chrono::seconds(30) ||
      options.maxOutputBytes < 256 || options.maxOutputBytes > 256 * 1024) {
    result["reason"] = "invalid-limits";
    return finish();
  }
  if (stop.stop_requested()) return finish();
  std::error_code error;
  if (options.fixturePath.empty() || !std::filesystem::is_regular_file(options.fixturePath, error)) {
    result["reason"] = "fixture-unavailable";
    return finish();
  }
  try {
    const auto fixture = std::filesystem::absolute(options.fixturePath).string();
    TemporaryDirectory temporary(options.temporaryDirectory.empty()
        ? std::filesystem::temp_directory_path() : options.temporaryDirectory);
    const auto deadline = start + options.timeout;
    auto version = run({options.gdbPath, "-nx", "-nh", "--version"},
                       options, deadline, stop, temporary.path);
    result["gdbVersion"] = std::move(version.result);
    if (result["gdbVersion"]["ok"] != true) {
      result["reason"] = stageFailure(result["gdbVersion"], deadline);
      return finish();
    }
    const auto scriptPath = temporary.path / "probe.gdb";
    {
      std::ofstream script(scriptPath, std::ios::binary);
      script << runtimeProbeScript;
      if (!script.good()) throw std::runtime_error("could not write runtime probe script");
    }
    auto execution = run({options.gdbPath, "-nx", "-nh", "-q", "--batch",
                          "-iex", "set auto-load off", "-x", scriptPath.string(), "--args", fixture},
                         options, deadline, stop, temporary.path);
    result["evidence"] = parseEvidence(execution.rawOutput);
    result["execution"] = std::move(execution.result);
    result["available"] = result["execution"]["ok"] == true && verified(result["evidence"]);
    result["reason"] = result["available"] == true ? "verified" :
        result["execution"]["ok"] == true ? "verification-failed" :
        stageFailure(result["execution"], deadline);
  } catch (const std::exception& exception) {
    result["reason"] = "probe-setup-failed";
    result["execution"]["detail"] = wireText(exception.what());
  }
  return finish();
}

}  // namespace phantom
