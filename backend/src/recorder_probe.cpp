#include "phantom/recorder_probe.hpp"

#include "phantom/process.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string_view>
#include <system_error>

#ifdef __linux__
#include <unistd.h>
#endif

namespace phantom {
namespace {
using Json = nlohmann::json;

std::string wireText(const std::string& bytes) {
  // Tool diagnostics can contain filesystem bytes which are not UTF-8.
  return Json::parse(Json(bytes).dump(-1, ' ', false, Json::error_handler_t::replace)).get<std::string>();
}

Json notRun(const std::string& detail) {
  return {{"attempted", false}, {"ok", false}, {"status", "not-run"},
          {"exitCode", nullptr}, {"signal", nullptr}, {"stdout", ""},
          {"stderr", ""}, {"detail", detail}};
}

std::optional<int> readInteger(const std::filesystem::path& path) {
  std::ifstream file(path);
  std::array<char, 64> bytes{};
  file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  const auto size = static_cast<std::size_t>(file.gcount());
  if (size == 0 || size == bytes.size()) return std::nullopt;
  std::string_view text(bytes.data(), size);
  while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) text.remove_suffix(1);
  int value = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return std::nullopt;
  return value;
}

class TemporaryDirectory final {
 public:
  explicit TemporaryDirectory(const std::filesystem::path& parent) {
#ifdef __linux__
    auto pattern = (parent / "phantom-recorder-probe-XXXXXX").string();
    char* created = ::mkdtemp(pattern.data());
    if (!created) throw std::system_error(errno, std::generic_category(), "create recorder probe directory");
    path = created;
#else
    (void)parent;
    throw std::runtime_error("recorder probes require Linux");
#endif
  }
  ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
  std::filesystem::path path;
};

bool traceWithinBudget(const std::filesystem::path& path, std::size_t limit) {
  std::error_code error;
  if (!std::filesystem::exists(path, error)) return !error;
  std::filesystem::recursive_directory_iterator entry(path, error), end;
  if (error) return false;
  std::uintmax_t total = 0;
  std::size_t count = 0;
  for (; entry != end; entry.increment(error)) {
    if (error || ++count > 1024) return false;
    const auto status = entry->symlink_status(error);
    if (error) return false;
    // Never follow trace-created symlinks when accounting or cleaning up.
    if (std::filesystem::is_regular_file(status)) {
      const auto size = entry->file_size(error);
      if (error || size > limit - total) return false;
      total += size;
    }
  }
  return !error;
}

Json run(const std::vector<std::string>& arguments, const RecorderProbeOptions& options,
         Deadline deadline, std::stop_token stop, const std::filesystem::path& work,
         const std::filesystem::path& trace = {}) {
  if (stop.stop_requested()) return notRun("probe cancelled before this stage");
  if (std::chrono::steady_clock::now() >= deadline) return notRun("shared probe deadline exhausted");
  Json result = {{"attempted", true}, {"ok", false}, {"status", "spawn-error"},
                 {"exitCode", nullptr}, {"signal", nullptr}, {"stdout", ""},
                 {"stderr", ""}, {"detail", nullptr}};
  std::string output, errors;
  try {
    ProcessOptions processOptions;
    processOptions.argv = arguments;
    processOptions.cwd = work.string();
    processOptions.environment = {{"LC_ALL", "C"}, {"DEBUGINFOD_URLS", ""},
                                  {"RR_LOG", ""}, {"_RR_TRACE_DIR", work.string()}};
    processOptions.max_output_bytes = options.maxOutputBytes;
    auto process = Process::spawn(processOptions);
    process.close_stdin();
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
      if (!trace.empty() && !traceWithinBudget(trace, options.maxTraceBytes)) {
        result["status"] = "trace-limit";
        result["detail"] = "temporary trace exceeded byte/file budget or became unreadable";
        break;
      }
      const auto chunk = process.poll(std::chrono::milliseconds(10), stop);
      output += chunk.out;
      errors += chunk.err;
      if (chunk.exit && chunk.stdout_eof && chunk.stderr_eof) {
        if (!trace.empty() && !traceWithinBudget(trace, options.maxTraceBytes)) {
          result["status"] = "trace-limit";
          result["detail"] = "temporary trace exceeded byte/file budget or became unreadable";
          break;
        }
        result["exitCode"] = chunk.exit->exit_code;
        result["signal"] = chunk.exit->signal;
        const bool success = chunk.exit->exit_code == 0 && chunk.exit->signal == 0;
        result["ok"] = success;
        result["status"] = success ? "succeeded" : "exit-error";
        break;
      }
    }
    // Destructor terminates/reaps the owned process group on every path.
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
  result["stdout"] = wireText(output);
  result["stderr"] = wireText(errors);
  return result;
}

bool containsLine(const Json& stage, const std::string& line) {
  const auto output = stage.value("stdout", "");
  return ("\n" + output).find("\n" + line + "\n") != std::string::npos;
}

std::string stageFailure(const Json& stage) {
  if (!stage.value("attempted", false)) return "not-tested";
  return stage.value("status", "failed");
}

constexpr std::string_view gdbScript = R"GDB(set pagination off
set confirm off
set debuginfod enabled off
set auto-load off
set may-call-functions off
set non-stop off
set mi-async off
set record full insn-number-max 1024
set record full stop-at-limit on
break phantom_recorder_probe_checkpoint
break phantom_recorder_probe_final_checkpoint
run
record full
continue
set $phantom_middle_pc = $pc
printf "PHANTOM_PROBE_MIDDLE:%u\n", phantom_recorder_probe_value
continue
set $phantom_forward_pc = $pc
printf "PHANTOM_PROBE_FORWARD:%u:%d\n", phantom_recorder_probe_value, $pc != $phantom_middle_pc
reverse-continue
printf "PHANTOM_PROBE_REVERSE:%u:%d\n", phantom_recorder_probe_value, $pc == $phantom_middle_pc
continue
printf "PHANTOM_PROBE_REPLAY:%u:%d\n", phantom_recorder_probe_value, $pc == $phantom_forward_pc
info record
quit
)GDB";
}  // namespace

Json probeRecorders(const RecorderProbeOptions& options, std::stop_token stop) {
  const auto start = std::chrono::steady_clock::now();
  Json result = {
      {"scope", "isolated-scalar-fixture"}, {"elapsedMs", 0}, {"cancelled", false},
      {"environment", {{"perfEventParanoid", nullptr}, {"ptraceScope", nullptr}}},
      {"rr", {{"available", false}, {"reason", "not-tested"},
               {"version", notRun("not tested")}, {"record", notRun("not tested")},
               {"replay", notRun("recording has not succeeded")}}},
      {"gdbRecordFull", {{"available", false}, {"reason", "not-tested"},
                          {"mode", "synchronous-all-stop"},
                          {"version", notRun("not tested")}, {"probe", notRun("not tested")},
                          {"memoryRestored", false}, {"pcRestored", false}, {"forwardReplay", false}}},
      {"limitations", {"Only an isolated tiny scalar fixture is tested; live-session recording is not enabled.",
                        "GDB full recording supports only a subset of instructions and syscalls; unsupported operations can stop recording.",
                        "GDB probe uses synchronous all-stop mode, not the live engine's asynchronous execution profile.",
                        "rr availability depends on CPU/performance counters, ptrace and kernel permissions.",
                        "Probe traces are deleted; no checkpoints or user-program replay are created."}}};
  const auto finish = [&] {
    result["elapsedMs"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    result["cancelled"] = stop.stop_requested();
    return result;
  };
  if (options.timeout < std::chrono::milliseconds(1) || options.timeout > std::chrono::seconds(30) ||
      options.maxOutputBytes < 256 || options.maxOutputBytes > 256 * 1024 ||
      options.maxTraceBytes < 1024 || options.maxTraceBytes > 64 * 1024 * 1024) {
    result["rr"]["reason"] = result["gdbRecordFull"]["reason"] = "invalid-limits";
    return finish();
  }
  if (const auto value = readInteger("/proc/sys/kernel/perf_event_paranoid"))
    result["environment"]["perfEventParanoid"] = *value;
  if (const auto value = readInteger("/proc/sys/kernel/yama/ptrace_scope"))
    result["environment"]["ptraceScope"] = *value;
  if (stop.stop_requested()) return finish();
  std::error_code fileError;
  if (options.fixturePath.empty() || !std::filesystem::is_regular_file(options.fixturePath, fileError)) {
    result["rr"]["reason"] = result["gdbRecordFull"]["reason"] = "fixture-unavailable";
    return finish();
  }
  try {
    const auto fixture = std::filesystem::absolute(options.fixturePath).string();
    TemporaryDirectory temporary(options.temporaryDirectory.empty()
        ? std::filesystem::temp_directory_path() : options.temporaryDirectory);
    const auto deadline = start + options.timeout;
    auto& gdb = result["gdbRecordFull"];
    gdb["version"] = run({options.gdbPath, "-nx", "-nh", "--version"}, options, deadline, stop, temporary.path);
    if (gdb["version"]["ok"] == true) {
      const auto scriptPath = temporary.path / "probe.gdb";
      { std::ofstream script(scriptPath, std::ios::binary);
        script << gdbScript;
        if (!script.good()) throw std::runtime_error("could not write recorder probe script"); }
      gdb["probe"] = run({options.gdbPath, "-nx", "-nh", "-q", "--batch",
                            "-iex", "set auto-load off", "-x", scriptPath.string(), "--args", fixture},
                           options, deadline, stop, temporary.path);
      const auto& probe = gdb["probe"];
      const bool middle = containsLine(probe, "PHANTOM_PROBE_MIDDLE:17");
      const bool forward = containsLine(probe, "PHANTOM_PROBE_FORWARD:29:1");
      const bool reverse = containsLine(probe, "PHANTOM_PROBE_REVERSE:17:1");
      const bool replay = containsLine(probe, "PHANTOM_PROBE_REPLAY:29:1");
      gdb["memoryRestored"] = middle && forward && reverse;
      gdb["pcRestored"] = forward && reverse;
      gdb["forwardReplay"] = replay && reverse;
      gdb["available"] = probe["ok"] == true && middle && forward && reverse && replay;
      gdb["reason"] = gdb["available"] == true ? Json(nullptr)
          : Json(probe["ok"] == true ? "verification-failed" : stageFailure(probe));
    } else gdb["reason"] = stageFailure(gdb["version"]);

    auto& rr = result["rr"];
    rr["version"] = run({options.rrPath, "--version"}, options, deadline, stop, temporary.path);
    if (rr["version"]["ok"] == true) {
      const auto trace = temporary.path / "trace";
      rr["record"] = run({options.rrPath, "record", "-o", trace.string(), fixture},
                           options, deadline, stop, temporary.path, trace);
      if (rr["record"]["ok"] == true && containsLine(rr["record"], "phantom-recorder-probe-ok")) {
        rr["replay"] = run({options.rrPath, "replay", "-a", trace.string()},
                             options, deadline, stop, temporary.path, trace);
        rr["available"] = rr["replay"]["ok"] == true && containsLine(rr["replay"], "phantom-recorder-probe-ok");
        rr["reason"] = rr["available"] == true ? Json(nullptr)
            : Json(rr["replay"]["ok"] == true ? "verification-failed" : stageFailure(rr["replay"]));
      } else rr["reason"] = rr["record"]["ok"] == true ? "verification-failed" : stageFailure(rr["record"]);
    } else rr["reason"] = stageFailure(rr["version"]);
  } catch (const std::exception& error) {
    // Preserve already-completed evidence if a later setup/cleanup phase fails.
    result["detail"] = wireText(error.what());
    if (result["gdbRecordFull"]["reason"] == "not-tested") result["gdbRecordFull"]["reason"] = "probe-setup-failed";
    if (result["rr"]["reason"] == "not-tested") result["rr"]["reason"] = "probe-setup-failed";
  }
  return finish();
}

}  // namespace phantom
