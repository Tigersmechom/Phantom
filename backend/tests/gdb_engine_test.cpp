#include "phantom/gdb.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>

using namespace std::chrono_literals;
using phantom::GdbEngine;
using phantom::GdbError;
using phantom::GdbLaunchRequest;
using phantom::GdbOptions;
using phantom::GdbStop;
using Json = nlohmann::json;

namespace {
void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}

std::string readFile(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  require(static_cast<bool>(stream), "cannot read " + path.string());
  return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

struct TemporaryDirectory {
  std::filesystem::path path;
  TemporaryDirectory() {
    char pattern[] = "/tmp/phantom-engine-test-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    require(created != nullptr, "cannot create regression temp directory");
    path = created;
  }
  ~TemporaryDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(path, ignored);
  }
};

void writeExecutable(const std::filesystem::path& path, const std::string& script) {
  std::ofstream stream(path, std::ios::binary);
  stream << script;
  stream.close();
  require(static_cast<bool>(stream) && ::chmod(path.c_str(), 0700) == 0,
          "cannot create fake GDB script");
}

// A zombie has already exited and cannot execute or hold inferior resources.
// An orphan may briefly remain a zombie until the container's init reaps it.
bool processIsRunning(int pid) {
  std::ifstream stream("/proc/" + std::to_string(pid) + "/stat");
  if (!stream) return false;
  std::string stat;
  std::getline(stream, stat);
  const auto endName = stat.rfind(')');
  return endName == std::string::npos || endName + 2 >= stat.size() ||
         (stat[endName + 2] != 'Z' && stat[endName + 2] != 'X');
}

void requireExited(int pid) {
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (processIsRunning(pid) && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(10ms);
  require(!processIsRunning(pid), "debugger/inferior still running: " + std::to_string(pid));
}

void requireEntry(const GdbStop& stop) {
  require(stop.stopped && !stop.exited, "launch did not stop at main");
  require(!stop.stack.empty() && stop.stack.front().value("functionName", "") == "main",
          "entry snapshot has no main frame");
  const auto& vars = stop.stack.front().at("variables");
  require(std::any_of(vars.begin(), vars.end(), [](const Json& variable) {
    return variable.value("name", "") == "argc";
  }), "entry frame variables missing; selected frame leaked from prior launch");
}

void launch(GdbEngine& engine, const GdbLaunchRequest& request, GdbStop& stop) {
  GdbError error;
  const bool ok = engine.launch(request, stop, error);
  require(ok, "launch failed: " + error.code + ": " + error.message);
  requireEntry(stop);
}

void enterLoop(GdbEngine& engine, const GdbLaunchRequest& request, GdbStop& stop) {
  const auto& source = request.sourceBundle.documents.front().text;
  const auto marker = source.find("for (;;) {  // GDB_TEST_LOOP_BREAKPOINT");
  require(marker != std::string::npos, "fixture loop marker is missing");
  const auto line = 1 + std::count(source.begin(), source.begin() + marker, '\n');
  Json breakpoints;
  GdbError error;
  require(engine.setBreakpoints({{"documentId", "fixture"}, {"breakpoints", Json::array({
    {{"id", "loop"}, {"documentId", "fixture"}, {"enabled", true},
     {"range", {{"start", {{"line", line}, {"column", 1}}},
                {"end", {{"line", line}, {"column", 1}}}}}}
  })}}, breakpoints, error), "cannot set loop breakpoint: " + error.message);
  require(breakpoints.size() == 1 && breakpoints.front().value("verified", false),
          "loop breakpoint was not verified");
  require(engine.resume("continue", stop, error), "cannot enter loop: " + error.message);
  require(stop.stopped && stop.stack.size() >= 2, "loop snapshot has no caller frame");
  require(stop.stdoutSnapshot.at("text") == "loop-out\n" &&
          stop.stderrSnapshot.at("text") == "loop-err\n", "loop output streams are incorrect");
  const auto& loopVariables = stop.stack.front().at("variables");
  const auto aggregate = std::find_if(loopVariables.begin(), loopVariables.end(),
      [](const Json& variable) { return variable.value("name", "") == "aggregate"; });
  require(aggregate != loopVariables.end(), "aggregate variable missing from loop frame");
  require(aggregate->value("addressHex", "").rfind("0x", 0) == 0,
          "aggregate storage address is not exposed");
  require(aggregate->contains("storage") && aggregate->at("storage").at("state") == "observed" &&
          aggregate->at("storage").at("lifetime") == "unknown" &&
          aggregate->at("storage").at("byteLength") == sizeof(int) * 2 &&
          aggregate->at("storage").at("rawBytesHex").get<std::string>().size() == sizeof(int) * 2 * 2,
          "aggregate raw storage metadata is incomplete: " + aggregate->dump());
  const auto markerVariable = std::find_if(loopVariables.begin(), loopVariables.end(),
      [](const Json& variable) { return variable.value("name", "") == "marker"; });
  require(markerVariable != loopVariables.end() && markerVariable->value("addressHex", "").rfind("0x", 0) == 0 &&
          markerVariable->at("storage").at("state") == "observed",
          "scalar storage address metadata is incomplete");
  Json variables;
  require(engine.readVariables("frame:1", 0, 32, variables, error),
          "cannot select caller frame: " + error.message);
  // Do not stop on subsequent loop iterations: continuation must hit the
  // deadline, not report a second breakpoint hit.
  require(engine.setBreakpoints({{"documentId", "fixture"}, {"breakpoints", Json::array()}},
                                breakpoints, error), "cannot clear loop breakpoint");
}

void testBufferedMode(const GdbOptions& options, GdbLaunchRequest request,
                      const std::string& mode,
                      const std::string& expectedCaptured,
                      const std::string& expectedBuffered,
                      const std::string& expectedMode,
                      std::optional<std::uint64_t> expectedCapacity,
                      std::optional<std::uint64_t> expectedRemaining) {
  request.argv = {mode};
  GdbEngine engine(options);
  GdbStop stop;
  launch(engine, request, stop);
  const auto& source = request.sourceBundle.documents.front().text;
  const auto marker = source.find("for (;;) {  // GDB_TEST_PENDING_LOOP");
  require(marker != std::string::npos, "pending-output marker is missing");
  const auto line = 1 + std::count(source.begin(), source.begin() + marker, '\n');
  Json breakpoints;
  GdbError error;
  require(engine.setBreakpoints({{"documentId", "fixture"}, {"breakpoints", Json::array({
    {{"id", "pending-loop"}, {"documentId", "fixture"}, {"enabled", true},
     {"range", {{"start", {{"line", line}, {"column", 1}}},
                {"end", {{"line", line}, {"column", 1}}}}}}
  })}}, breakpoints, error), "cannot set pending-output breakpoint: " + error.message);
  require(engine.resume("continue", stop, error), "cannot reach pending-output breakpoint: " + error.message);
  require(stop.stdoutSnapshot.at("text") == expectedCaptured,
          "captured stdout is incorrect for " + mode + ": got " +
              std::to_string(stop.stdoutSnapshot.at("text").get<std::string>().size()) +
              " expected " + std::to_string(expectedCaptured.size()));
  if (mode == "cout-empty") {
    require(!stop.stdoutSnapshot.contains("buffered"),
            "uninitialized stdout buffer should remain an absent optional field");
    (void)engine.stopAndSnapshot();
    return;
  }
  require(stop.stdoutSnapshot.contains("buffered"),
          "runtime omitted the buffered stdout status for " + mode);
  const auto& buffered = stop.stdoutSnapshot.at("buffered");
  require(buffered.at("available") == true && buffered.at("source") == "glibc-_IO_FILE" &&
          buffered.at("stream") == "stdout" && buffered.at("association") == "cout-if-synchronized" &&
          buffered.at("mode") == expectedMode && buffered.at("text") == expectedBuffered &&
          buffered.at("pendingBytes") == expectedBuffered.size() &&
          buffered.at("totalBytes") == expectedBuffered.size(),
          "runtime did not expose the confirmed pending cout buffer for " + mode + ": " + stop.stdoutSnapshot.dump());
  if (expectedCapacity) require(buffered.at("capacityBytes") == *expectedCapacity,
                                "wrong buffered capacity for " + mode + ": " + buffered.dump());
  else require(buffered.at("capacityBytes").is_null(), "line mode reported a byte capacity: " + buffered.dump());
  if (expectedRemaining) require(buffered.at("remainingCapacityBytes") == *expectedRemaining,
                                 "wrong remaining buffered capacity for " + mode + ": " + buffered.dump());
  else require(buffered.at("remainingCapacityBytes").is_null(), "line mode reported remaining capacity: " + buffered.dump());
  require(buffered.at("writeWindowCapacityBytes") == buffered.at("capacityBytes") &&
          buffered.at("writeWindowRemainingBytes") == buffered.at("remainingCapacityBytes"),
          "write-window fields disagree with compatibility aliases for " + mode + ": " + buffered.dump());
  require(buffered.contains("storageCapacityBytes"),
          "buffer snapshot omitted physical storage capacity for " + mode + ": " + buffered.dump());
  (void)engine.stopAndSnapshot();
}

void testBufferedStdout(const GdbOptions& options, GdbLaunchRequest request) {
  testBufferedMode(options, request, "cout-pending", "", "pending\n", "full", 4096, 4088);
  testBufferedMode(options, request, "cout-empty", "", "", "full", std::nullopt, std::nullopt);
  testBufferedMode(options, request, "cout-line", "", "line", "line", std::nullopt, std::nullopt);
  testBufferedMode(options, request, "cout-unbuffered", "direct", "", "unbuffered", 0, 0);
  // The fixture writes fixed chunks so this regression does not inherit the
  // implementation's BUFSIZ macro (which differs from glibc's FIFO window).
  testBufferedMode(options, request, "cout-boundary", "", std::string(4095, 'x'), "full", 4096, 1);
  testBufferedMode(options, request, "cout-full", std::string(4096, 'x'), "x", "full", 4096, 4095);
}

void testTimeoutAndReuse(const GdbOptions& options, const GdbLaunchRequest& request) {
  GdbEngine engine(options);
  GdbStop stopped;
  launch(engine, request, stopped);
  const auto debuggerPid = engine.gdbPid();
  require(debuggerPid.has_value(), "live engine has no debugger PID");
  const int inferiorPid = std::stoi(stopped.processInstanceId);
  enterLoop(engine, request, stopped);
  GdbError error;
  const auto started = std::chrono::steady_clock::now();
  require(!engine.resume("continue", stopped, error), "endless loop did not time out");
  const auto elapsed = std::chrono::steady_clock::now() - started;
  require(error.code == "TIMEOUT", "unexpected timeout error: " + error.code + ": " + error.message);
  require(elapsed >= options.commandTimeout && elapsed < options.commandTimeout + 3s,
          "command timeout was not bounded");
  require(!engine.live() && !engine.gdbPid(), "timeout left a live debugger handle");
  requireExited(*debuggerPid);
  requireExited(inferiorPid);

  // The same object must be reusable after fatal cleanup; its selected frame
  // and buffered MI records belong to the previous debugger instance.
  launch(engine, request, stopped);
  const int replacementPid = std::stoi(stopped.processInstanceId);
  const auto replacementDebugger = engine.gdbPid();
  require(replacementDebugger.has_value(), "replacement debugger PID missing");
  enterLoop(engine, request, stopped);
  const auto final = engine.stopAndSnapshot();
  require(final.exited && !final.stopped && final.reason == "stop", "invalid explicit-stop status");
  require(final.processInstanceId == std::to_string(replacementPid), "stop lost inferior identity");
  require(final.stack.empty() && final.location.is_null(), "stop returned stale stack/location");
  require(final.stdoutSnapshot == stopped.stdoutSnapshot && final.stderrSnapshot == stopped.stderrSnapshot,
          "explicit stop discarded the last stream snapshot");
  require(final.input.at("tracking") == "transport-only" && final.input.at("deliveredBytes") == 0,
          "explicit stop returned invalid input tracking");
  require(!engine.live() && !engine.gdbPid(), "explicit stop left a live engine");
  requireExited(replacementPid);
  requireExited(*replacementDebugger);
}

void testUtf8Tail(GdbOptions options, GdbLaunchRequest request) {
  options.maxOutputBytes = 9;
  request.argv = {"utf8"};
  GdbEngine engine(options);
  GdbStop stopped;
  launch(engine, request, stopped);
  GdbError error;
  require(engine.resume("continue", stopped, error), "UTF-8 fixture failed: " + error.message);
  require(stopped.exited, "UTF-8 fixture did not exit");
  require(stopped.exitCode == 0, "normal inferior exit did not report exit code zero");
  require(stopped.stdoutSnapshot.at("totalBytes") == 22 &&
          stopped.stdoutSnapshot.at("retainedFromByte") == 13 &&
          stopped.stdoutSnapshot.at("truncated") == true,
          "stdout truncation metadata counts encoded display text instead of raw bytes");
  require(stopped.stderrSnapshot.at("totalBytes") == 15 &&
          stopped.stderrSnapshot.at("retainedFromByte") == 6 &&
          stopped.stderrSnapshot.at("truncated") == true,
          "stderr truncation metadata is incorrect");
  const std::string emoji = "\xf0\x9f\x98\x80";
  const auto out = stopped.stdoutSnapshot.at("text").get<std::string>();
  require(out.ends_with(emoji + emoji), "UTF-8 truncation corrupted complete trailing characters");
  // dump() rejects invalid UTF-8 by default. Both a retained continuation
  // byte and inherently invalid inferior bytes must be safe to serialize.
  const Json streams = {{"stdout", stopped.stdoutSnapshot}, {"stderr", stopped.stderrSnapshot}};
  require(Json::parse(streams.dump()) == streams, "stream snapshots cannot round-trip through JSON");
}

void testFinalPipeBacklog(const GdbOptions& options, const GdbLaunchRequest& request) {
  GdbEngine engine(options);
  GdbStop stopped;
  launch(engine, request, stopped);
  // Write through another descriptor to the stopped inferior's FIFOs. No MI
  // command is pumping them, so the final capture must drain the entire
  // backlog itself. Keeping these writers open also rules out an EOF wait.
  struct Writer {
    int fd;
    explicit Writer(const std::string& path)
        : fd(::open(path.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC)) {
      require(fd >= 0, "cannot open inferior FIFO for final-capture regression");
    }
    ~Writer() { (void)::close(fd); }
  };
  const auto descriptors = "/proc/" + stopped.processInstanceId + "/fd/";
  Writer out(descriptors + "1");
  Writer err(descriptors + "2");
  const auto fill = [](int fd, char character) {
    const int enlarged = ::fcntl(fd, F_SETPIPE_SZ, 256 * 1024);
    if (enlarged < 0) {
      require(errno == EPERM || errno == EACCES || errno == ENOMEM,
              "unexpected FIFO enlargement failure");
      std::cout << "FIFO enlargement unavailable; checking final capture at the existing capacity\n";
    }
    const int capacity = ::fcntl(fd, F_GETPIPE_SZ);
    require(capacity > 0, "cannot inspect FIFO capacity");
    std::string bytes(static_cast<std::size_t>(capacity), character);
    bytes.replace(bytes.size() - 4, 4, "END\n");
    std::size_t written = 0;
    while (written < bytes.size()) {
      const auto count = ::write(fd, bytes.data() + written, bytes.size() - written);
      if (count < 0 && errno == EINTR) continue;
      require(count > 0, "could not fill an empty FIFO up to its reported capacity");
      written += static_cast<std::size_t>(count);
    }
    return bytes;
  };
  const auto stdoutBytes = fill(out.fd, 'o');
  const auto stderrBytes = fill(err.fd, 'e');
  const auto started = std::chrono::steady_clock::now();
  const auto final = engine.stopAndSnapshot();
  require(std::chrono::steady_clock::now() - started < 3s,
          "final capture waited for still-open FIFO writers");
  const auto check = [](const Json& snapshot, const std::string& expected) {
    require(snapshot.at("text") == expected && snapshot.at("totalBytes") == expected.size() &&
            snapshot.at("retainedFromByte") == 0 && snapshot.at("truncated") == false,
            "final snapshot lost bytes beyond the live-pump budget");
  };
  check(final.stdoutSnapshot, stdoutBytes);
  check(final.stderrSnapshot, stderrBytes);
}

void testMalformedMi(GdbOptions options, const GdbLaunchRequest& request) {
  TemporaryDirectory temporary;
  const auto script = temporary.path / "fake-gdb";
  const auto seen = temporary.path / "seen";
  writeExecutable(script, "#!/bin/sh\nif [ ! -e '" + seen.string() + "' ]; then\n"
                  "  : > '" + seen.string() + "'\n"
                  "  printf '^done,broken={\\nunconsumed-invalid-record\\n'\n"
                  "  exec sleep 30\nfi\nexec gdb \"$@\"\n");
  options.gdbPath = script;
  options.commandTimeout = 5s;
  GdbEngine engine(options);
  GdbStop stopped;
  GdbError error;
  const auto started = std::chrono::steady_clock::now();
  require(!engine.launch(request, stopped, error), "malformed MI startup was accepted");
  require(error.code == "READ_FAILED", "malformed MI returned " + error.code);
  require(std::chrono::steady_clock::now() - started < 3s, "malformed MI waited for command timeout");
  require(!engine.live() && !engine.gdbPid(), "malformed MI left debugger live");
  // The fake debugger emits another invalid line in the same write. A new
  // launch must discard it before the script replaces itself with real GDB.
  launch(engine, request, stopped);
}

void testLongMiStream(GdbOptions options, GdbLaunchRequest request) {
  TemporaryDirectory temporary;
  const auto script = temporary.path / "verbose-gdb";
  // Valid, individually bounded MI records can exceed the former 4 MiB
  // lifetime cap in aggregate. Then hand the same pipes to the real GDB.
  writeExecutable(script, "#!/usr/bin/env python3\nimport os, sys\n"
                  "line = b'~\"' + b'x' * 1024 + b'\"\\n'\n"
                  "for _ in range(5000): os.write(1, line)\n"
                  "os.execvp('gdb', ['gdb', *sys.argv[1:]])\n");
  options.gdbPath = script;
  options.commandTimeout = 5s;
  request.argv = {"utf8"};
  GdbEngine engine(options);
  GdbStop stopped;
  launch(engine, request, stopped);
  GdbError error;
  require(engine.resume("continue", stopped, error), "long MI stream killed a healthy debugger");
  require(stopped.exited && stopped.exitCode == 0, "long MI stream corrupted subsequent execution");
}

void testUnterminatedMi(GdbOptions options, const GdbLaunchRequest& request) {
  TemporaryDirectory temporary;
  const auto script = temporary.path / "fake-gdb";
  writeExecutable(script, "#!/bin/sh\n"
                  "python3 -c 'import sys;sys.stdout.write(\"x\"*1048577)'\n"
                  "exec sleep 30\n");
  options.gdbPath = script;
  options.commandTimeout = 5s;
  GdbEngine engine(options);
  GdbStop stopped;
  GdbError error;
  const auto started = std::chrono::steady_clock::now();
  require(!engine.launch(request, stopped, error), "overlong unterminated MI was accepted");
  require(error.code == "LIMIT_EXCEEDED", "overlong MI returned " + error.code + ": " + error.message);
  require(std::chrono::steady_clock::now() - started < 3s, "overlong MI waited for command timeout");
  require(!engine.live() && !engine.gdbPid(), "overlong MI left debugger live");
}

void testMissingWrapper(GdbOptions options, const GdbLaunchRequest& request) {
  TemporaryDirectory temporary;
  for (const auto& wrapper : {std::filesystem::path{}, temporary.path / "missing-wrapper"}) {
    options.execWrapper = wrapper;
    GdbEngine engine(options);
    GdbStop stopped;
    GdbError error;
    require(!engine.launch(request, stopped, error), "missing wrapper silently fell back to a PTY");
    require(error.code == "LAUNCH_FAILED", "missing wrapper returned " + error.code);
    require(!engine.live() && !engine.gdbPid(), "missing wrapper left a live debugger");
  }
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: gdb-engine-test FIXTURE IO_WRAPPER FIXTURE_SOURCE\n";
    return 2;
  }
  try {
    GdbOptions options;
    options.execWrapper = std::filesystem::absolute(argv[2]);
    options.commandTimeout = 1500ms;
    GdbLaunchRequest request;
    request.binaryPath = std::filesystem::absolute(argv[1]);
    const auto source = std::filesystem::absolute(argv[3]);
    request.sourceBundle = {"fixture-bundle", {{"fixture", "fixture-revision", source, readFile(source)}}};
    testMissingWrapper(options, request);
    testBufferedStdout(options, request);
    testTimeoutAndReuse(options, request);
    testUtf8Tail(options, request);
    testFinalPipeBacklog(options, request);
    testMalformedMi(options, request);
    testLongMiStream(options, request);
    testUnterminatedMi(options, request);
    std::cout << "GDB engine regression tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "GDB engine regression failed: " << error.what() << '\n';
    return 1;
  }
}
