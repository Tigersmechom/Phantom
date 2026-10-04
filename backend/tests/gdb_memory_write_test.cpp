#include "phantom/gdb.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std::chrono_literals;
using Json = nlohmann::json;
using phantom::GdbEngine;
using phantom::GdbError;
using phantom::GdbLaunchRequest;
using phantom::GdbOptions;
using phantom::GdbStop;

namespace {
void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}
std::string readFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  require(static_cast<bool>(input), "cannot read " + path.string());
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void writeFile(const std::filesystem::path& path, const std::string& content) {
  std::ofstream output(path, std::ios::binary);
  output << content;
  output.close();
  require(static_cast<bool>(output), "cannot write " + path.string());
}
struct TemporaryDirectory {
  std::filesystem::path path;
  TemporaryDirectory() {
    char pattern[] = "/tmp/phantom-memory-write-test-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    require(created != nullptr, "cannot create regression directory");
    path = created;
  }
  ~TemporaryDirectory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
};
struct Descriptor {
  int value;
  ~Descriptor() { if (value >= 0) (void)::close(value); }
};
const Json& variable(const GdbStop& stop, const std::string& name) {
  for (const auto& frame : stop.stack)
    for (const auto& value : frame.at("variables"))
      if (value.at("name") == name) return value;
  throw std::runtime_error("missing variable " + name);
}
void enterLoop(GdbEngine& engine, const GdbLaunchRequest& request, GdbStop& stop) {
  const auto& source = request.sourceBundle.documents.front().text;
  const auto marker = source.find("// GDB_TEST_LOOP_BREAKPOINT");
  require(marker != std::string::npos, "missing loop marker");
  const auto line = 1 + std::count(source.begin(), source.begin() + marker, '\n');
  Json result;
  GdbError error;
  require(engine.setBreakpoints({{"documentId", "fixture"}, {"breakpoints", Json::array({
      {{"id", "loop"}, {"range", {{"start", {{"line", line}, {"column", 1}}}}}, {"enabled", true}}})}}, result, error),
      "cannot install loop breakpoint: " + error.message);
  require(engine.resume("continue", stop, error) && stop.stopped && !stop.exited,
          "cannot reach loop: " + error.message);
}

void realEngine(GdbOptions options, GdbLaunchRequest request) {
  GdbEngine engine(options);
  GdbError error;
  GdbStop stop;
  Json result;
  bool attempted = true;
  require(!engine.prepareMemoryWrite(error), "prepared a dead debugger");
  require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && !attempted,
          "attempted a dead debugger write");
  require(!engine.refreshStoppedSnapshot(stop, error) && !stop.stopped, "refreshed a dead debugger");
  request.input = std::string(1024 * 1024, 'x');
  request.inputId = "initial-input";
  require(engine.launch(request, stop, error), "native launch failed: " + error.message);
  enterLoop(engine, request, stop);
  const auto address = variable(stop, "marker").at("addressHex").get<std::string>();
  const auto original = variable(stop, "marker").at("storage").at("rawBytesHex").get<std::string>();
  require(original == "2a000000", "unexpected initial marker storage");
  const auto originalLocation = stop.location;
  const auto originalOutput = stop.stdoutSnapshot;
  const auto originalError = stop.stderrSnapshot;
  Json registersBefore, registersAfter;
  require(engine.readRegisters({"rip", "rsp"}, registersBefore, error), "cannot read initial registers");
  require(engine.readVariables("frame:1", 0, 128, result, error), "cannot issue outer-frame handles");
  require(engine.inspectVariableLayout("frame:1:argc", result, error), "outer handle unavailable");
  require(engine.prepareMemoryWrite(error), "native stopped write refused: " + error.message);
  require(engine.writeMemoryBytes(address, "78563412", attempted, error) && attempted,
          "real memory write failed: " + error.message);
  require(engine.refreshStoppedSnapshot(stop, error), "refresh failed: " + error.message);
  require(stop.stopped && !stop.exited && stop.reason == "intervention" &&
          stop.processInstanceId == std::to_string(*engine.inferiorPid()), "refresh has wrong process/stop identity");
  require(stop.location == originalLocation && stop.stdoutSnapshot == originalOutput && stop.stderrSnapshot == originalError,
          "write/refresh advanced execution or changed output");
  require(variable(stop, "marker").at("storage").at("rawBytesHex") == "78563412" &&
          variable(stop, "marker").at("value").at("value").at("decimal") == "305419896",
          "fresh variable snapshot did not observe written storage");
  require(!engine.inspectVariableLayout("frame:1:argc", result, error) && error.code == "READ_FAILED",
          "refresh retained handles absent from the new observation");
  require(engine.inspectVariableLayout("frame:0:marker", result, error), "refresh did not reissue current handles");
  require(engine.readRegisters({"rip", "rsp"}, registersAfter, error) && registersBefore == registersAfter,
          "memory intervention changed registers");

  for (const auto& invalid : {"", "0x", "-1", "+1", " 10", "0x10\n-exec-continue", "0x10000000000000000",
                              "0xffffffffffffffff", "&marker", "marker()", "0x10+4"}) {
    attempted = true;
    require(!engine.writeMemoryBytes(invalid, "00", attempted, error) && !attempted &&
            error.code == "INVALID_REQUEST" && engine.live(), "unsafe/overflowing write address accepted");
  }
  for (const auto& invalid : {"", "0", "0g", " 00", "00\n", "0x00", "00 01"}) {
    attempted = true;
    require(!engine.writeMemoryBytes(address, invalid, attempted, error) && !attempted &&
            error.code == "INVALID_REQUEST", "unsafe write bytes accepted");
  }
  require(!engine.writeMemoryBytes(address, std::string(514, '0'), attempted, error) && !attempted &&
          error.code == "LIMIT_EXCEEDED", "oversized write accepted");
  require(!engine.writeMemoryBytes("0x0", "00", attempted, error) && attempted &&
          error.code == "READ_FAILED" && engine.live(), "GDB rejection lost attempted/live state");
  require(engine.writeMemoryBytes(address, original, attempted, error) && attempted, "cannot restore test marker");

  // Free pipe capacity externally while the inferior remains stopped. This
  // makes an accidental command()->drainIo()->feedInput call observable.
  const auto stdinPath = "/proc/" + std::to_string(*engine.inferiorPid()) + "/fd/0";
  Descriptor input{::open(stdinPath.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
  require(input.value >= 0, "cannot open fixture stdin FIFO");
  const int capacity = ::fcntl(input.value, F_GETPIPE_SZ);
  require(capacity > 0, "cannot inspect stdin capacity");
  const auto drain = [&] {
    std::array<char, 65536> bytes{};
    for (;;) {
      const auto count = ::read(input.value, bytes.data(), bytes.size());
      if (count > 0) continue;
      if (count < 0 && errno == EINTR) continue;
      require(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "stdin EOF was exposed early");
      break;
    }
  };
  Json inputSnapshot;
  require(engine.closeInput(inputSnapshot, error), "cannot inspect pending EOF");
  while (request.input.size() - inputSnapshot.at("deliveredBytes").get<std::size_t>() > static_cast<std::size_t>(capacity)) {
    drain();
    const auto previous = inputSnapshot.at("deliveredBytes");
    require(engine.closeInput(inputSnapshot, error) && inputSnapshot.at("deliveredBytes") > previous,
            "cannot arrange final pending input chunk");
  }
  require(inputSnapshot.at("status") == "reading" && inputSnapshot.at("eof") == "requested",
          "test did not retain pending bytes/EOF");
  drain();
  require(engine.readMemory(address, 4, result, error), "memory read with pending input failed");
  require(engine.prepareMemoryWrite(error), "prepare with pending input failed");
  require(engine.writeMemoryBytes(address, original, attempted, error) && attempted, "write with pending input failed");
  require(engine.refreshStoppedSnapshot(stop, error), "refresh with pending input failed");
  require(stop.input == inputSnapshot, "read/prepare/write/refresh delivered stdin or EOF");
  std::array<char, 1> byte{};
  require(::read(input.value, byte.data(), byte.size()) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "intervention fed or closed the inferior stdin pipe");
  require(engine.resume("instruction", stop, error) && stop.stopped, "normal execution failed after capture-only scope");
  require(stop.input.at("deliveredBytes") == request.input.size() && stop.input.at("status") == "complete",
          "capture-only scope leaked and prevented later stdin delivery/EOF");

  request.input.clear();
  request.recordingProfile = "gdb-record-full";
  require(engine.launch(request, stop, error), "record-full launch failed: " + error.message);
  require(!engine.prepareMemoryWrite(error) && error.code == "UNSUPPORTED", "record-full write prepared");
  require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && !attempted && error.code == "UNSUPPORTED",
          "record-full memory mutation attempted");
  require(!engine.refreshStoppedSnapshot(stop, error) && error.code == "UNSUPPORTED", "record-full intervention refresh accepted");
}

void fakeDebugger(GdbOptions options, const GdbLaunchRequest& request) {
  TemporaryDirectory temporary;
  const auto script = temporary.path / "fake-gdb";
  const auto mode = temporary.path / "mode";
  const auto log = temporary.path / "commands";
  writeFile(mode, "single");
  // Keep responses synthetic to exercise thread-state and send-boundary
  // failures deterministically; real memory semantics are checked above.
  writeFile(script, R"PY(#!/usr/bin/env python3
import json, os, pathlib, re, sys
root = pathlib.Path(__file__).parent
for line in sys.stdin:
    token, command = re.match(r'(\d+)(.*)', line.rstrip('\n')).groups()
    with (root / 'commands').open('a') as log:
        log.write(command + '\n')
    mode = (root / 'mode').read_text()
    if command == '-exec-run':
        print('=thread-group-started,id="i1",pid="' + str(os.getpid()) + '"')
        print(token + '^running')
        print('*stopped,reason="breakpoint-hit",thread-id="1",frame={level="0",func="main",addr="0x1000"}')
    elif command == '-stack-list-frames':
        print(token + '^done,stack=[]')
    elif command == '-stack-info-frame':
        print(token + '^done,frame={level="0",func="main",addr="0x1000"}')
    elif command == '-thread-info':
        threads = {
            'single': 'threads=[{id="1",state="stopped"}],current-thread-id="1"',
            'multiple': 'threads=[{id="1",state="stopped"},{id="2",state="stopped"}],current-thread-id="1"',
            'running': 'threads=[{id="1",state="running"}],current-thread-id="1"',
            'empty': 'threads=[]',
            'missing-state': 'threads=[{id="1"}],current-thread-id="1"',
            'wrong-current': 'threads=[{id="1",state="stopped"}],current-thread-id="2"',
            'wrong-list': 'threads={id="1",state="stopped"},current-thread-id="1"',
            'duplicate-state': 'threads=[{id="1",state="stopped",state="running"}],current-thread-id="1"',
        }
        print(token + '^done,' + threads.get(mode, threads['single']))
    elif command.startswith('-data-write-memory-bytes '):
        if mode == 'write-error': print(token + '^error,msg="write rejected after command sent"')
        elif mode == 'write-eof': sys.exit(0)
        elif mode == 'write-unknown': print(token + '^unexpected')
        else: print(token + '^done')
    elif command.startswith('-data-read-memory-bytes '):
        if mode == 'recorder-stopped': print('=record-stopped,thread-group="i1"')
        address = int(command.split()[1], 16)
        count = int(command.split()[2])
        print(token + '^done,memory=[{begin="' + hex(address) + '",end="' + hex(address + count) +
              '",offset="0x0",contents="' + '00' * count + '"}]')
    elif command == '-interpreter-exec console "info record"':
        print('~' + json.dumps('Active record target: record-full\nRecord mode:\nNo instructions have been logged.\nMax logged instructions is 200000.\n'))
        print(token + '^done')
    else:
        print(token + '^done')
    sys.stdout.flush()
)PY");
  require(::chmod(script.c_str(), 0700) == 0, "cannot mark fake debugger executable");
  options.gdbPath = script;
  GdbEngine engine(options);
  GdbStop stop;
  GdbError error;
  bool attempted = false;
  require(engine.launch(request, stop, error), "fake launch failed: " + error.message);
  require(engine.prepareMemoryWrite(error), "fake single-thread check failed");
  for (const auto* value : {"multiple", "running", "empty", "missing-state", "wrong-current", "wrong-list", "duplicate-state"}) {
    writeFile(mode, value);
    require(!engine.prepareMemoryWrite(error), "invalid fake thread state prepared");
    const auto before = readFile(log);
    attempted = true;
    require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && !attempted && engine.live(),
            "invalid fake thread state allowed a mutation");
    const auto added = readFile(log).substr(before.size());
    require(added.find("-data-write-memory-bytes") == std::string::npos,
            "thread rejection sent a mutating command");
  }
  writeFile(mode, "single");
  require(engine.writeMemoryBytes("DEAD", "AbCD", attempted, error) && attempted, "canonical test write failed");
  require(readFile(log).find("-data-write-memory-bytes 0xdead abcd\n") != std::string::npos,
          "write did not canonicalize address/bytes or supplied a repeat count");
  require(engine.writeMemoryBytes("0x1000", std::string(512, 'F'), attempted, error) && attempted,
          "256-byte boundary rejected");
  writeFile(mode, "write-error");
  require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && attempted && engine.live(),
          "failed write lost attempted state");
  writeFile(mode, "write-unknown");
  require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && attempted && error.code == "READ_FAILED",
          "unknown MI acknowledgement accepted as a completed write");
  require(!engine.live(), "malformed MI acknowledgement must fail closed");
  writeFile(mode, "single");
  require(engine.launch(request, stop, error), "relaunch after malformed MI failed: " + error.message);
  writeFile(mode, "write-eof");
  const bool eofResult = engine.writeMemoryBytes("0x1000", "00", attempted, error);
  require(!eofResult && attempted && !engine.live(),
          "debugger loss was not marked attempted and failed closed: result=" + std::to_string(eofResult) +
          " attempted=" + std::to_string(attempted) + " live=" + std::to_string(engine.live()) +
          " error=" + error.code + " " + error.message);

  writeFile(mode, "single");
  auto recorded = request;
  recorded.recordingProfile = "gdb-record-full";
  require(engine.launch(recorded, stop, error), "fake recording launch failed: " + error.message);
  writeFile(mode, "recorder-stopped");
  Json result;
  require(engine.readMemory("0x1000", 1, result, error), "cannot inject recorder-stopped notification");
  require(engine.readRecording(result, error) && result.at("reason") == "recording-not-active",
          "test did not deactivate the recorder");
  const auto before = readFile(log);
  require(!engine.prepareMemoryWrite(error) && error.code == "UNSUPPORTED", "inactive record profile prepared");
  require(!engine.writeMemoryBytes("0x1000", "00", attempted, error) && !attempted && error.code == "UNSUPPORTED",
          "inactive record profile allowed a write");
  require(readFile(log) == before, "record profile rejection unexpectedly sent MI commands");
}
}  // namespace

int main(int argc, char** argv) try {
  require(argc == 4, "expected fixture, I/O wrapper and fixture source");
  GdbOptions options;
  options.execWrapper = std::filesystem::absolute(argv[2]);
  options.commandTimeout = 5s;
  GdbLaunchRequest request;
  request.binaryPath = std::filesystem::absolute(argv[1]);
  request.sourceBundle.id = "memory-write-source";
  request.sourceBundle.documents.push_back({"fixture", "revision-1", std::filesystem::absolute(argv[3]), readFile(argv[3])});
  realEngine(options, request);
  fakeDebugger(options, request);
  std::cout << "memory write engine checks passed\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
