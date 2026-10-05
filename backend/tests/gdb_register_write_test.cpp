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
    char pattern[] = "/tmp/phantom-register-write-test-XXXXXX";
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
  require(!engine.prepareRegisterWrite("rax", result, error) && result.is_null(), "prepared dead debugger");
  require(!engine.readRegisterValue("rax", result, error) && result.is_null(), "read dead debugger");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && !attempted,
          "attempted dead debugger write");
  require(engine.launch(request, stop, error), "native launch failed: " + error.message);
  enterLoop(engine, request, stop);
  const auto original = stop;
  Json protectedBefore, protectedAfter;
  require(engine.readRegisters({"rip", "rsp", "rbp", "eflags", "fs_base", "gs_base"}, protectedBefore, error),
          "cannot read protected register baseline");
  for (const auto* name : {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}) {
    Json initial, target;
    require(engine.readRegisterValue(name, initial, error), "initial read failed: " + std::string(name) + ": " + error.message);
    auto expectedTarget = initial;
    expectedTarget.erase("valueHex");
    require(expectedTarget == Json({{"architecture", "x86_64"}, {"register", name}, {"bits", 64},
            {"threadId", stop.threadId}, {"frameLevel", 0}}), "incorrect register binding");
    require(engine.readVariables("frame:1", 0, 128, result, error), "cannot select caller frame");
    require(engine.prepareRegisterWrite(name, target, error) && target == expectedTarget,
            "preparation did not restore the innermost frame");
    for (const auto* value : {"0xffffffffffffffff", "0x8000000000000000", "0x0123456789abcdef", "0x0000000000000000"}) {
      require(engine.readVariables("frame:1", 0, 128, result, error), "cannot reselect caller frame");
      require(engine.writeRegisterValue(name, value, attempted, error) && attempted,
              "real register write failed: " + std::string(name) + ": " + error.code + ": " + error.message);
      require(engine.readRegisterValue(name, result, error) && result.at("valueHex") == value,
              "full-width register bits changed during read/write: " + std::string(name));
    }
    require(engine.writeRegisterValue(name, initial.at("valueHex").get<std::string>(), attempted, error) && attempted,
            "cannot restore fixture register");
  }
  require(engine.readRegisters({"rip", "rsp", "rbp", "eflags", "fs_base", "gs_base"}, protectedAfter, error) &&
          protectedBefore == protectedAfter, "general register writes changed protected registers");
  require(engine.refreshStoppedSnapshot(stop, error) && stop.stopped && !stop.exited &&
          stop.location == original.location && stop.stdoutSnapshot == original.stdoutSnapshot &&
          stop.stderrSnapshot == original.stderrSnapshot && stop.stack == original.stack,
          "register round-trips or refresh executed code or changed stack storage");

  for (const auto* name : {"", "RAX", "$rax", "eax", "ax", "al", "ah", "rip", "eip", "pc", "rsp", "sp", "rbp", "bp",
                          "eflags", "rflags", "cs", "ss", "ds", "fs", "gs", "fs_base", "gs_base", "orig_rax", "xmm0", "st0",
                          "r16", "r8d", "rax=0", "rax\n-exec-continue", "rax;call evil()"}) {
    require(!engine.prepareRegisterWrite(name, result, error) && result.is_null() && error.code == "INVALID_REQUEST",
            "forbidden register prepared: " + std::string(name));
    require(!engine.readRegisterValue(name, result, error) && result.is_null() && error.code == "INVALID_REQUEST",
            "forbidden register read through mutation primitive");
    attempted = true;
    require(!engine.writeRegisterValue(name, "0x0000000000000000", attempted, error) && !attempted &&
            error.code == "INVALID_REQUEST" && engine.live(), "forbidden register mutation attempted");
  }
  for (const auto* value : {"", "0", "0x0", "0000000000000000", "0X0000000000000000", "0x000000000000000A", "-1",
                           "0x10000000000000000", "0x000000000000000g", "0x0000000000000000\n", "0x0000000000000000+1",
                           "(unsigned long)0", "$rax", "evil()"}) {
    attempted = true;
    require(!engine.writeRegisterValue("rax", value, attempted, error) && !attempted && error.code == "INVALID_REQUEST",
            "nonliteral/noncanonical register value accepted");
  }

  // Arrange free pipe capacity with both queued input and EOF pending. No
  // preparation, register read/write or refresh may expose those bytes.
  request.input = std::string(1024 * 1024, 'x');
  request.inputId = "pending-input";
  require(engine.launch(request, stop, error), "input fixture launch failed");
  enterLoop(engine, request, stop);
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
      require(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), "stdin EOF exposed early");
      break;
    }
  };
  Json inputSnapshot;
  require(engine.closeInput(inputSnapshot, error), "cannot inspect pending EOF");
  while (request.input.size() - inputSnapshot.at("deliveredBytes").get<std::size_t>() > static_cast<std::size_t>(capacity)) {
    drain();
    const auto previous = inputSnapshot.at("deliveredBytes");
    require(engine.closeInput(inputSnapshot, error) && inputSnapshot.at("deliveredBytes") > previous,
            "cannot arrange pending final chunk");
  }
  require(inputSnapshot.at("status") == "reading" && inputSnapshot.at("eof") == "requested",
          "test lost pending bytes/EOF");
  drain();
  require(engine.prepareRegisterWrite("rax", result, error), "prepare with pending input failed");
  require(engine.readRegisterValue("rax", result, error), "read with pending input failed");
  require(engine.writeRegisterValue("rax", result.at("valueHex").get<std::string>(), attempted, error) && attempted,
          "write with pending input failed");
  require(engine.refreshStoppedSnapshot(stop, error) && stop.input == inputSnapshot,
          "register primitives/refresh delivered pending input or EOF");
  std::array<char, 1> byte{};
  require(::read(input.value, byte.data(), byte.size()) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "register intervention fed or closed stdin pipe");
  require(engine.resume("instruction", stop, error) && stop.stopped &&
          stop.input.at("deliveredBytes") == request.input.size() && stop.input.at("status") == "complete",
          "capture-only register scope leaked into subsequent execution");

  request.input.clear();
  request.recordingProfile = "gdb-record-full";
  require(engine.launch(request, stop, error), "record-full launch failed: " + error.message);
  require(!engine.prepareRegisterWrite("rax", result, error) && error.code == "UNSUPPORTED", "record-full register prepared");
  require(!engine.readRegisterValue("rax", result, error) && error.code == "UNSUPPORTED", "record-full write primitive read accepted");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && !attempted &&
          error.code == "UNSUPPORTED", "record-full register mutation attempted");

  request.recordingProfile = "native";
  request.closeInputAfterWrite = false;
  request.argv = {"trace-input"};
  require(engine.launch(request, stop, error), "input-wait launch failed");
  const bool resumedToInput = engine.resume("continue", stop, error);
  require(!resumedToInput && error.code == "INPUT_WAIT" && stop.stopped && !stop.exited && stop.reason == "input-wait",
          "fixture did not reach input wait: " + stop.reason + ": " + error.message);
  require(!engine.prepareRegisterWrite("rax", result, error) && error.code == "UNSUPPORTED", "input-wait register prepared");
  require(!engine.readRegisterValue("rax", result, error) && error.code == "UNSUPPORTED", "input-wait write primitive read accepted");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && !attempted &&
          error.code == "UNSUPPORTED", "input-wait register mutation attempted");
  require(engine.appendInput("resume-input", "z", result, error), "input wait no longer accepts input");
  require(engine.resume("continue", stop, error) && stop.exited && stop.exitCode == 122,
          "rejected register mutation damaged input recovery");
}

void fakeDebugger(GdbOptions options, const GdbLaunchRequest& request) {
  TemporaryDirectory temporary;
  const auto script = temporary.path / "fake-gdb";
  const auto mode = temporary.path / "mode";
  const auto log = temporary.path / "commands";
  writeFile(mode, "single");
  writeFile(script, R"PY(#!/usr/bin/env python3
import json, os, pathlib, re, sys
root = pathlib.Path(__file__).parent
stored = '0x123456789abcdef0'
for line in sys.stdin:
    token, command = re.match(r'(\d+)(.*)', line.rstrip('\n')).groups()
    with (root / 'commands').open('a') as log: log.write(command + '\n')
    mode = (root / 'mode').read_text()
    if command == '-exec-run':
        print('=thread-group-started,id="i1",pid="' + str(os.getpid()) + '"')
        print(token + '^running')
        print('*stopped,reason="breakpoint-hit",thread-id="1",frame={level="0",func="main",addr="0x1000"}')
    elif command == '-stack-list-frames': print(token + '^done,stack=[]')
    elif command == '-stack-info-frame': print(token + '^done,frame={level="0",func="main",addr="0x1000"}')
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
            'invalid-id': 'threads=[{id="1 bad",state="stopped"}],current-thread-id="1 bad"',
        }
        print(token + '^done,' + threads.get(mode, threads['single']))
    elif command.startswith('-thread-select '):
        fields = 'new-thread-id="2"' if mode == 'bad-selection' else 'new-thread-id="1"'
        if mode == 'duplicate-selection': fields += ',new-thread-id="1"'
        print(token + '^done,' + fields)
    elif command == '-list-features':
        print(token + '^done,features=[' + ('' if mode == 'no-python' else '"python"') + ']')
    elif 'PHANTOM_REGISTER_TARGET_V1:' in command:
        data = {'architecture':'i386:x86-64','register':'rax','bits':64,'threadId':'1','frameLevel':0}
        if mode == 'architecture': data['architecture'] = 'i386'
        if mode == 'width': data['bits'] = 32
        if mode == 'boolean-width': data['bits'] = True
        if mode == 'float-width': data['bits'] = 64.0
        if mode == 'register-name': data['register'] = 'rbx'
        if mode == 'metadata-thread': data['threadId'] = '2'
        if mode == 'metadata-frame': data['frameLevel'] = 1
        if mode == 'metadata-boolean-frame': data['frameLevel'] = False
        if mode == 'metadata-extra': data['unknown'] = True
        if mode == 'metadata-missing': del data['bits']
        text = json.dumps(data)
        if mode == 'metadata-duplicate': text = text[:-1] + ',"bits":64}'
        if mode == 'metadata-trailing': text += '{}'
        print('~' + json.dumps('PHANTOM_REGISTER_TARGET_V1:' + text + '\n'))
        print(token + '^done')
    elif command == '-data-list-register-names':
        names = '["", "rip", "rsp", "rax", "rbx"]'
        if mode == 'names-duplicate': names = '["rax", "rax"]'
        if mode == 'names-other-duplicate': names = '["rax", "rsp", "rsp"]'
        if mode == 'names-missing': names = '["rbx"]'
        if mode == 'names-type': names = '[{name="rax"}]'
        if mode == 'names-object': names = '{name="rax"}'
        names = names.replace(', ', ',')
        suffix = ',register-names=' + names if mode == 'names-repeat' else ''
        print(token + '^done,register-names=' + names + suffix)
    elif command.startswith('-data-list-register-values --thread '):
        fields = 'register-values=[{number="3",value="' + stored + '"}]'
        if mode == 'read-missing': fields = 'register-values=[]'
        if mode == 'read-duplicate': fields = 'register-values=[{number="3",value="0x1",value="0x2"}]'
        if mode == 'read-duplicate-index': fields = 'register-values=[{number="3",number="3",value="0x1"}]'
        if mode == 'read-extra': fields = 'register-values=[{number="3",value="0x1",extra="x"}]'
        if mode == 'read-wrong-index': fields = 'register-values=[{number="0",value="0x1"}]'
        if mode == 'read-leading-index': fields = 'register-values=[{number="03",value="0x1"}]'
        if mode == 'read-overflow': fields = 'register-values=[{number="3",value="0x10000000000000000"}]'
        if mode == 'read-unavailable': fields = 'register-values=[{number="3",value="<unavailable>"}]'
        if mode == 'read-expression': fields = 'register-values=[{number="3",value="0x1+1"}]'
        if mode == 'read-tuple': fields = 'register-values={number="3",value="0x1"}'
        if mode == 'read-many': fields = 'register-values=[{number="3",value="0x1"},{number="4",value="0x2"}]'
        if mode == 'read-upper': fields = 'register-values=[{number="3",value="0xABC"}]'
        if mode == 'read-zero': fields = 'register-values=[{number="3",value="0x0"}]'
        if mode == 'read-repeat': fields += ',' + fields
        print(token + '^done,' + fields)
    elif command.startswith('-data-write-register-values '):
        if mode == 'write-error': print(token + '^error,msg="write rejected after submission"')
        elif mode == 'write-eof': sys.exit(0)
        elif mode == 'write-unknown': print(token + '^unexpected')
        else:
            stored = command.split()[-1]
            print(token + '^done')
    elif command == '-interpreter-exec console "info record"':
        print('~' + json.dumps('Active record target: record-full\nRecord mode:\nNo instructions have been logged.\nMax logged instructions is 200000.\n'))
        print(token + '^done')
    else: print(token + '^done')
    sys.stdout.flush()
)PY");
  require(::chmod(script.c_str(), 0700) == 0, "cannot make fake debugger executable");
  options.gdbPath = script;
  GdbEngine engine(options);
  GdbStop stop;
  GdbError error;
  Json result;
  bool attempted = true;
  require(engine.launch(request, stop, error), "fake launch failed: " + error.message);
  require(engine.readRegisterValue("rax", result, error) && result.at("valueHex") == "0x123456789abcdef0",
          "fake initial register read failed: " + error.message);
  require(engine.writeRegisterValue("rax", "0xffffffffffffffff", attempted, error) && attempted,
          "dynamic register-index write failed");
  require(readFile(log).find("-data-write-register-values --thread 1 --frame 0 x 3 0xffffffffffffffff\n") != std::string::npos,
          "register write hardcoded an index, lost frame selection or changed literal bits");
  for (const auto* rejected : {"multiple", "running", "empty", "missing-state", "wrong-current", "wrong-list", "duplicate-state", "invalid-id",
                              "bad-selection", "duplicate-selection", "no-python", "architecture", "width", "boolean-width", "float-width",
                              "register-name", "metadata-thread", "metadata-frame", "metadata-boolean-frame", "metadata-extra", "metadata-missing",
                              "metadata-duplicate", "metadata-trailing", "names-duplicate", "names-other-duplicate", "names-missing", "names-type",
                              "names-object", "names-repeat"}) {
    writeFile(mode, rejected);
    require(!engine.prepareRegisterWrite("rax", result, error) && result.is_null(), "invalid metadata prepared: " + std::string(rejected));
    require(!engine.readRegisterValue("rax", result, error) && result.is_null(), "invalid metadata read: " + std::string(rejected));
    const auto before = readFile(log);
    attempted = true;
    require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && !attempted && engine.live(),
            "invalid metadata allowed attempted write: " + std::string(rejected));
    require(readFile(log).substr(before.size()).find("-data-write-register-values") == std::string::npos,
            "metadata rejection sent mutating command");
  }
  for (const auto* rejected : {"read-missing", "read-duplicate", "read-duplicate-index", "read-extra", "read-wrong-index", "read-leading-index",
                              "read-overflow", "read-unavailable", "read-expression", "read-tuple", "read-many", "read-repeat"}) {
    writeFile(mode, rejected);
    require(!engine.readRegisterValue("rax", result, error) && result.is_null() && error.code == "READ_FAILED" && engine.live(),
            "malformed register value accepted: " + std::string(rejected));
  }
  writeFile(mode, "read-upper");
  require(engine.readRegisterValue("rax", result, error) && result.at("valueHex") == "0x0000000000000abc", "MI hex was not canonicalized");
  writeFile(mode, "read-zero");
  require(engine.readRegisterValue("rax", result, error) && result.at("valueHex") == "0x0000000000000000", "zero MI hex was not padded");
  writeFile(mode, "write-error");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && attempted && engine.live(),
          "failed register write lost attempted state");
  writeFile(mode, "single");
  require(engine.readRegisterValue("rax", result, error) && result.at("valueHex") == "0xffffffffffffffff",
          "independent readback unavailable after rejected register write");
  writeFile(mode, "write-unknown");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && attempted && !engine.live(),
          "unknown write acknowledgement did not fail closed");
  writeFile(mode, "single");
  require(engine.launch(request, stop, error), "fake relaunch failed");
  writeFile(mode, "write-eof");
  require(!engine.writeRegisterValue("rax", "0x0000000000000000", attempted, error) && attempted && !engine.live(),
          "debugger loss was not an attempted write/fail-closed result");
}
}  // namespace

int main(int argc, char** argv) try {
  require(argc == 4, "expected fixture, I/O wrapper and fixture source");
  GdbOptions options;
  options.execWrapper = std::filesystem::absolute(argv[2]);
  options.commandTimeout = 5s;
  GdbLaunchRequest request;
  request.binaryPath = std::filesystem::absolute(argv[1]);
  request.sourceBundle.id = "register-write-source";
  request.sourceBundle.documents.push_back({"fixture", "revision-1", std::filesystem::absolute(argv[3]), readFile(argv[3])});
  realEngine(options, request);
  fakeDebugger(options, request);
  std::cout << "register write engine checks passed\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
