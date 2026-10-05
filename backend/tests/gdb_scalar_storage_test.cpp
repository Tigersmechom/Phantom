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

using Json = nlohmann::json;
using namespace std::chrono_literals;
namespace {
void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}
std::string readFile(const std::filesystem::path& path) {
  std::ifstream input(path);
  require(bool(input), "cannot read fixture");
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void writeFile(const std::filesystem::path& path, const std::string& content) {
  std::ofstream output(path, std::ios::binary);
  output << content;
  output.close();
  require(bool(output), "cannot write test file");
}
struct TemporaryDirectory {
  std::filesystem::path path;
  TemporaryDirectory() {
    char pattern[] = "/tmp/phantom-scalar-metadata-test-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    require(created != nullptr, "cannot create metadata regression directory");
    path = created;
  }
  ~TemporaryDirectory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
};
bool hasVariable(const phantom::GdbStop& stop, std::string_view name) {
  for (const auto& frame : stop.stack)
    for (const auto& variable : frame.at("variables"))
      if (variable.at("name") == name) return true;
  return false;
}
Json inspect(phantom::GdbEngine& engine, std::string_view name, unsigned level = 0) {
  phantom::GdbError error;
  Json result;
  const auto locator = "frame:" + std::to_string(level) + ":" + std::string(name);
  const bool ok = engine.inspectScalarStorage(locator, result, error);
  require(ok, "inspection failed for " + locator + ": " + error.code + ": " + error.message);
  require(result.at("locator") == locator && result.at("lifetime") == "unknown" &&
          result.at("source") == "gdb-python-dwarf", "wrong scalar metadata scope");
  return result;
}
void breakpoint(phantom::GdbEngine& engine, const phantom::GdbLaunchRequest& request,
                std::string_view marker, unsigned document = 0) {
  const auto& source = request.sourceBundle.documents.at(document);
  const auto offset = source.text.find(marker);
  require(offset != std::string::npos, "missing source marker");
  const auto line = 1 + std::count(source.text.begin(), source.text.begin() + offset, '\n');
  phantom::GdbError error;
  Json result;
  require(engine.setBreakpoints({{"documentId", source.documentId}, {"breakpoints", Json::array({
      {{"id", "scalar-stop"}, {"range", {{"start", {{"line", line}, {"column", 1}}}}}, {"enabled", true}}})}}, result, error),
      "breakpoint failed: " + error.message);
  require(result[0].at("verified") == true, "unresolved breakpoint");
}
void resume(phantom::GdbEngine& engine, phantom::GdbStop& stop) {
  phantom::GdbError error;
  const bool ok = engine.resume("continue", stop, error);
  require(ok && stop.stopped && !stop.exited, "resume failed: " + error.code + ": " + error.message);
}

void malformedMetadata(phantom::GdbOptions options, phantom::GdbLaunchRequest request) {
  TemporaryDirectory temporary;
  const auto proxy = temporary.path / "gdb-proxy";
  const auto payload = temporary.path / "payload";
  const auto commandLog = temporary.path / "commands";
  // A real stopped inferior supplies the issued locator and native thread
  // evidence. Replace only the metadata response, keeping corruption tests
  // independent of launch/snapshot MI emulation and target execution.
  writeFile(proxy, R"PY(#!/usr/bin/env python3
import json, pathlib, re, subprocess, sys, threading
root = pathlib.Path(__file__).parent
child = subprocess.Popen(['gdb', *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
lock = threading.Lock()
def output(line):
    with lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
def forward():
    for line in child.stdout:
        output(line)
reader = threading.Thread(target=forward, daemon=True)
reader.start()
try:
    for line in sys.stdin.buffer:
        token, command = re.match(rb'(\d+)(.*)', line.rstrip(b'\n')).groups()
        with (root / 'commands').open('ab') as log:
            log.write(command + b'\n')
        if b'PHANTOM_SCALAR_STORAGE_V1:' in command and (root / 'payload').exists():
            data = (root / 'payload').read_text()
            output(b'~' + json.dumps(data).encode() + b'\n' + token + b'^done\n')
        else:
            child.stdin.write(line)
            child.stdin.flush()
finally:
    if child.poll() is None: child.terminate()
    try: child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    reader.join(timeout=3)
)PY");
  require(::chmod(proxy.c_str(), 0700) == 0, "cannot make debugger proxy executable");
  options.gdbPath = proxy;
  request.recordingProfile = "native";
  request.input.clear();
  phantom::GdbEngine engine(options);
  phantom::GdbError error;
  phantom::GdbStop stop;
  require(engine.launch(request, stop, error), "metadata proxy launch failed: " + error.message);
  breakpoint(engine, request, "SCALAR_READY");
  resume(engine, stop);
  const auto valid = inspect(engine, "s32");
  require(valid.at("available") == true, "proxy baseline metadata unavailable");
  Json registersBefore, registersAfter;
  require(engine.readRegisters({"rip", "rsp"}, registersBefore, error), "cannot read proxy baseline registers");
  const auto beforeInput = stop.input;
  const auto logSize = readFile(commandLog).size();
  const auto response = [&](const Json& target) {
    writeFile(payload, "PHANTOM_SCALAR_STORAGE_V1:" + target.dump() + "\n");
  };
  const auto reject = [&](const Json& target, const std::string& label) {
    response(target);
    Json result = {{"old", "value"}};
    require(!engine.inspectScalarStorage("frame:0:s32", result, error) && error.code == "READ_FAILED" &&
            result.is_null() && engine.live(), "accepted malformed metadata: " + label);
  };
  for (const auto* field : {"available", "source", "locator", "lifetime", "reason", "typeName", "scalar", "addressHex"}) {
    auto target = valid;
    target.erase(field);
    reject(target, std::string("missing target ") + field);
  }
  for (const auto* field : {"kind", "byteSize", "bits", "signed", "byteOrder", "representation"}) {
    auto target = valid;
    target["scalar"].erase(field);
    reject(target, std::string("missing scalar ") + field);
  }
  auto bad = valid; bad["extra"] = true; reject(bad, "extra target field");
  bad = valid; bad["scalar"]["extra"] = true; reject(bad, "extra scalar field");
  bad = valid; bad["source"] = "foreign"; reject(bad, "source mismatch");
  bad = valid; bad["locator"] = "frame:0:u32"; reject(bad, "locator mismatch");
  bad = valid; bad["lifetime"] = "alive"; reject(bad, "unsupported lifetime claim");
  bad = valid; bad["available"] = "true"; reject(bad, "non-boolean availability");
  bad = valid; bad["scalar"]["signed"] = "unknown"; reject(bad, "unknown signedness");
  bad = valid; bad["scalar"]["signed"] = nullptr; reject(bad, "null integer signedness");
  bad = valid; bad["scalar"]["byteSize"] = 3; bad["scalar"]["bits"] = 24; reject(bad, "unsupported integer width");
  bad = valid; bad["scalar"]["byteSize"] = -4294967292LL; reject(bad, "wrapping negative width");
  bad = valid; bad["scalar"]["byteSize"] = 4.0; reject(bad, "floating byte size");
  bad = valid; bad["scalar"]["bits"] = 32.0; reject(bad, "floating bit size");
  bad = valid; bad["scalar"]["bits"] = 64; reject(bad, "width inconsistency");
  bad = valid; bad["scalar"]["byteOrder"] = "big"; reject(bad, "unsupported byte order");
  bad = valid; bad["scalar"]["representation"] = "unsigned-binary"; reject(bad, "signedness/representation inconsistency");
  bad = valid; bad["scalar"]["representation"] = "sign-magnitude"; reject(bad, "unknown integer representation");
  bad = valid; bad["scalar"]["kind"] = "float"; reject(bad, "unknown scalar kind");
  bad = valid; bad["scalar"] = nullptr; reject(bad, "available without type evidence");
  bad = valid; bad["reason"] = "optimized-out"; reject(bad, "available with rejection reason");
  bad = valid; bad["available"] = false; reject(bad, "unavailable with memory address");
  bad = valid; bad["typeName"] = std::string(257, 'x'); reject(bad, "oversized type name");
  for (const auto* address : {"dead", "0x", "0X1234", "0x123A", "0x001234", "0x10000000000000000",
                             "0xffffffffffffffff", "0xfffffffffffffffc", "0x1000+4", "0x1000\n-exec-continue", "counter()"}) {
    bad = valid; bad["addressHex"] = address; reject(bad, "invalid address");
  }
  for (const auto& text : {std::string("PHANTOM_SCALAR_STORAGE_V1:") + std::string(4097, 'x'),
                           std::string("PHANTOM_SCALAR_STORAGE_V1:{"), std::string("WRONG_PREFIX:"),
                           std::string("PHANTOM_SCALAR_STORAGE_V1:[]\n")}) {
    writeFile(payload, text);
    Json result;
    require(!engine.inspectScalarStorage("frame:0:s32", result, error) && error.code == "READ_FAILED" &&
            result.is_null() && engine.live(), "accepted malformed metadata framing");
  }
  bad = valid;
  bad["available"] = false; bad["addressHex"] = nullptr; bad["scalar"] = nullptr;
  bad["reason"] = "signedness-unavailable";
  response(bad);
  require(inspect(engine, "s32") == bad, "missing GDB signedness must remain an explicit unavailable target");
  response(valid);
  require(inspect(engine, "s32") == valid, "valid metadata rejected after corruption");
  require(engine.readRegisters({"rip", "rsp"}, registersAfter, error) && registersBefore == registersAfter,
          "metadata validation changed inferior registers");
  require(engine.refreshStoppedSnapshot(stop, error) && stop.input == beforeInput, "metadata validation delivered stdin");
  const auto added = readFile(commandLog).substr(logSize);
  require(added.find("-exec-") == std::string::npos && added.find("-data-write-") == std::string::npos,
          "metadata validation executed or wrote the inferior");
  engine.stop();
}
}

int main(int argc, char** argv) try {
  require(argc == 5, "expected fixture, wrapper, fixture source, optimized fixture source");
  phantom::GdbOptions options;
  options.execWrapper = std::filesystem::absolute(argv[2]);
  options.commandTimeout = 5s;
  phantom::GdbEngine engine(options);
  phantom::GdbLaunchRequest request;
  request.binaryPath = std::filesystem::absolute(argv[1]);
  request.sourceBundle.id = "scalar-source";
  request.sourceBundle.documents.push_back({"scalar.cpp", "revision-1", std::filesystem::absolute(argv[3]), readFile(argv[3])});
  request.sourceBundle.documents.push_back({"optimized.cpp", "revision-1", std::filesystem::absolute(argv[4]), readFile(argv[4])});
  // A large queued input exercises inspection's capture-only IO guard.
  request.input = std::string(1024 * 1024, 'q');
  request.inputId = "scalar-input";
  phantom::GdbError error;
  phantom::GdbStop stop;
  Json result;
  require(!engine.inspectScalarStorage("frame:0:s32", result, error) && result.is_null(), "inspected dead process");
  require(engine.launch(request, stop, error), "launch failed: " + error.message);
  breakpoint(engine, request, "SCALAR_READY");
  resume(engine, stop);
  Json beforeRegisters, afterRegisters;
  require(engine.readRegisters({"rip", "rsp", "rbp"}, beforeRegisters, error), "cannot read baseline registers");
  const auto beforeInput = stop.input;
  const auto beforeLocation = stop.location;
  const auto beforeOutput = stop.stdoutSnapshot;
  const auto stdinPath = "/proc/" + std::to_string(*engine.inferiorPid()) + "/fd/0";
  const int inputFd = ::open(stdinPath.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  require(inputFd >= 0, "cannot open fixture input pipe");
  {
    std::array<char, 65536> bytes{};
    for (;;) {
      const auto count = ::read(inputFd, bytes.data(), bytes.size());
      if (count > 0) continue;
      if (count < 0 && errno == EINTR) continue;
      const bool pending = count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
      ::close(inputFd);
      require(pending, "fixture stdin closed before scalar inspection");
      break;
    }
  }
  for (const unsigned bytes : {1U, 2U, 4U, 8U}) {
    for (const bool isSigned : {false, true}) {
      const auto name = std::string(isSigned ? "s" : "u") + std::to_string(bytes * 8);
      const auto target = inspect(engine, name);
      require(target.at("available") == true && target.at("reason").is_null() && target.at("addressHex").is_string(),
              "supported scalar unavailable: " + target.dump());
      require(target.at("scalar") == Json({{"kind", "integer"}, {"byteSize", bytes}, {"bits", bytes * 8},
          {"signed", isSigned}, {"byteOrder", "little"}, {"representation", isSigned ? "twos-complement" : "unsigned-binary"}}),
          "wrong signedness/width: " + target.dump());
    }
  }
  const auto flag = inspect(engine, "flag");
  require(flag.at("available") == true && flag.at("scalar") == Json({{"kind", "boolean"}, {"byteSize", 1},
      {"bits", 8}, {"signed", nullptr}, {"byteOrder", "little"}, {"representation", "boolean-01"}}), "bool encoding wrong");
  require(inspect(engine, "character").at("available") == true, "plain char unsupported");
  for (const auto name : {"constant", "changing", "both", "atomicValue", "reference", "rvalueReference",
                           "pointer", "array", "floating", "enumeration", "wide", "hostile"}) {
    const auto target = inspect(engine, name);
    require(target.at("available") == false && target.at("addressHex").is_null() && target.at("reason").is_string(),
            "unsupported type gained writable storage: " + target.dump());
  }
  if (hasVariable(stop, "cAtomic")) {
    const auto atomic = inspect(engine, "cAtomic");
    require(atomic.at("available") == false && atomic.at("reason") == "scalar-representation-unsupported",
            "_Atomic int was confused with ordinary int: " + atomic.dump());
  }
  for (const auto locator : {"", "s32", "frame:00:s32", "frame:0:s32[0]", "frame:0:s32()", "frame:0:*pointer",
                             "frame:0:s32\n-exec-continue", "frame:4096:s32", "frame:-1:s32"}) {
    require(!engine.inspectScalarStorage(locator, result, error) && error.code == "INVALID_REQUEST" && result.is_null(),
            "accepted non-canonical locator");
  }
  require(!engine.inspectScalarStorage("frame:0:missing", result, error) && error.code == "READ_FAILED", "accepted unissued locator");
  require(engine.refreshStoppedSnapshot(stop, error), "cannot refresh scalar snapshot");
  require(stop.input == beforeInput && stop.location == beforeLocation && stop.stdoutSnapshot == beforeOutput,
          "metadata inspection delivered input or advanced execution");
  require(engine.readRegisters({"rip", "rsp", "rbp"}, afterRegisters, error) && beforeRegisters == afterRegisters,
          "metadata inspection changed registers");

  breakpoint(engine, request, "SCALAR_INNER");
  resume(engine, stop);
  require(inspect(engine, "inner").at("available") == true, "inner scalar unavailable");
  require(!engine.inspectScalarStorage("frame:1:s32", result, error) && error.code == "READ_FAILED", "unissued outer handle accepted");
  require(engine.readVariables("frame:1", 0, 128, result, error), "cannot issue outer variables");
  require(inspect(engine, "s32", 1).at("available") == true, "outer frame scalar unavailable");
  breakpoint(engine, request, "SCALAR_SHADOW");
  resume(engine, stop);
  require(!engine.inspectScalarStorage("frame:0:inner", result, error) && error.code == "READ_FAILED", "stale inner handle survived");
  unsigned duplicates = 0;
  for (const auto& frame : stop.stack) for (const auto& variable : frame.at("variables"))
    if (variable.at("locator") == "frame:0:s32") ++duplicates;
  if (duplicates > 1)
    require(!engine.inspectScalarStorage("frame:0:s32", result, error) && error.code == "UNSUPPORTED", "ambiguous shadow handle resolved");

  breakpoint(engine, request, "SCALAR_REGISTER", 1);
  resume(engine, stop);
  const auto registerOnly = inspect(engine, "registerOnly");
  require(registerOnly.at("available") == false && registerOnly.at("reason") == "not-addressable", "register storage became memory: " + registerOnly.dump());
  breakpoint(engine, request, "SCALAR_OPTIMIZED", 1);
  resume(engine, stop);
  const auto optimized = inspect(engine, "seed");
  require(optimized.at("available") == false && optimized.at("reason") == "optimized-out", "optimized scalar became addressable: " + optimized.dump());
  require(engine.setBreakpoints({{"documentId", "scalar.cpp"}, {"breakpoints", Json::array()}}, result, error), "cannot clear source breakpoint");
  require(engine.setBreakpoints({{"documentId", "optimized.cpp"}, {"breakpoints", Json::array()}}, result, error), "cannot clear optimized breakpoint");
  require(engine.resume("continue", stop, error) && stop.exited && stop.exitCode == 0, "inspection executed hostile conversion");
  request.recordingProfile = "gdb-record-full";
  require(engine.launch(request, stop, error), "recorded launch failed");
  require(!engine.inspectScalarStorage("frame:0:s32", result, error) && error.code == "UNSUPPORTED", "recorded inspection enabled mutation profile");
  engine.stop();
  malformedMetadata(options, request);
  std::cout << "scalar storage checks passed\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
