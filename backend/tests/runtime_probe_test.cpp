#include "phantom/runtime_probe.hpp"

#include <cassert>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stop_token>
#include <string>
#include <thread>

#include <sys/stat.h>
#include <unistd.h>

namespace {
using Json = nlohmann::json;

Json goodEvidence() {
  return {{"profile", "linux-x86_64-syscall-probe-v1"}, {"pid", 12345},
          {"pageSize", 4096}, {"scratchAddressHex", "0x100000"},
          {"getpid", true}, {"allocated", true}, {"writable", true},
          {"executable", true}, {"payloadExecuted", true}, {"released", true},
          {"deniedSyscall", true}, {"registersRestored", true},
          {"stackUnchanged", true}, {"errnoUnchanged", true},
          {"signalMaskUnchanged", true}, {"codeUnchanged", true},
          {"signalStopVerified", true}, {"handlerNotRun", true},
          {"registerCount", 61}, {"stackBytes", 135168}};
}

constexpr const char* pythonPrefix = R"PY(#!/usr/bin/python3
import os, pathlib, signal, sys, time
if '--version' in sys.argv:
    print('GNU gdb (runtime test fixture)')
    sys.exit(0)
)PY";

class Fixture final {
 public:
  Fixture() {
    char pattern[] = "/tmp/phantom-runtime-test-XXXXXX";
    assert(::mkdtemp(pattern));
    directory = pattern;
    fixture = directory / "fixture with ' quotes ; $.bin";
    write(fixture, "fixture", false);
    options.fixturePath = fixture;
    options.temporaryDirectory = directory;
    options.gdbPath = (directory / "gdb with spaces").string();
    options.timeout = std::chrono::milliseconds(3000);
    output(evidenceLine(goodEvidence()));
  }
  ~Fixture() {
    std::error_code error;
    std::filesystem::remove_all(directory, error);
  }
  static void write(const std::filesystem::path& path, const std::string& bytes, bool executable = true) {
    std::ofstream file(path, std::ios::binary);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    assert(file.good());
    if (executable) assert(::chmod(path.c_str(), 0700) == 0);
  }
  static std::string evidenceLine(const Json& evidence) {
    return "PHANTOM_RUNTIME_PROBE_V1:" + evidence.dump() + "\n";
  }
  void script(const std::string& code) const {
    write(options.gdbPath, std::string(pythonPrefix) + code);
  }
  void output(const std::string& bytes, int exitCode = 0) const {
    write(directory / "output.bin", bytes, false);
    script("sys.stdout.buffer.write(pathlib.Path(__file__).with_name('output.bin').read_bytes())\n"
           "sys.stdout.buffer.flush()\n"
           "sys.exit(" + std::to_string(exitCode) + ")\n");
  }
  Json probe(std::stop_token stop = {}) const {
    const auto result = phantom::probeRuntime(options, stop);
    for (const auto& entry : std::filesystem::directory_iterator(directory))
      assert(!entry.path().filename().string().starts_with("phantom-runtime-probe-"));
    assert(!result.dump().empty());
    assert(result.size() == 10);
    for (const auto* stage : {"gdbVersion", "execution"}) {
      assert(result.at(stage).size() == 8);
      for (const auto* key : {"attempted", "ok", "status", "exitCode", "signal", "stdout", "stderr", "detail"})
        assert(result.at(stage).contains(key));
    }
    return result;
  }
  std::filesystem::path directory, fixture;
  phantom::RuntimeProbeOptions options;
};

void verificationTests() {
  Fixture fixture;
  auto result = fixture.probe();
  assert(result["scope"] == "isolated-runtime-fixture");
  assert(result["profile"] == "linux-x86_64-syscall-probe-v1");
  assert(result["available"] == true && result["reason"] == "verified");
  assert(result["evidence"] == goodEvidence());

  fixture.output("GDB startup noise\n" + Fixture::evidenceLine(goodEvidence()) + "[Inferior exited]\n");
  assert(fixture.probe()["available"] == true);

  // Successful exit, fragments, duplicate records and incomplete final lines
  // cannot turn into verified runtime support.
  const auto line = Fixture::evidenceLine(goodEvidence());
  for (const auto& bytes : std::vector<std::string>{"", "no evidence\n", "noise" + line,
      line + line, line.substr(0, line.size() - 1), line + "PHANTOM_RUNTIME_PROBE_V1:",
      "PHANTOM_RUNTIME_PROBE_V1:{}\n"}) {
    fixture.output(bytes);
    result = fixture.probe();
    assert(result["available"] == false && result["reason"] == "verification-failed");
    assert(result["evidence"].is_null());
  }

  // Reject duplicate keys, including differently escaped spellings, before
  // the JSON library can silently retain only the last value.
  const auto json = goodEvidence().dump();
  for (const auto& key : {"pid", "p\\u0069d"}) {
    fixture.output("PHANTOM_RUNTIME_PROBE_V1:{\"" + std::string(key) + "\":12345," + json.substr(1) + "\n");
    result = fixture.probe();
    assert(result["available"] == false && result["evidence"].is_null());
  }

  for (const auto* flag : {"getpid", "allocated", "writable", "executable", "payloadExecuted",
       "released", "deniedSyscall", "registersRestored", "stackUnchanged", "errnoUnchanged",
       "signalMaskUnchanged", "codeUnchanged", "signalStopVerified", "handlerNotRun"}) {
    auto evidence = goodEvidence();
    evidence[flag] = false;
    fixture.output(Fixture::evidenceLine(evidence));
    result = fixture.probe();
    assert(result["available"] == false && result["reason"] == "verification-failed");
    assert(result["evidence"] == evidence);  // Preserve actual negative evidence.
    evidence[flag] = 1;
    fixture.output(Fixture::evidenceLine(evidence));
    assert(fixture.probe()["evidence"].is_null());
  }

  fixture.output(line, 4);
  result = fixture.probe();
  assert(result["available"] == false && result["reason"] == "exit-error");
  assert(result["execution"]["exitCode"] == 4 && result["evidence"] == goodEvidence());
}

void shapeTests() {
  Fixture fixture;
  const auto invalidField = [&](const std::string& name, const Json& value) {
    auto evidence = goodEvidence();
    evidence[name] = value;
    fixture.output(Fixture::evidenceLine(evidence));
    const auto result = fixture.probe();
    assert(result["available"] == false && result["evidence"].is_null());
  };
  for (const auto& value : std::vector<Json>{0, -1, 2147483648ULL, 2.5, true, "123"}) invalidField("pid", value);
  for (const auto& value : std::vector<Json>{0, 4095, 8193, 2097152}) invalidField("pageSize", value);
  for (const auto& value : std::vector<Json>{0, 18, 31, 513, 61.5}) invalidField("registerCount", value);
  for (const auto& value : std::vector<Json>{0, 4095, 1048577}) invalidField("stackBytes", value);
  for (const auto& value : std::vector<Json>{nullptr, 0, "0x0", "0x00001000", "0X1000", "0xABCD0000",
       "0x1001", "0x8000000000000000", "0xfffffffffffff000", "0x10000000000000000", "1+2", "0x1000\n"})
    invalidField("scratchAddressHex", value);
  invalidField("profile", "unrelated-profile");
  invalidField("unexpected", true);
  invalidField("pid", Json::array({12345}));
  auto missing = goodEvidence();
  missing.erase("handlerNotRun");
  fixture.output(Fixture::evidenceLine(missing));
  assert(fixture.probe()["evidence"].is_null());

  // Sanitize diagnostics for valid wire JSON, but never use those replacement
  // bytes as the input to evidence parsing.
  auto bytes = Fixture::evidenceLine(goodEvidence());
  bytes.insert(bytes.find("linux-x86_64"), 1, '\xff');
  fixture.output(bytes);
  const auto result = fixture.probe();
  assert(result["evidence"].is_null());
  assert(result["execution"]["stdout"].get<std::string>().find("\xef\xbf\xbd") != std::string::npos);
  fixture.output(std::string("diagnostic \xff\xfe\n") + Fixture::evidenceLine(goodEvidence()));
  assert(fixture.probe()["available"] == true);
}

bool processRunning(int pid) {
  std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
  std::string text;
  std::getline(file, text);
  const auto closing = text.rfind(')');
  return closing != std::string::npos && closing + 2 < text.size() && text[closing + 2] != 'Z';
}

void waitGone(int pid) {
  for (int attempt = 0; attempt < 200 && processRunning(pid); ++attempt)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  assert(!processRunning(pid));
}

void limitAndCleanupTests() {
  Fixture fixture;
  auto invalid = fixture.options;
  for (const auto duration : {0, 30001}) {
    fixture.options.timeout = std::chrono::milliseconds(duration);
    assert(fixture.probe()["reason"] == "invalid-limits");
  }
  fixture.options = invalid;
  for (const auto bytes : {255u, 262145u}) {
    fixture.options.maxOutputBytes = bytes;
    assert(fixture.probe()["reason"] == "invalid-limits");
  }
  fixture.options = invalid;
  fixture.options.fixturePath = fixture.directory / "missing";
  auto result = fixture.probe();
  assert(result["reason"] == "fixture-unavailable");
  assert(result["gdbVersion"]["attempted"] == false);
  fixture.options = invalid;
  fixture.options.gdbPath = (fixture.directory / "absent-gdb").string();
  result = fixture.probe();
  assert(result["reason"] == "spawn-error" && result["execution"]["attempted"] == false);
  fixture.options = invalid;

  std::stop_source cancelled;
  cancelled.request_stop();
  result = fixture.probe(cancelled.get_token());
  assert(result["cancelled"] == true && result["reason"] == "cancelled");
  assert(result["gdbVersion"]["attempted"] == false);

  fixture.options.maxOutputBytes = 256;
  fixture.script("os.write(1,b'x'*4096)\n");
  result = fixture.probe();
  assert(result["reason"] == "output-limit");
  assert(result["execution"]["stdout"].get<std::string>().size() <= 256);
  fixture.options = invalid;

  // A direct child deliberately leaves the debugger's process group. The
  // timeout must kill that owned child using its pidfd as well as its parent.
  const auto childFile = fixture.directory / "child.pid";
  fixture.script("child=os.fork()\n"
                 "if child==0:\n"
                 "    os.setsid()\n"
                 "    pathlib.Path(" + Json(childFile.string()).dump() + ").write_text(str(os.getpid()))\n"
                 "    time.sleep(30)\n"
                 "else:\n"
                 "    time.sleep(30)\n");
  fixture.options.timeout = std::chrono::milliseconds(250);
  result = fixture.probe();
  assert(result["reason"] == "timeout");
  assert(result["elapsedMs"].get<long long>() < 1500);
  int child = 0;
  std::ifstream(childFile) >> child;
  assert(child > 0);
  waitGone(child);

  // A child observed while its parent was alive must still be terminated if
  // the debugger exits abruptly and the kernel reparents that child first.
  fixture.options = invalid;
  fixture.script("child=os.fork()\n"
                 "if child==0:\n"
                 "    os.setsid()\n"
                 "    pathlib.Path(" + Json(childFile.string()).dump() + ").write_text(str(os.getpid()))\n"
                 "    os.close(0);os.close(1);os.close(2)\n"
                 "    time.sleep(30)\n"
                 "else:\n"
                 "    time.sleep(0.15)\n"
                 "    os._exit(4)\n");
  result = fixture.probe();
  assert(result["reason"] == "exit-error" && result["execution"]["exitCode"] == 4);
  child = 0;
  std::ifstream(childFile) >> child;
  assert(child > 0);
  waitGone(child);

  // Version and execution share one deadline; successful version output does
  // not reset the available time for the next subprocess.
  Fixture::write(fixture.options.gdbPath,
      "#!/usr/bin/python3\nimport sys,time\n"
      "if '--version' in sys.argv:\n"
      "    time.sleep(0.15);print('gdb version');sys.exit(0)\n"
      "time.sleep(0.15)\n");
  fixture.options.timeout = std::chrono::milliseconds(250);
  result = fixture.probe();
  assert(result["gdbVersion"]["ok"] == true && result["reason"] == "timeout");
  assert(result["elapsedMs"].get<long long>() < 700);

  // Keep a valid record that arrived before cancellation, but never turn it
  // into available=true while execution is unfinished or cancelled.
  fixture.options = invalid;
  fixture.write(fixture.directory / "output.bin", Fixture::evidenceLine(goodEvidence()), false);
  fixture.script("os.write(1,pathlib.Path(__file__).with_name('output.bin').read_bytes())\n"
                 "time.sleep(30)\n");
  std::stop_source running;
  std::jthread cancel([&] {
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    running.request_stop();
  });
  result = fixture.probe(running.get_token());
  assert(result["cancelled"] == true && result["available"] == false);
  assert(result["reason"] == "cancelled" && result["evidence"] == goodEvidence());

  Fixture::write(fixture.options.gdbPath, "#!/usr/bin/python3\nimport os\nos.write(2,b'\\xff\\xfe\\n')\nraise SystemExit(1)\n");
  result = fixture.probe();
  assert(result["reason"] == "exit-error");
  assert(result["gdbVersion"]["stderr"].get<std::string>().find("\xef\xbf\xbd") != std::string::npos);
}

void realEarlyCleanupTest(const std::filesystem::path& actualFixture, bool cancel) {
  if (!std::filesystem::exists("/usr/bin/gdb")) return;
  Fixture fixture;
  fixture.options.fixturePath = actualFixture;
  fixture.options.timeout = std::chrono::milliseconds(cancel ? 3000 : 800);
  const auto marker = fixture.directory / "early-child.json";
  // Stop in the dynamic loader, before the fixture can install PDEATHSIG.
  // The GDB Python sleep leaves the real inferior stopped in another group.
  const std::string gdbScript =
      "set confirm off\nset pagination off\nset startup-with-shell off\n"
      "set auto-load off\nset debuginfod enabled off\nstarti\npython\n"
      "import gdb,os,json,time\n"
      "pid=gdb.selected_inferior().pid\n"
      "open(" + Json(marker.string()).dump() + ",'w').write(json.dumps({'pid':pid,'pgid':os.getpgid(pid),'gdbPgid':os.getpgrp()}))\n"
      "time.sleep(30)\nend\nquit\n";
  fixture.script("arguments=sys.argv[1:]\n"
                 "script=pathlib.Path(arguments[arguments.index('-x')+1])\n"
                 "script.write_text(" + Json(gdbScript).dump() + ")\n"
                 "os.execv('/usr/bin/gdb',['/usr/bin/gdb']+arguments)\n");
  std::stop_source cancellation;
  std::jthread interrupter;
  if (cancel) interrupter = std::jthread([&] {
    for (int i = 0; i < 300 && !std::filesystem::exists(marker); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    cancellation.request_stop();
  });
  const auto result = fixture.probe(cancellation.get_token());
  if (!std::filesystem::exists(marker)) {
    // A host which cannot launch GDB at all still reports its concrete reason.
    assert(result["available"] == false);
    std::cout << "early-start cleanup fixture unavailable: " << result.dump() << '\n';
    return;
  }
  Json child;
  std::ifstream(marker) >> child;
  assert(child["pid"] == child["pgid"] && child["pgid"] != child["gdbPgid"]);
  assert(result["available"] == false && result["reason"] == (cancel ? "cancelled" : "timeout"));
  waitGone(child["pid"].get<int>());
}

}  // namespace

int main(int argc, char** argv) {
  verificationTests();
  shapeTests();
  limitAndCleanupTests();
  if (argc == 2) {
    phantom::RuntimeProbeOptions options;
    options.fixturePath = argv[1];
    const auto result = phantom::probeRuntime(options);
    std::cout << result.dump(2) << '\n';
    if (result["available"] == true) {
      assert(result["reason"] == "verified");
      assert(result["evidence"].is_object());
      assert(result["execution"]["exitCode"] == 0);
    } else assert(result["reason"].is_string());
    realEarlyCleanupTest(argv[1], false);
    realEarlyCleanupTest(argv[1], true);
  }
}
