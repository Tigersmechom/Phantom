#include "phantom/recorder_probe.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stop_token>
#include <string>
#include <thread>

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
using Json = nlohmann::json;

class Fixture final {
 public:
  Fixture() {
    char name[] = "/tmp/phantom-recorder-test-XXXXXX";
    assert(::mkdtemp(name));
    directory = name;
    fixture = directory / "fixture with ' quotes ; $.bin";
    write(fixture, "fixture", false);
    options.fixturePath = fixture;
    options.temporaryDirectory = directory;
    options.gdbPath = (directory / "gdb with spaces").string();
    options.rrPath = (directory / "rr with spaces").string();
    options.timeout = std::chrono::milliseconds(3000);
    successfulGdb();
    write(options.rrPath, R"SH(#!/bin/sh
if [ "$1" = '--version' ]; then printf 'rr test-version\n'; exit 0; fi
if [ "$1" = 'record' ]; then mkdir "$3"; printf 'record\n' > "$3/data"; fi
printf 'phantom-recorder-probe-ok\n'
)SH");
  }
  ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
  static void write(const std::filesystem::path& path, const std::string& text, bool executable = true) {
    { std::ofstream file(path); file << text; assert(file.good()); }
    if (executable) assert(::chmod(path.c_str(), 0700) == 0);
  }
  void successfulGdb() {
    write(options.gdbPath, R"SH(#!/bin/sh
if [ "$3" = '--version' ]; then printf 'gdb test-version\n'; exit 0; fi
printf 'PHANTOM_PROBE_MIDDLE:17\nPHANTOM_PROBE_FORWARD:29:1\nPHANTOM_PROBE_REVERSE:17:1\nPHANTOM_PROBE_REPLAY:29:1\n'
)SH");
  }
  Json probe(std::stop_token stop = {}) const {
    const auto before = std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator());
    const auto result = phantom::probeRecorders(options, stop);
    const auto after = std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator());
    assert(before == after);  // Traces and GDB scripts are never retained.
    assert(!result.dump().empty());
    return result;
  }
  std::filesystem::path directory, fixture;
  phantom::RecorderProbeOptions options;
};

void successfulAndVerificationTests() {
  Fixture fixture;
  auto result = fixture.probe();
  assert(result["scope"] == "isolated-scalar-fixture");
  assert(result["gdbRecordFull"]["available"] == true);
  assert(result["gdbRecordFull"]["memoryRestored"] == true);
  assert(result["gdbRecordFull"]["pcRestored"] == true);
  assert(result["gdbRecordFull"]["forwardReplay"] == true);
  assert(result["rr"]["available"] == true);
  assert(result["rr"]["record"]["attempted"] == true);
  assert(result["rr"]["replay"]["attempted"] == true);
  assert(result["rr"]["reason"].is_null());

  // Successful exit or textual fragments alone do not establish a replay.
  Fixture::write(fixture.options.gdbPath, "#!/bin/sh\nprintf 'noisePHANTOM_PROBE_REVERSE:17:1\\n'\n");
  result = fixture.probe();
  assert(result["gdbRecordFull"]["available"] == false);
  assert(result["gdbRecordFull"]["reason"] == "verification-failed");
  assert(result["rr"]["available"] == true);
  fixture.successfulGdb();
  Fixture::write(fixture.options.rrPath, "#!/bin/sh\nprintf 'rr installed\\n'\n");
  result = fixture.probe();
  assert(result["rr"]["available"] == false);
  assert(result["rr"]["reason"] == "verification-failed");
  assert(result["rr"]["replay"]["attempted"] == false);

  // An rr recording failure never launches replay of the incomplete trace.
  Fixture::write(fixture.options.rrPath, R"SH(#!/bin/sh
if [ "$1" = '--version' ]; then printf 'rr test-version\n'; exit 0; fi
printf 'perf_event_paranoid is 4\n' >&2
exit 1
)SH");
  result = fixture.probe();
  assert(result["rr"]["reason"] == "exit-error");
  assert(result["rr"]["record"]["exitCode"] == 1);
  assert(result["rr"]["replay"]["attempted"] == false);
}

void unavailableTests() {
  Fixture fixture;
  fixture.options.gdbPath = (fixture.directory / "does-not-exist").string();
  auto result = fixture.probe();
  assert(result["gdbRecordFull"]["available"] == false);
  assert(result["gdbRecordFull"]["reason"] == "spawn-error");
  assert(result["rr"]["available"] == true);
  fixture.options.fixturePath = fixture.directory / "missing-fixture";
  result = fixture.probe();
  assert(result["gdbRecordFull"]["reason"] == "fixture-unavailable");
  assert(result["rr"]["version"]["attempted"] == false);
  fixture.options.timeout = std::chrono::milliseconds(0);
  assert(fixture.probe()["rr"]["reason"] == "invalid-limits");
}

void boundsTests() {
  Fixture fixture;
  fixture.options.timeout = std::chrono::milliseconds(60);
  Fixture::write(fixture.options.gdbPath, "#!/bin/sh\nsleep 5\n");
  auto result = fixture.probe();
  assert(result["gdbRecordFull"]["reason"] == "timeout");
  assert(result["rr"]["version"]["attempted"] == false);
  assert(result["elapsedMs"].get<long long>() < 1500);

  std::stop_source cancelled;
  cancelled.request_stop();
  result = fixture.probe(cancelled.get_token());
  assert(result["cancelled"] == true);
  assert(result["gdbRecordFull"]["version"]["attempted"] == false);
  fixture.options.timeout = std::chrono::milliseconds(3000);
  std::stop_source running;
  std::jthread cancel([&running] { std::this_thread::sleep_for(std::chrono::milliseconds(50)); running.request_stop(); });
  result = fixture.probe(running.get_token());
  assert(result["cancelled"] == true);
  assert(result["gdbRecordFull"]["reason"] == "cancelled");
  assert(result["elapsedMs"].get<long long>() < 1500);

  fixture.options.maxOutputBytes = 256;
  Fixture::write(fixture.options.gdbPath, "#!/bin/sh\ni=0; while [ $i -lt 100 ]; do printf 'xxxxxxxxxxxxxxxx\\n'; i=$((i+1)); done\n");
  result = fixture.probe();
  assert(result["gdbRecordFull"]["reason"] == "output-limit");
  fixture.options.maxOutputBytes = 64 * 1024;
  fixture.successfulGdb();
  fixture.options.maxTraceBytes = 1024;
  Fixture::write(fixture.options.rrPath, R"SH(#!/bin/sh
if [ "$1" = '--version' ]; then printf 'rr test-version\n'; exit 0; fi
mkdir "$3"
dd if=/dev/zero of="$3/overflow" bs=2048 count=1 2>/dev/null
printf 'phantom-recorder-probe-ok\n'
)SH");
  result = fixture.probe();
  assert(result["rr"]["reason"] == "trace-limit");
  assert(result["rr"]["replay"]["attempted"] == false);

  // Diagnostics with non-UTF-8 bytes must still produce legal wire JSON.
  Fixture::write(fixture.options.gdbPath, "#!/bin/sh\nprintf '\\377\\376\\n' >&2\nexit 1\n");
  result = fixture.probe();
  assert(result["gdbRecordFull"]["version"]["stderr"].get<std::string>().find("\xef\xbf\xbd") != std::string::npos);
}
}  // namespace

int main(int argc, char** argv) {
  successfulAndVerificationTests();
  unavailableTests();
  boundsTests();
  if (argc == 2) {
    phantom::RecorderProbeOptions options;
    options.fixturePath = argv[1];
    const auto actual = phantom::probeRecorders(options);
    std::cout << actual.dump(2) << '\n';
    if (actual["gdbRecordFull"]["available"] == true) {
      assert(actual["gdbRecordFull"]["memoryRestored"] == true);
      assert(actual["gdbRecordFull"]["pcRestored"] == true);
      assert(actual["gdbRecordFull"]["forwardReplay"] == true);
    } else {
      // Permission-denied and unsupported-host results remain explicit evidence.
      assert(actual["gdbRecordFull"]["reason"].is_string());
    }
  }
  return 0;
}
