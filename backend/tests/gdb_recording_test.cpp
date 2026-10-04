#include "phantom/gdb.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <thread>

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
  std::ifstream input(path);
  require(static_cast<bool>(input), "cannot read fixture");
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::uint64_t cursor(const GdbStop& stop) {
  require(stop.recording.value("available", false), "missing recorder status: " + stop.recording.dump());
  return std::stoull(stop.recording.at("currentInstruction").get<std::string>());
}
int value(const GdbStop& stop) {
  for (const auto& frame : stop.stack)
    for (const auto& variable : frame.at("variables"))
      if (variable.value("name", "") == "value")
        return std::stoi(variable.at("value").at("value").at("decimal").get<std::string>());
  throw std::runtime_error("value absent: " + stop.stack.dump());
}
void advance(GdbEngine& engine, GdbStop& stop, std::string_view kind = "over") {
  GdbError error;
  require(engine.resume(kind, stop, error), "resume failed: " + error.code + ": " + error.message);
  require(stop.stopped && !stop.exited, "resume lost live stop");
}
void breakpoint(GdbEngine& engine, const GdbLaunchRequest& launch, std::string_view marker) {
  const auto& text = launch.sourceBundle.documents.front().text;
  const auto at = text.find(marker);
  require(at != std::string::npos, "missing fixture marker");
  const auto line = 1 + std::count(text.begin(), text.begin() + at, '\n');
  Json result;
  GdbError error;
  require(engine.setBreakpoints({{"documentId", "recording.cpp"}, {"breakpoints", Json::array({
      {{"id", "recording-breakpoint"}, {"range", {{"start", {{"line", line}, {"column", 1}}}}}, {"enabled", true}}})}}, result, error),
      "breakpoint failed: " + error.message);
  require(result.size() == 1 && result[0].value("verified", false), "breakpoint was not resolved: " + result.dump());
}
void clearBreakpoints(GdbEngine& engine) {
  Json result;
  GdbError error;
  require(engine.setBreakpoints({{"documentId", "recording.cpp"}, {"breakpoints", Json::array()}}, result, error),
          "cannot clear breakpoints");
}
void launch(GdbEngine& engine, const GdbLaunchRequest& request, GdbStop& stop) {
  GdbError error;
  require(engine.launch(request, stop, error), "launch failed: " + error.code + ": " + error.message);
}
void seek(GdbEngine& engine, std::uint64_t instruction, GdbStop& stop) {
  GdbError error;
  require(engine.seekRecording(instruction, stop, error), "seek failed: " + error.code + ": " + error.message);
  require(cursor(stop) == instruction, "seek returned wrong cursor");
}
}  // namespace

int main(int argc, char** argv) try {
  require(argc == 4, "expected fixture, I/O wrapper and fixture source");
  GdbOptions options;
  options.execWrapper = std::filesystem::absolute(argv[2]);
  options.commandTimeout = 5s;
  options.stepTimeout = 300ms;
  GdbEngine engine(options);
  GdbLaunchRequest request;
  request.binaryPath = std::filesystem::absolute(argv[1]);
  request.recordingProfile = "gdb-record-full";
  request.maxRecordedInstructions = 256;
  request.sourceBundle.id = "recording-test";
  request.sourceBundle.documents.push_back({"recording.cpp", "revision-1", std::filesystem::absolute(argv[3]), readFile(argv[3])});
  GdbStop stop;
  GdbError error;
  Json result;

  auto invalid = request;
  invalid.closeInputAfterWrite = false;
  require(!engine.launch(invalid, stop, error) && error.code == "INVALID_REQUEST", "recording accepted interactive stdin");
  invalid = request;
  invalid.maxRecordedInstructions = 0;
  require(!engine.launch(invalid, stop, error) && error.code == "INVALID_REQUEST", "recording accepted unbounded log");
  launch(engine, request, stop);
  require(cursor(stop) == 0 && stop.recording.at("recordedInstructions") == 0, "entry recording is not empty");
  seek(engine, 0, stop);
  require(!engine.reverseInstruction(stop, error) && error.code == "INVALID_REQUEST", "reversed before recording origin");
  require(!engine.appendInput("late", "1 ", result, error) && error.code == "UNSUPPORTED", "recorder accepted new stdin");
  require(!engine.closeInput(result, error) && error.code == "UNSUPPORTED", "recorder accepted input mutation");
  breakpoint(engine, request, "value = 1;  // RECORD_SEQUENCE");
  advance(engine, stop, "continue");
  clearBreakpoints(engine);
  require(value(stop) == 0, "sequence must start at zero");
  const auto before = cursor(stop);
  advance(engine, stop);
  require(value(stop) == 1, "first store absent");
  const auto one = cursor(stop);
  advance(engine, stop);
  require(value(stop) == 2, "second store absent");
  const auto two = cursor(stop);
  advance(engine, stop);
  require(value(stop) == 0, "third store absent");
  const auto end = cursor(stop);
  require(before < one && one < two && two < end, "recording cursors are not ordered");
  engine.interrupt(1);
  require(!engine.reverseInstruction(stop, error) && error.code == "CANCELLED" && cursor(stop) == end,
          "queued Pause was lost during recorder metadata query");
  engine.interrupt(1);
  require(!engine.seekRecording(before, stop, error) && error.code == "CANCELLED" && cursor(stop) == end,
          "queued Pause was lost before seek");
  require(engine.reverseInstruction(stop, error), "reverse instruction failed: " + error.message);
  require(value(stop) == 2 && cursor(stop) == two, "reverse did not undo last store");
  seek(engine, before, stop);
  require(value(stop) == 0, "seek did not restore first zero");
  seek(engine, one, stop);
  require(value(stop) == 1, "seek skipped intermediate one");
  seek(engine, two, stop);
  require(value(stop) == 2, "seek skipped intermediate two");
  seek(engine, end, stop);
  require(value(stop) == 0, "seek did not restore final zero");
  seek(engine, end, stop);
  require(!engine.seekRecording(end + 1, stop, error) && error.code == "INVALID_REQUEST" && engine.live(),
          "out-of-range seek corrupted live session");

  // Circular eviction is explicit and requests cannot fabricate an evicted
  // baseline. GDB's earliest seekable cursor after eviction is first, not first-1.
  request.maxRecordedInstructions = 4;
  launch(engine, request, stop);
  for (int step = 0; step < 20; ++step) advance(engine, stop, "instruction");
  require(stop.recording.at("evicted") == true && stop.recording.at("recordedInstructions") == 4,
          "recording limit did not evict old instructions");
  const auto earliest = std::stoull(stop.recording.at("earliestSeekableInstruction").get<std::string>());
  require(earliest > 0, "evicted recording claims origin retained");
  require(!engine.seekRecording(earliest - 1, stop, error), "seek reached evicted boundary");
  seek(engine, earliest, stop);
  require(!engine.reverseInstruction(stop, error), "reverse crossed eviction boundary");

  // Unsupported recording instructions must return an authoritative current
  // stop, retaining prior recorded instructions for inspection and reverse.
  request.maxRecordedInstructions = 256;
  request.argv = {"u"};
  launch(engine, request, stop);
  breakpoint(engine, request, "asm volatile(\"ud2\")");
  advance(engine, stop, "continue");
  clearBreakpoints(engine);
  const auto unsupported = cursor(stop);
  const bool supported = engine.resume("instruction", stop, error);
  require(stop.stopped && !stop.exited && engine.live(), "unsupported instruction lost actual stopped state");
  // A newer recorder may support UD2 and report SIGILL instead of rejecting
  // its decoder. Both are explicit stops, never fabricated forward progress.
  require(!supported || stop.signalName == "SIGILL", "UD2 silently completed");
  require(cursor(stop) >= unsupported, "recording cursor regressed after unsupported instruction");
  seek(engine, unsupported - 1, stop);
  require(cursor(stop) == unsupported - 1, "prior recording unusable after unsupported instruction");

  // GDB's decoder/memory recorder also reject execution with *stopped
  // signal-name="0" plus diagnostics, without a ^error command response.
  // Runtime support can improve: a real breakpoint after success is allowed,
  // but synthetic signal zero must never masquerade as successful execution.
  for (const auto& scenario : {std::pair{"a", "RECORD_AVX_AFTER"}, std::pair{"m", "RECORD_MUNMAP_AFTER"}}) {
    request.argv = {scenario.first};
    request.maxRecordedInstructions = 4096;
    launch(engine, request, stop);
    breakpoint(engine, request, scenario.second);
    const bool completed = engine.resume("continue", stop, error);
    require(stop.stopped && !stop.exited && engine.live(), "recorder diagnostic lost stopped process");
    require(stop.recording.value("available", false), "recorder diagnostic discarded usable log");
    if (stop.signalName == "0") {
      require(!completed && (error.code == "UNSUPPORTED" || error.code == "READ_FAILED"),
              "synthetic recorder signal zero incorrectly completed: " + error.code);
      require(error.message.find("record-full could not record") != std::string::npos,
              "recorder failure omitted explanation");
    } else require(completed && stop.reason == "breakpoint-hit", "unexpected recorder diagnostic stop");
    clearBreakpoints(engine);
    const auto retained = cursor(stop);
    require(retained > 0, "diagnostic test recorded no instructions");
    seek(engine, retained - 1, stop);
  }

  // Real write syscall effects persist while memory/registers rewind. Replay
  // does not perform the syscall again; exact raw bytes include NUL and invalid UTF-8.
  request.argv = {"o"};
  request.maxRecordedInstructions = 256;
  launch(engine, request, stop);
  breakpoint(engine, request, "RECORD_OUTPUT_BEGIN");
  advance(engine, stop, "continue");
  clearBreakpoints(engine);
  const auto beforeOutput = cursor(stop);
  breakpoint(engine, request, "value = static_cast<int>(result);");
  advance(engine, stop, "continue");
  clearBreakpoints(engine);
  const auto afterOutput = cursor(stop);
  const std::string bytes("o\0\xff\n", 4);
  require(stop.stdoutRaw == bytes && stop.stdoutSnapshot.at("totalBytes") == 4, "exact output hook lost raw bytes");
  seek(engine, beforeOutput, stop);
  require(stop.stdoutRaw == bytes, "reverse incorrectly erased an external output effect");
  seek(engine, afterOutput, stop);
  require(stop.stdoutRaw == bytes && stop.stdoutSnapshot.at("totalBytes") == 4, "replay duplicated a write effect");

  // Control interrupts the synchronous recorder through its process group.
  request.argv.clear();
  launch(engine, request, stop);
  std::thread pause([&] { std::this_thread::sleep_for(60ms); engine.interrupt(1); });
  const bool paused = engine.resume("continue", stop, error);
  pause.join();
  require(paused && stop.stopped && !stop.exited && engine.live(), "Pause failed during record-full continue: " + error.message);
  require(stop.recording.value("available", false), "Pause lost recording");
  std::thread cancel([&] { std::this_thread::sleep_for(60ms); engine.interrupt(2); });
  const bool cancelled = engine.resume("continue", stop, error);
  cancel.join();
  require(!cancelled && error.code == "CANCELLED" && !engine.live(), "Stop failed during recording");
  engine.stop();

  request.argv = {"t"};
  launch(engine, request, stop);
  breakpoint(engine, request, "while (true) { value = value + 1; }");
  advance(engine, stop, "continue");
  clearBreakpoints(engine);
  require(!engine.resume("over", stop, error) && error.code == "STEP_TIMEOUT" &&
          stop.stopped && stop.recording.value("available", false) && engine.live(),
          "source step timeout destroyed recording: " + error.code + ": " + error.message);

  request.argv = {"e"};
  launch(engine, request, stop);
  const bool exited = engine.resume("continue", stop, error);
  // Some runtimes use an instruction unsupported by record-full in their
  // exit path. Preserve that stop; when exit is reached, the log is gone.
  require(stop.stopped || stop.exited, "exit attempt lost authoritative stop");
  if (exited && stop.exited)
    require(!stop.recording.value("available", true) && stop.recording.at("reason") == "process-exited",
            "exited recorder still claims recoverable process state");

  request.recordingProfile = "native";
  request.argv.clear();
  launch(engine, request, stop);
  require(stop.recording.is_null(), "native profile acquired recorder state");
  require(engine.readRecording(result, error) && !result.at("available").get<bool>(), "native recorder status is dishonest");
  require(!engine.reverseInstruction(stop, error) && error.code == "UNSUPPORTED", "native profile executed reverse");
  engine.stop();
  std::cout << "recording engine checks passed\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
