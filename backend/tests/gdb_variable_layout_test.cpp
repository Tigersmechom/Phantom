#include "phantom/gdb.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

using Json = nlohmann::json;
using namespace std::chrono_literals;
namespace {
void require(bool condition, const std::string& message) {
  if (!condition) throw std::runtime_error(message);
}
std::string readFile(const std::filesystem::path& path) {
  std::ifstream stream(path);
  require(bool(stream), "cannot open fixture");
  return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
const Json& field(const Json& root, std::string_view name) {
  for (const auto& item : root.at("fields")) if (item.at("name") == name) return item;
  throw std::runtime_error("field missing: " + std::string(name) + " " + root.dump());
}
std::uint64_t address(const Json& node) {
  return std::stoull(node.at("addressHex").get<std::string>(), nullptr, 16);
}
Json layout(phantom::GdbEngine& engine, std::string_view locator) {
  phantom::GdbError error;
  Json result;
  const bool ok = engine.inspectVariableLayout(locator, result, error);
  require(ok, "inspection failed for " + std::string(locator) + ": " + error.code + ": " + error.message);
  require(result.at("available") == true, "layout unavailable: " + result.dump());
  require(result.at("lifetime") == "unknown", "layout invented source lifetime");
  require(result.at("locator") == locator, "wrong locator");
  require(result.at("bitOffsetConvention") == "gdb-target-bitpos", "bit numbering not explicit");
  require(result.dump().size() <= 262144, "unbounded layout");
  return result;
}
void breakpoint(phantom::GdbEngine& engine, const phantom::GdbLaunchRequest& launch, std::string_view marker,
                std::size_t document = 0) {
  const auto& source = launch.sourceBundle.documents.at(document);
  const auto& text = source.text;
  const auto offset = text.find(marker);
  require(offset != std::string::npos, "missing marker");
  const auto line = 1 + std::count(text.begin(), text.begin() + offset, '\n');
  phantom::GdbError error;
  Json result;
  require(engine.setBreakpoints({{"documentId", source.documentId}, {"breakpoints", Json::array({
      {{"id", "layout-stop"}, {"range", {{"start", {{"line", line}, {"column", 1}}}}}, {"enabled", true}}})}}, result, error),
      "breakpoint failed: " + error.message);
  require(result[0].at("verified") == true, "unresolved breakpoint");
}
void resume(phantom::GdbEngine& engine, phantom::GdbStop& stop, std::string_view kind = "continue") {
  phantom::GdbError error;
  const bool ok = engine.resume(kind, stop, error);
  require(ok, "resume failed: " + error.code + ": " + error.message);
  require(stop.stopped && !stop.exited, "lost stop");
}
}

int main(int argc, char** argv) try {
  require(argc == 5, "expected fixture, wrapper, fixture source, optimized fixture source");
  phantom::GdbOptions options;
  options.execWrapper = std::filesystem::absolute(argv[2]);
  options.commandTimeout = 5s;
  phantom::GdbEngine engine(options);
  phantom::GdbLaunchRequest launch;
  launch.binaryPath = std::filesystem::absolute(argv[1]);
  launch.sourceBundle.id = "layout-source";
  launch.sourceBundle.documents.push_back({"layout.cpp", "revision-1", std::filesystem::absolute(argv[3]), readFile(argv[3])});
  launch.sourceBundle.documents.push_back({"optimized.cpp", "revision-1", std::filesystem::absolute(argv[4]), readFile(argv[4])});
  phantom::GdbError error;
  phantom::GdbStop stop;
  Json result;
  require(!engine.inspectVariableLayout("frame:0:scalar", result, error), "inspected dead process");
  require(engine.launch(launch, stop, error), "launch failed: " + error.message);
  breakpoint(engine, launch, "LAYOUT_READY");
  resume(engine, stop);
  Json registersBefore, registersAfter;
  require(engine.readRegisters({"rip", "rsp"}, registersBefore, error), "register baseline failed");
  auto plain = layout(engine, "frame:0:plain");
  const auto& root = plain.at("root");
  const auto base = address(root);
  require(root.at("kind") == "struct" && root.at("byteSize") == "48", "incorrect Plain extent");
  require(field(root, "first").at("byteOffset") == "0", "wrong first field offset");
  require(address(field(root, "first").at("type")) == base, "wrong first field address");
  const auto& low = field(root, "low");
  const auto& high = field(root, "high");
  require(low.at("bitOffset") == "32" && low.at("bitSize") == "3" && low.at("bitOffsetInByte") == 0, "wrong low bitfield");
  require(high.at("bitOffset") == "35" && high.at("bitSize") == "5" && high.at("bitOffsetInByte") == 3, "wrong high bitfield");
  require(low.at("type").at("addressHex").is_null() && high.at("type").at("addressHex").is_null(), "bitfield has fake address");
  const auto& matrix = field(root, "matrix").at("type");
  require(matrix.at("array").at("elementCount") == "2" && matrix.at("array").at("strideBytes") == "12", "wrong outer array layout");
  require(matrix.at("array").at("elementLayout").at("array").at("elementCount") == "3", "wrong nested array layout");
  require(address(matrix) == base + 8 && address(matrix.at("array").at("elementLayout")) == base + 8, "wrong array storage");
  const auto& overlap = field(root, "overlap").at("type");
  require(overlap.at("kind") == "union" && address(field(overlap, "integer").at("type")) == address(field(overlap, "bytes").at("type")), "union overlap lost");
  const auto& global = field(root, "global");
  require(global.at("kind") == "static" && global.at("byteOffset").is_null() && global.at("type").at("addressHex").is_null(), "static field assigned object storage");
  require(layout(engine, "frame:0:invalidPointer").at("root").at("kind") == "pointer", "invalid pointer was dereferenced");
  require(!layout(engine, "frame:0:invalidPointer").at("root").contains("fields"), "pointer traversal occurred");
  auto reference = layout(engine, "frame:0:reference");
  require(reference.at("root").at("kind") == "reference" && reference.at("storage").at("addressHex").is_null(), "reference slot confused with referent");
  auto array = layout(engine, "frame:0:array");
  require(array.at("root").at("array").at("elementCount") == "10000" && array.dump().size() < 4096, "array was expanded without bounds");
  auto derived = layout(engine, "frame:0:derived");
  unsigned bases = 0, artificial = 0;
  for (const auto& member : derived.at("root").at("fields")) {
    if (member.at("kind") == "base") {
      ++bases;
      require(member.at("byteOffset").is_null() && member.at("type").at("addressHex").is_null(), "base extent was guessed");
    }
    if (member.at("artificial") == true) ++artificial;
  }
  require(bases == 3 && artificial >= 1, "base or compiler-provided vptr metadata lost");
  const auto deep = layout(engine, "frame:0:deep");
  require(deep.at("coverage") == "truncated" && deep.at("truncationReasons") == Json::array({"depth-limit"}), "recursive layout is unbounded");
  const auto wide = layout(engine, "frame:0:wide");
  require(wide.at("coverage") == "truncated" && wide.at("root").at("fields").size() == 128 &&
          wide.at("truncationReasons") == Json::array({"node-limit", "field-limit"}), "wide layout exceeded node/field limits");
  layout(engine, "frame:0:hostile");
  for (const auto* invalid : {"frame:0:hostile()", "frame:0:*invalidPointer", "frame:0:plain.first", "frame:0:scalar\nquit",
                             "frame:00:scalar", "frame:-1:scalar", "frame:4096:scalar", "frame:0:"})
    require(!engine.inspectVariableLayout(invalid, result, error) && error.code == "INVALID_REQUEST" && engine.live(), "unsafe locator accepted");
  require(!engine.inspectVariableLayout("frame:0:notPresent", result, error) && error.code == "READ_FAILED", "unknown variable accepted");
  require(engine.readRegisters({"rip", "rsp"}, registersAfter, error) && registersBefore == registersAfter, "inspection changed registers/frame");
  breakpoint(engine, launch, "LAYOUT_INNER");
  resume(engine, stop);
  layout(engine, "frame:0:local");
  require(!engine.inspectVariableLayout("frame:1:plain", result, error) && error.code == "READ_FAILED",
          "accepted an outer-frame locator not emitted at this stop");
  require(engine.readVariables("frame:1", 0, 1, result, error), "outer first page unavailable");
  require(result.at("variables").size() == 1, "unexpected first page size");
  layout(engine, result.at("variables")[0].at("locator").get<std::string>());
  if (result.at("variables")[0].at("locator") != "frame:1:plain")
    require(!engine.inspectVariableLayout("frame:1:plain", result, error) && error.code == "READ_FAILED",
            "un-emitted page authorized an outer variable");
  require(engine.readVariables("frame:1", 0, 128, result, error), "outer frame variables unavailable");
  require(engine.readRegisters({"rip", "rsp"}, registersBefore, error), "inner register read failed");
  require(layout(engine, "frame:1:plain").at("root").at("addressHex") == root.at("addressHex"), "outer frame storage changed");
  layout(engine, "frame:0:local");
  require(engine.readVariables("frame:0", 0, 128, result, error), "inner frame re-read failed");
  layout(engine, "frame:1:plain");
  require(engine.readRegisters({"rip", "rsp"}, registersAfter, error) && registersBefore == registersAfter, "outer inspection changed selected frame");
  breakpoint(engine, launch, "LAYOUT_SHADOW");
  resume(engine, stop);
  require(!engine.inspectVariableLayout("frame:0:local", result, error) && error.code == "READ_FAILED",
          "previous-stop inner locator survived execution");
  require(!engine.inspectVariableLayout("frame:1:plain", result, error) && error.code == "READ_FAILED",
          "previous-stop outer locator survived execution");
  unsigned duplicates = 0;
  for (const auto& frame : stop.stack) for (const auto& variable : frame.at("variables"))
    if (variable.at("locator") == "frame:0:scalar") ++duplicates;
  if (duplicates > 1) require(!engine.inspectVariableLayout("frame:0:scalar", result, error) && error.code == "UNSUPPORTED", "shadowed locator resolved ambiguously");
  breakpoint(engine, launch, "LAYOUT_OPTIMIZED", 1);
  resume(engine, stop);
  const auto absent = layout(engine, "frame:0:seed");
  require(absent.at("storage").at("available") == false && absent.at("storage").at("reason") == "optimized-out" && absent.at("root").at("kind") == "integer", "optimized variable lost metadata or gained fake address");
  require(engine.setBreakpoints({{"documentId", "layout.cpp"}, {"breakpoints", Json::array()}}, result, error), "clear breakpoint failed");
  require(engine.setBreakpoints({{"documentId", "optimized.cpp"}, {"breakpoints", Json::array()}}, result, error), "clear optimized breakpoint failed");
  require(engine.resume("continue", stop, error) && stop.exited && stop.exitCode == 0, "inspection called hostile user code");
  launch.recordingProfile = "gdb-record-full";
  require(engine.launch(launch, stop, error), "recorded launch failed");
  require(!engine.inspectVariableLayout("frame:0:seed", result, error) && error.code == "READ_FAILED",
          "previous process locator survived relaunch");
  resume(engine, stop, "instruction");
  Json recordingBefore, recordingAfter;
  require(engine.readRecording(recordingBefore, error), "recording baseline missing");
  layout(engine, "frame:0:plain");
  require(engine.readRecording(recordingAfter, error) && recordingBefore == recordingAfter, "layout mutated recording cursor");
  engine.stop();
  std::cout << "variable layout checks passed\n";
  return 0;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return 1;
}
