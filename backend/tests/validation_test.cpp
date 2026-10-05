#include "phantom/validation.hpp"
#include "phantom/service.hpp"

#include <cstdlib>
#include <filesystem>

#include <cassert>
#include <iostream>

using phantom::Json;
using phantom::ValidationError;

static bool fails(const std::string& wire, const char* code = nullptr) {
  try { (void)phantom::parse_wire_json(wire); return false; }
  catch (const ValidationError& e) { return !code || e.code == code; }
}

static bool validation_fails(const Json& value, const char* code = nullptr) {
  try { phantom::validate_request(value); return false; }
  catch (const ValidationError& e) { return !code || e.code == code; }
}

static bool scalar_fails(const Json& value, const char* code = nullptr) {
  try { phantom::validate_scalar_value(value); return false; }
  catch (const ValidationError& e) { return !code || e.code == code; }
}

static bool runtime_fails(const Json& value, const char* code = nullptr) {
  try { phantom::validate_runtime_value(value); return false; }
  catch (const ValidationError& e) { return !code || e.code == code; }
}

int main() {
  auto hello = phantom::parse_wire_json(R"({"ok":true,"text":"😀"})");
  assert(hello["ok"] == true);
  assert(fails(R"({"x":1,"x":2})"));
  assert(fails(R"({"x":"\ud800"})"));
  assert(fails(std::string("{\"x\":\"") + char(0xc0) + char(0x80) + "\"}"));
  assert(fails("9007199254740992"));
  assert(phantom::parse_wire_json("-9007199254740991").get<std::int64_t>() == -9007199254740991LL);
  assert(fails("-9007199254740992"));
  phantom::ValidationLimits tiny; tiny.maxWireBytes = 8;
  try { (void)phantom::parse_wire_json("{\"long\":1}", tiny); assert(false); }
  catch (const ValidationError& e) { assert(e.code == "LIMIT_EXCEEDED"); }

  const std::string text = "a😀\nб";
  assert(phantom::utf16_to_utf8_offset(text, 0) == 0);
  assert(phantom::utf16_to_utf8_offset(text, 3) == 5);
  assert((phantom::utf8_byte_position(text, 5) == phantom::TextPosition{3, 1, 4}));
  assert(fails("[1e100]"));

  Json scalar = {{"kind","integer"},{"decimal","18446744073709551615"},{"bits",64},{"signed",false}};
  phantom::validate_scalar_value(scalar);
  Json runtime = {{"availability","unavailable"},{"reason","not-captured"}};
  phantom::validate_runtime_value(runtime);
  // Missing required members are reported as protocol errors rather than
  // reaching nlohmann::json's asserting const operator[].
  assert(validation_fails(Json::object(), "INVALID_REQUEST"));
  assert(validation_fails(Json{{"protocolVersion", 1}}, "INVALID_REQUEST"));
  assert(scalar_fails(Json{{"kind", "integer"}}, "INVALID_REQUEST"));
  assert(runtime_fails(Json{{"availability", "available"}}, "INVALID_REQUEST"));
  Json connect = Json::object({{"supportedProtocolVersions", Json::array({1})}});
  phantom::validate_connect(connect);
  Json launch = {
      {"protocolVersion", 1}, {"requestId", "r"},
      {"workspace", {{"id", "w"}, {"revisionId", "r"}}}, {"session", nullptr},
      {"command", {{"kind", "launch"}, {"buildId", "b"},
                    {"input", {{"id", "i"}, {"text", ""}, {"encoding", "utf-8"}, {"closeAfterWrite", true}}},
                    {"argv", {"bad\narg"}}, {"environment", Json::object()}, {"stopAtEntry", true}}}};
  assert(validation_fails(launch, "INVALID_REQUEST"));
  launch["command"]["argv"] = Json::array();
  launch["command"]["environment"] = {{"BAD-NAME", "x"}};
  assert(validation_fails(launch, "INVALID_REQUEST"));
  launch["command"]["environment"] = Json::object();
  launch["command"]["input"]["closeAfterWrite"] = false;
  assert(!validation_fails(launch));
  Json append = launch;
  append["session"] = {{"id", "s"}, {"generation", 1}};
  append["expectedStop"] = {{"stopId", "stop-1"}, {"stateRevision", 1}};
  append["command"] = {{"kind", "appendInput"}, {"id", "chunk-1"}, {"text", "41"}};
  assert(!validation_fails(append));
  append["command"] = {{"kind", "closeInput"}};
  assert(!validation_fails(append));
  // Recording is explicit, finite-input-only, and never changes the native
  // profile's defaults through a stray log-size option.
  Json recorded = launch;
  recorded["command"]["recordingProfile"] = "gdb-record-full";
  assert(validation_fails(recorded, "INVALID_REQUEST"));
  recorded["command"]["input"]["closeAfterWrite"] = true;
  assert(!validation_fails(recorded));
  recorded["command"]["stopAtEntry"] = false;
  assert(validation_fails(recorded, "INVALID_REQUEST"));
  recorded["command"]["stopAtEntry"] = true;
  for (const auto& bound : Json::array({1, 1000000})) {
    recorded["command"]["maxRecordedInstructions"] = bound;
    assert(!validation_fails(recorded));
  }
  for (const auto& bound : Json::array({0, -1, 1000001, 1.5, "32", false})) {
    recorded["command"]["maxRecordedInstructions"] = bound;
    assert(validation_fails(recorded));
  }
  recorded["command"]["maxRecordedInstructions"] = 32;
  recorded["command"]["recordingProfile"] = "native";
  assert(validation_fails(recorded, "INVALID_REQUEST"));
  recorded["command"].erase("maxRecordedInstructions");
  assert(!validation_fails(recorded));
  recorded["command"]["recordingProfile"] = "rr";
  assert(validation_fails(recorded, "INVALID_REQUEST"));
  Json gateway = append;
  for (const auto* kind : {"readRecording", "reverseInstruction", "inspectModules"}) {
    gateway["command"] = {{"kind", kind}};
    assert(!validation_fails(gateway));
    auto missingStop = gateway;
    missingStop.erase("expectedStop");
    assert(validation_fails(missingStop, "INVALID_REQUEST"));
    gateway["command"]["pid"] = 1;
    assert(validation_fails(gateway, "INVALID_REQUEST"));
  }
  // Cursors are full-width integers represented as canonical decimal text;
  // they must not pass through JavaScript's floating-point number domain.
  gateway["command"] = {{"kind", "seekRecording"}, {"instruction", "0"}};
  for (const auto* cursor : {"0", "1", "9007199254740992", "18446744073709551615"}) {
    gateway["command"]["instruction"] = cursor;
    assert(!validation_fails(gateway));
  }
  for (const auto& cursor : Json::array({"", "00", "01", "-1", "+1", " 1", "1 ", "0x1", "1.0", "1e3",
                                        "1\n-exec-continue", "18446744073709551616", 1, false})) {
    gateway["command"]["instruction"] = cursor;
    assert(validation_fails(gateway));
  }
  gateway["command"]["instruction"] = "0";
  gateway.erase("expectedStop");
  assert(validation_fails(gateway, "INVALID_REQUEST"));
  gateway["command"] = {{"kind", "probeRecorders"}};
  assert(!validation_fails(gateway));
  for (const auto* executable : {"executable", "gdbPath", "rrPath"}) {
    auto injected = gateway;
    injected["command"][executable] = "/tmp/untrusted-recorder";
    assert(validation_fails(injected, "INVALID_REQUEST"));
  }
  gateway["command"] = {{"kind", "readModuleSnapshot"}, {"snapshotId", "modules-1"}};
  assert(!validation_fails(gateway));
  for (const auto& invalidId : Json::array({"", 1, nullptr})) {
    gateway["command"]["snapshotId"] = invalidId;
    assert(validation_fails(gateway));
  }
  // Layout and ELF inspection cannot accept executable expressions or paths.
  gateway["expectedStop"] = {{"stopId", "stop-1"}, {"stateRevision", 1}};
  for (const auto* kind : {"inspectModuleSymbols", "inspectVariableLayout"}) {
    const auto field = std::string(kind) == "inspectModuleSymbols" ? "moduleId" : "locator";
    gateway["command"] = {{"kind", kind}, {field, "identifier"}};
    assert(!validation_fails(gateway));
    auto missingStop = gateway; missingStop.erase("expectedStop");
    assert(validation_fails(missingStop, "INVALID_REQUEST"));
    for (const auto* key : {"path", "expression", "pid"}) {
      auto injected = gateway; injected["command"][key] = "untrusted";
      assert(validation_fails(injected, "INVALID_REQUEST"));
    }
  }
  // Root variable locators include their frame prefix and must round-trip
  // identifiers at the engine's 256-byte name limit through this gateway.
  gateway["command"] = {{"kind", "inspectVariableLayout"}, {"locator", "frame:0:" + std::string(256, 'x')}};
  assert(!validation_fails(gateway));
  gateway["command"]["locator"] = "frame:4095:" + std::string(256, 'x');
  assert(!validation_fails(gateway));
  gateway["command"]["locator"] = std::string(272, 'x');
  assert(!validation_fails(gateway));  // Exact locator syntax belongs to GdbEngine.
  gateway["command"]["locator"] = std::string(273, 'x');
  assert(validation_fails(gateway, "LIMIT_EXCEEDED"));
  for (const auto& invalidLocator : Json::array({"", false, nullptr, 1})) {
    gateway["command"]["locator"] = invalidLocator;
    assert(validation_fails(gateway, "INVALID_REQUEST"));
  }
  gateway["command"]["locator"] = std::string("frame:0:") + char(0xff);
  assert(validation_fails(gateway, "INVALID_REQUEST"));
  // Other IDs retain their existing independent limit.
  gateway["command"] = {{"kind", "inspectModuleSymbols"}, {"moduleId", std::string(257, 'x')}};
  assert(validation_fails(gateway, "LIMIT_EXCEEDED"));
  gateway.erase("expectedStop");
  gateway["command"] = {{"kind", "readModuleSymbols"}, {"snapshotId", "symbols-1"}, {"start", 0}, {"count", 100}};
  assert(!validation_fails(gateway));
  for (const auto& count : Json::array({0, -1, 1025, "1", 1.5})) {
    gateway["command"]["count"] = count; assert(validation_fails(gateway));
  }
  gateway["command"] = {{"kind", "readVariableLayout"}, {"snapshotId", "layout-1"}};
  assert(!validation_fails(gateway));
  gateway["command"]["snapshotId"] = "";
  assert(validation_fails(gateway));
  // The ABI decoder accepts bounded exact addresses, never an expression.
  gateway["expectedStop"] = {{"stopId", "stop-1"}, {"stateRevision", 1}};
  const Json vtableCommand = {{"kind", "inspectVtable"}, {"abi", "itanium-x86_64-absolute-v1"},
                              {"vptrAddressHex", "0x1234"}, {"maxEntries", 64}};
  gateway["command"] = vtableCommand;
  assert(!validation_fails(gateway));
  auto missingVtableStop = gateway; missingVtableStop.erase("expectedStop");
  assert(validation_fails(missingVtableStop, "INVALID_REQUEST"));
  for (const auto& address : {"0x0", "0xffffffffff600000", "0xfffffffffffffff7", "0xABCDEF"}) {
    gateway["command"]["vptrAddressHex"] = address;
    assert(!validation_fails(gateway));
  }
  for (const auto& address : Json::array({"", "0x", "1234", "-0x1", "0x+1", "0x1\ncontinue",
                                         "0x1\t", "&object", "0xfffffffffffffff8", "0x10000000000000000", 1, false, nullptr})) {
    gateway["command"]["vptrAddressHex"] = address;
    assert(validation_fails(gateway));
  }
  for (const auto& count : Json::array({0, -1, 65, 1.5, true, "1", nullptr})) {
    gateway["command"] = vtableCommand; gateway["command"]["maxEntries"] = count;
    assert(validation_fails(gateway));
  }
  for (const auto* extra : {"expression", "pid", "path", "script"}) {
    gateway["command"] = vtableCommand; gateway["command"][extra] = "untrusted";
    assert(validation_fails(gateway, "INVALID_REQUEST"));
  }
  gateway["command"] = vtableCommand; gateway["command"].erase("abi");
  assert(validation_fails(gateway, "INVALID_REQUEST"));
  gateway["command"]["abi"] = "relative";
  assert(validation_fails(gateway, "INVALID_REQUEST"));
  gateway.erase("expectedStop");
  gateway["command"] = {{"kind", "readVtableSnapshot"}, {"snapshotId", "vtable-1"}};
  assert(!validation_fails(gateway));
  gateway["command"]["snapshotId"] = "";
  assert(validation_fails(gateway));
  gateway["expectedStop"] = {{"stopId","stop-1"},{"stateRevision",1}};
  const Json editCommand = {{"kind","writeMemory"},{"profile","native-private-memory-v1"},
    {"addressHex","0x0000ABCDEF"},{"expectedBytesHex","00fF"},{"replacementBytesHex","FE80"}};
  gateway["command"] = editCommand;
  assert(!validation_fails(gateway));
  auto missingEditStop = gateway; missingEditStop.erase("expectedStop");
  assert(validation_fails(missingEditStop,"INVALID_REQUEST"));
  for (const auto& address : Json::array({"0x", "&x", "0x+1", "0x1\n-exec-continue", "0xffffffffffffffff", "0x10000000000000000", -1, nullptr})) {
    gateway["command"] = editCommand; gateway["command"]["addressHex"] = address;
    assert(validation_fails(gateway));
  }
  for (const auto& bytes : Json::array({"", "0", "xx", "00ff ", "00\nff", 1, false, nullptr})) {
    for (const auto* key : {"expectedBytesHex","replacementBytesHex"}) {
      gateway["command"] = editCommand; gateway["command"][key] = bytes;
      assert(validation_fails(gateway));
    }
  }
  gateway["command"] = editCommand; gateway["command"]["replacementBytesHex"] = "00";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  gateway["command"] = editCommand;
  gateway["command"]["expectedBytesHex"] = std::string(512,'f');
  gateway["command"]["replacementBytesHex"] = std::string(512,'0');
  assert(!validation_fails(gateway));
  gateway["command"]["replacementBytesHex"] = std::string(514,'0');
  assert(validation_fails(gateway,"LIMIT_EXCEEDED"));
  gateway["command"] = editCommand; gateway["command"]["profile"] = "auto";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  gateway["command"] = editCommand; gateway["command"]["pid"] = 1;
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  gateway.erase("expectedStop"); gateway["command"] = {{"kind","listBranches"}};
  assert(!validation_fails(gateway));
  gateway["command"] = {{"kind","listMemoryInterventions"},{"start",0},{"count",128}};
  assert(!validation_fails(gateway));
  gateway["command"]["count"] = 129; assert(validation_fails(gateway));
  gateway["command"] = {{"kind","readMemoryIntervention"},{"interventionId","intervention-1"}};
  assert(!validation_fails(gateway));
  gateway["expectedStop"] = {{"stopId","stop-1"},{"stateRevision",1}};
  gateway["command"] = {{"kind","inspectScalarStorage"},{"locator","frame:0:value"}};
  assert(!validation_fails(gateway));
  auto noScalarStop = gateway; noScalarStop.erase("expectedStop");
  assert(validation_fails(noScalarStop,"INVALID_REQUEST"));
  const Json scalarCommand = {{"kind","writeScalarStorage"},{"profile","native-dwarf-scalar-v1"},
    {"snapshotId","scalar-1"},{"value",{{"kind","integer"},{"decimal","-9223372036854775808"},{"bits",64},{"signed",true}}}};
  gateway["command"] = scalarCommand;
  assert(!validation_fails(gateway));
  noScalarStop = gateway; noScalarStop.erase("expectedStop");
  assert(validation_fails(noScalarStop,"INVALID_REQUEST"));
  for (const auto& value : Json::array({"-0","00","-01","+1","-","1.0","1e1"," 1","1 ","１", "184467440737095516150",1,nullptr})) {
    gateway["command"] = scalarCommand; gateway["command"]["value"]["decimal"] = value;
    assert(validation_fails(gateway));
  }
  for (const auto& bits : Json::array({0,1,7,65,128,32.0,true,"32"})) {
    gateway["command"] = scalarCommand; gateway["command"]["value"]["bits"] = bits;
    assert(validation_fails(gateway));
  }
  gateway["command"] = scalarCommand; gateway["command"]["value"] = {{"kind","boolean"},{"value",true}};
  assert(!validation_fails(gateway));
  gateway["command"]["value"]["value"] = 1; assert(validation_fails(gateway));
  gateway["command"] = scalarCommand; gateway["command"]["value"]["kind"] = "float";
  assert(validation_fails(gateway));
  gateway["command"] = scalarCommand; gateway["command"]["profile"] = "native-private-memory-v1";
  assert(validation_fails(gateway));
  gateway["command"] = scalarCommand; gateway["command"]["addressHex"] = "0x1234";
  assert(validation_fails(gateway));
  gateway.erase("expectedStop"); gateway["command"] = {{"kind","readScalarStorage"},{"snapshotId","scalar-1"}};
  assert(!validation_fails(gateway));
  // A configured smaller budget must be advertised and rejected before
  // accepting an asynchronous trace, not discovered after acceptance.
  phantom::ValidationLimits small;
  small.maxInstructions = 16;
  small.maxMemoryReadBytes = 32;
  Json trace = append;
  trace["command"] = {{"kind","traceInstructions"},{"count",16},{"memoryRanges",Json::array()}};
  phantom::validate_request(trace, small);
  trace["command"]["count"] = 17;
  try { phantom::validate_request(trace, small); assert(false); }
  catch (const ValidationError& e) { assert(e.code == "INVALID_REQUEST"); }
  trace["command"]["count"] = 1;
  trace["command"]["memoryRanges"] = {{{"addressHex","0x10"},{"byteCount",33}}};
  try { phantom::validate_request(trace, small); assert(false); }
  catch (const ValidationError& e) { assert(e.code == "INVALID_REQUEST"); }
  char temporary[] = "/tmp/phantom-service-limits-XXXXXX";
  const auto directory = ::mkdtemp(temporary); assert(directory);
  {
    phantom::ServiceOptions options; options.workspace = directory; options.limits = small;
    phantom::BackendService service(options);
    auto connected = service.connect({{"supportedProtocolVersions",{1}}});
    const auto& budgets = connected.front().at("capabilities").at("limits");
    assert(budgets.at("maxTraceInstructions") == 16);
    assert(budgets.at("maxTraceMemoryBytes") == 32);
    assert(budgets.at("maxCaptureBytes") == 32);
  }
  std::filesystem::remove_all(directory);
  std::cout << "validation tests passed\n";
}
