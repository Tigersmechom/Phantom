#include "phantom/validation.hpp"
#include "phantom/service.hpp"
#include "phantom/sha256.hpp"

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
  auto helperBuild = launch;
  helperBuild["command"] = {{"kind", "build"}, {"architecture", "x86_64"},
    {"source", {{"id", "source"}, {"documents", Json::array({{
      {"documentId", "main"}, {"revisionId", "r1"}, {"path", "main.cpp"},
      {"text", "int main() {}"}, {"sha256", phantom::sha256_hex("int main() {}")}}})}}},
    {"configuration", {{"revisionId", "config"}, {"compiler", "clang++"},
      {"flags", Json::array({"-g", "-O0"})}, {"outputDirectory", ".phantom/build"},
      {"addressProfile", "fixed-executable"}, {"runtimeProfile", "linux-x86_64-scratch-v1"}}}};
  assert(!validation_fails(helperBuild));
  for (const auto& profile : Json::array({nullptr, false, 1, "automatic", "linux-x86_64-scratch-v2"})) {
    auto invalid = helperBuild;
    invalid["command"]["configuration"]["runtimeProfile"] = profile;
    assert(validation_fails(invalid, "INVALID_REQUEST"));
  }
  helperBuild["command"]["configuration"]["runtimeProfile"] = "none";
  assert(!validation_fails(helperBuild));
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
  Json isolated = launch;
  for (const auto* profile : {"native", "single-process-v1"}) {
    isolated["command"]["processProfile"] = profile;
    assert(!validation_fails(isolated));
  }
  for (const auto& profile : Json::array({nullptr, false, 1, "", "single-process", Json::object(), Json::array()})) {
    isolated["command"]["processProfile"] = profile;
    assert(validation_fails(isolated, "INVALID_REQUEST"));
  }
  isolated["command"]["processProfile"] = "single-process-v1";
  isolated["command"]["stopAtEntry"] = false;
  assert(validation_fails(isolated, "INVALID_REQUEST"));
  isolated["command"]["stopAtEntry"] = true;
  isolated["command"]["input"]["closeAfterWrite"] = true;
  isolated["command"]["recordingProfile"] = "gdb-record-full";
  assert(validation_fails(isolated, "INVALID_REQUEST"));
  isolated["command"]["processProfile"] = "native";
  assert(!validation_fails(isolated));
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
  // Runtime readiness runs only the shipped fixture. The wire cannot select
  // a process, an executable, injected instructions or syscall arguments.
  gateway["command"] = {{"kind", "probeRuntime"}};
  gateway["session"] = nullptr;
  assert(!validation_fails(gateway));
  for (const auto* field : {"pid", "path", "gdbPath", "fixturePath", "profile",
                            "code", "syscall", "arguments", "timeoutMs"}) {
    auto injected = gateway;
    injected["command"][field] = "untrusted";
    assert(validation_fails(injected, "INVALID_REQUEST"));
  }
  gateway["command"] = {{"kind", "runRuntimeHelper"}, {"profile", "linux-x86_64-scratch-v1"}};
  assert(validation_fails(gateway, "INVALID_REQUEST"));
  gateway["expectedStop"] = {{"stopId", "stop-1"}, {"stateRevision", 1}};
  assert(!validation_fails(gateway));
  for (const auto* field : {"syscall", "code", "addressHex", "arguments", "timeoutMs", "helper"}) {
    auto injected = gateway;
    injected["command"][field] = "untrusted";
    assert(validation_fails(injected, "INVALID_REQUEST"));
  }
  for (const auto& profile : Json::array({nullptr, false, "native", "none", "linux-x86_64-scratch-v2"})) {
    auto invalid = gateway;
    invalid["command"]["profile"] = profile;
    assert(validation_fails(invalid, "INVALID_REQUEST"));
  }
  gateway.erase("expectedStop");
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
  const Json batchRange = {{"addressHex","0x10"},{"expectedBytesHex","00ff"},{"replacementBytesHex","12AB"}};
  const Json batchCommand = {{"kind","writeMemoryBatch"},{"profile","native-private-memory-batch-v1"},
    {"edits",Json::array({batchRange})}};
  gateway["command"] = batchCommand;
  assert(!validation_fails(gateway));
  auto missingBatchStop = gateway; missingBatchStop.erase("expectedStop");
  assert(validation_fails(missingBatchStop,"INVALID_REQUEST"));
  for (const auto& edits : Json::array({nullptr,false,1,"ranges",Json::object(),Json::array()})) {
    gateway["command"] = batchCommand; gateway["command"]["edits"] = edits;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto& edit : Json::array({nullptr,true,3,"0x10",Json::array(),Json::object()})) {
    gateway["command"] = batchCommand; gateway["command"]["edits"] = Json::array({edit});
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"addressHex","expectedBytesHex","replacementBytesHex"}) {
    gateway["command"] = batchCommand; gateway["command"]["edits"][0].erase(key);
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"kind","profile","pid","expression","snapshotId"}) {
    gateway["command"] = batchCommand; gateway["command"]["edits"][0][key] = "extra";
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* profile : {"auto","native-private-memory-v1","native-dwarf-scalar-v2"}) {
    gateway["command"] = batchCommand; gateway["command"]["profile"] = profile;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto& bytes : Json::array({"","0","GG"," 00","00\n","0x00",0,false,nullptr})) {
    for (const auto* key : {"expectedBytesHex","replacementBytesHex"}) {
      gateway["command"] = batchCommand; gateway["command"]["edits"][0][key] = bytes;
      assert(validation_fails(gateway));
    }
  }
  gateway["command"] = batchCommand; gateway["command"]["edits"][0]["replacementBytesHex"] = "00";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  for (const auto* address : {"0x10","0x000010","0x11","0x0F"}) {
    gateway["command"] = batchCommand;
    auto other = batchRange; other["addressHex"] = address;
    gateway["command"]["edits"].push_back(other);
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* address : {"0x12","0x0E"}) {
    gateway["command"] = batchCommand;
    auto other = batchRange; other["addressHex"] = address;
    gateway["command"]["edits"].push_back(other);
    assert(!validation_fails(gateway)); // Adjacency and descending request order are valid.
  }
  for (const auto& address : Json::array({"0x","&x","0x+1","0x10\n-exec-continue","0xfffffffffffffffe",
                                       "0xffffffffffffffff","0x10000000000000000",-1,nullptr})) {
    gateway["command"] = batchCommand; gateway["command"]["edits"][0]["addressHex"] = address;
    assert(validation_fails(gateway));
  }
  gateway["command"] = batchCommand; gateway["command"]["edits"][0]["addressHex"] = "0xfffffffffffffffd";
  assert(!validation_fails(gateway)); // Exclusive end still fits uint64.
  gateway["command"] = batchCommand; gateway["command"]["edits"] = Json::array();
  for (unsigned i = 0; i < 8; ++i) {
    auto range = batchRange; range["addressHex"] = "0x"+std::to_string(100+i*100);
    range["expectedBytesHex"] = std::string(64,'0'); range["replacementBytesHex"] = std::string(64,'f');
    gateway["command"]["edits"].push_back(range);
  }
  assert(!validation_fails(gateway)); // Exactly eight ranges and 256 total bytes.
  gateway["command"]["edits"].push_back(batchRange);
  assert(validation_fails(gateway,"LIMIT_EXCEEDED"));
  gateway["command"]["edits"].erase(8);
  gateway["command"]["edits"][7]["expectedBytesHex"] = std::string(66,'0');
  gateway["command"]["edits"][7]["replacementBytesHex"] = std::string(66,'f');
  assert(validation_fails(gateway,"LIMIT_EXCEEDED"));
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
  for (const auto* profile : {"native-dwarf-scalar-v1","native-dwarf-scalar-v2"}) {
    gateway["command"] = {{"kind","inspectScalarStorage"},{"locator","frame:0:value"},{"profile",profile}};
    assert(!validation_fails(gateway));
    gateway["command"] = scalarCommand; gateway["command"]["profile"] = profile;
    assert(!validation_fails(gateway));
  }
  for (const auto& profile : Json::array({nullptr,true,2,"auto","native-dwarf-scalar-v3"})) {
    gateway["command"] = {{"kind","inspectScalarStorage"},{"locator","frame:0:value"},{"profile",profile}};
    assert(validation_fails(gateway));
  }
  const Json floatCommand = {{"kind","writeScalarStorage"},{"profile","native-dwarf-scalar-v2"},
    {"snapshotId","scalar-1"},{"value",{{"kind","float"},{"bits",32},{"rawBitsHex","80000000"}}}};
  gateway["command"] = floatCommand;
  assert(!validation_fails(gateway));
  gateway["command"]["value"] = {{"kind","float"},{"bits",64},{"rawBitsHex","7ff0000000000001"}};
  assert(!validation_fails(gateway));
  gateway["command"]["profile"] = "native-dwarf-scalar-v1";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  for (const auto& bits : Json::array({0,16,128,32.0,true,"32",nullptr})) {
    gateway["command"] = floatCommand; gateway["command"]["value"]["bits"] = bits;
    assert(validation_fails(gateway));
  }
  for (const auto& raw : Json::array({"","8000000","800000000","0000000080000000","0x80000000","7F800001",
      "7g800001","8000000 ","8000000\n","８0000000",80000000,nullptr})) {
    gateway["command"] = floatCommand; gateway["command"]["value"]["rawBitsHex"] = raw;
    assert(validation_fails(gateway));
  }
  for (const auto* key : {"text","classification","decimal","signed","addressHex"}) {
    gateway["command"] = floatCommand; gateway["command"]["value"][key] = "0";
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"kind","bits","rawBitsHex"}) {
    gateway["command"] = floatCommand; gateway["command"]["value"].erase(key);
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  const Json registerCommand = {{"kind","writeRegister"},{"profile","native-x86_64-gpr-v1"},
    {"register","rax"},{"expectedValueHex","0x0000000000000000"},{"replacementValueHex","0xffffffffffffffff"}};
  for (const auto* name : {"rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"}) {
    gateway["command"] = registerCommand; gateway["command"]["register"] = name;
    assert(!validation_fails(gateway));
  }
  auto missingRegisterStop = gateway; missingRegisterStop.erase("expectedStop");
  assert(validation_fails(missingRegisterStop,"INVALID_REQUEST"));
  for (const auto& name : Json::array({"", "rip", "rsp", "rbp", "eax", "$rax", "RAX", "eflags", "fs_base", "xmm0", "r16",
       "rax;continue", "rax\n-exec-continue", "rax ", "раx", 0, nullptr})) {
    gateway["command"] = registerCommand; gateway["command"]["register"] = name;
    assert(validation_fails(gateway));
  }
  for (const auto* key : {"expectedValueHex","replacementValueHex"}) {
    for (const auto& value : Json::array({"", "0x0", "0x000000000000000", "0x00000000000000000", "0xFFFFFFFFFFFFFFFF",
         "0X0000000000000000", "000000000000000000", "-0x000000000000001", "0x100000000000000g", 42, true, nullptr})) {
      gateway["command"] = registerCommand; gateway["command"][key] = value;
      assert(validation_fails(gateway));
    }
  }
  for (const auto* key : {"profile","register","expectedValueHex","replacementValueHex"}) {
    gateway["command"] = registerCommand; gateway["command"].erase(key);
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"threadId","frameLevel","number","value","force","bits"}) {
    gateway["command"] = registerCommand; gateway["command"][key] = 0;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  gateway["command"] = registerCommand; gateway["command"]["profile"] = "native-private-memory-v1";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  for (const auto* kind : {"readIntervention","readRegisterIntervention","readMemoryIntervention"}) {
    gateway["command"] = {{"kind",kind},{"interventionId","intervention-1"}};
    auto historical = gateway; historical.erase("expectedStop");
    assert(!validation_fails(historical));
    historical["command"].erase("interventionId");
    assert(validation_fails(historical,"INVALID_REQUEST"));
  }
  for (const auto* kind : {"listInterventions","listRegisterInterventions","listMemoryInterventions"}) {
    gateway["command"] = {{"kind",kind},{"start",phantom::max_json_safe_integer},{"count",128}};
    assert(!validation_fails(gateway));
    gateway["command"]["count"] = 129;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
    gateway["command"]["count"] = 0;
    assert(validation_fails(gateway));
    gateway["command"]["count"] = 1; gateway["command"]["start"] = -1;
    assert(validation_fails(gateway));
  }
  auto scalarItem = scalarCommand; scalarItem.erase("kind");
  auto floatItem = floatCommand; floatItem.erase("kind"); floatItem["snapshotId"] = "scalar-2";
  const Json scalarBatchCommand = {{"kind","writeScalarStorageBatch"},{"profile","native-dwarf-scalar-batch-v1"},
    {"edits",Json::array({scalarItem,floatItem})}};
  gateway["command"] = scalarBatchCommand;
  assert(!validation_fails(gateway));
  auto missingScalarBatchStop = gateway; missingScalarBatchStop.erase("expectedStop");
  assert(validation_fails(missingScalarBatchStop,"INVALID_REQUEST"));
  for (const auto& entries : Json::array({nullptr,true,1,"snapshots",Json::object(),Json::array()})) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["edits"] = entries;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto& entry : Json::array({nullptr,false,1,"scalar-1",Json::array(),Json::object()})) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1] = entry;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"profile","snapshotId","value"}) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1].erase(key);
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* key : {"kind","addressHex","expectedBytesHex","locator","index"}) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1][key] = "forged";
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  for (const auto* profile : {"native-private-memory-batch-v1","native-dwarf-scalar-v2","auto"}) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["profile"] = profile;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1]["profile"] = "native-dwarf-scalar-v1";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1]["snapshotId"] = "scalar-1";
  assert(validation_fails(gateway,"INVALID_REQUEST"));
  for (const auto& value : Json::array({
      {{"kind","boolean"},{"value",1}},
      {{"kind","integer"},{"bits",64},{"signed",false},{"decimal","00"}},
      {{"kind","integer"},{"bits",64.0},{"signed",true},{"decimal","1"}},
      {{"kind","float"},{"bits",32},{"rawBitsHex","7F800000"}},
      {{"kind","float"},{"bits",32},{"rawBitsHex",0}},
      {{"kind","float"},{"bits",64},{"rawBitsHex","00000000"}},
      {{"kind","float"},{"bits",32},{"rawBitsHex","80000000"},{"text","-0"}}
    })) {
    gateway["command"] = scalarBatchCommand; gateway["command"]["edits"][1]["value"] = value;
    assert(validation_fails(gateway,"INVALID_REQUEST"));
  }
  gateway["command"] = scalarBatchCommand;
  gateway["command"]["edits"][0]["value"] = {{"kind","boolean"},{"value",false}};
  assert(!validation_fails(gateway));
  Json eightScalars = Json::array();
  for (unsigned i=0; i<8; ++i) {
    auto entry = scalarItem; entry["snapshotId"] = "scalar-"+std::to_string(i+1);
    eightScalars.push_back(entry);
  }
  gateway["command"] = scalarBatchCommand; gateway["command"]["edits"] = eightScalars;
  assert(!validation_fails(gateway)); // 8 exact 64-bit values, 64 bytes.
  auto ninth = scalarItem; ninth["snapshotId"] = "scalar-9";
  gateway["command"]["edits"].push_back(ninth);
  assert(validation_fails(gateway,"LIMIT_EXCEEDED"));
  gateway.erase("expectedStop"); gateway["command"] = {{"kind","readScalarStorage"},{"snapshotId","scalar-1"}};
  assert(!validation_fails(gateway));
  // A configured smaller budget must be advertised and rejected before
  // accepting an asynchronous trace, not discovered after acceptance.
  phantom::ValidationLimits small;
  small.maxInstructions = 16;
  small.maxMemoryReadBytes = 32;
  gateway["command"] = batchCommand;
  gateway["command"]["edits"][0]["expectedBytesHex"] = std::string(32,'0');
  gateway["command"]["edits"][0]["replacementBytesHex"] = std::string(32,'f');
  auto secondRange = gateway["command"]["edits"][0]; secondRange["addressHex"] = "0x20";
  gateway["command"]["edits"].push_back(secondRange);
  gateway["expectedStop"] = {{"stopId","stop-1"},{"stateRevision",1}};
  phantom::validate_request(gateway,small);
  gateway["command"]["edits"][1]["expectedBytesHex"] = std::string(34,'0');
  gateway["command"]["edits"][1]["replacementBytesHex"] = std::string(34,'f');
  try { phantom::validate_request(gateway,small); assert(false); }
  catch (const ValidationError& e) { assert(e.code == "LIMIT_EXCEEDED"); }
  gateway["command"] = scalarBatchCommand; gateway["command"]["edits"] = eightScalars;
  try { phantom::validate_request(gateway,small); assert(false); }
  catch (const ValidationError& e) { assert(e.code == "LIMIT_EXCEEDED"); }
  gateway["command"]["edits"].erase(gateway["command"]["edits"].begin()+4,gateway["command"]["edits"].end());
  phantom::validate_request(gateway,small);
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
    assert(budgets.at("maxMemoryBatchRanges") == 8);
    assert(budgets.at("maxMemoryBatchBytes") == 32);
    assert(budgets.at("maxScalarStorageBatchItems") == 8);
    assert(budgets.at("maxScalarStorageBatchBytes") == 32);
  }
  std::filesystem::remove_all(directory);
  std::cout << "validation tests passed\n";
}
