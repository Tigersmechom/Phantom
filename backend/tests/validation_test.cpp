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
