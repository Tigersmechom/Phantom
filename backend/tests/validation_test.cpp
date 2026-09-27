#include "phantom/validation.hpp"

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
  std::cout << "validation tests passed\n";
}
