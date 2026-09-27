#pragma once

#include <cstddef>
#include <optional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace phantom::mi {

enum class ValueKind { string, tuple, value_list, result_list };

struct Value {
  ValueKind kind = ValueKind::string;
  std::string text;  // decoded C-string for string values
  using Ptr = std::shared_ptr<Value>;
  std::vector<std::pair<std::string, Ptr>> fields;  // order/repeated keys retained
  std::vector<Ptr> values;

  static Value string_value(std::string value) { return {ValueKind::string, std::move(value), {}, {}}; }
  static Value tuple_value(std::vector<std::pair<std::string, Ptr>> value) {
    return {ValueKind::tuple, {}, std::move(value), {}};
  }
  static Value value_list(std::vector<Ptr> value) { return {ValueKind::value_list, {}, {}, std::move(value)}; }
  static Value result_list(std::vector<std::pair<std::string, Ptr>> value) {
    return {ValueKind::result_list, {}, std::move(value), {}};
  }
};

struct Limits {
  std::size_t max_line_bytes = 1024 * 1024;
  std::size_t max_depth = 128;
  std::size_t max_values = 100000;
};

enum class RecordKind { result, exec, status, notify, console, target, log, prompt };

struct Record {
  RecordKind kind = RecordKind::result;
  std::optional<std::string> token;
  std::string klass;  // result/async class (done, stopped, ...)
  std::vector<std::pair<std::string, Value::Ptr>> fields;
  std::string stream;  // decoded stream text for ~ @ & records
};

enum class ParseErrorCode { syntax, limit, invalid_escape, trailing_data };

class ParseError final : public std::runtime_error {
 public:
  ParseError(ParseErrorCode code, std::size_t offset, std::string message);
  ParseErrorCode code() const noexcept { return code_; }
  std::size_t offset() const noexcept { return offset_; }

 private:
  ParseErrorCode code_;
  std::size_t offset_;
};

Record parse_record(std::string_view line, const Limits& limits = {});
std::string quote(std::string_view value);

const Value* find(const std::vector<std::pair<std::string, Value::Ptr>>& fields, std::string_view key);
std::vector<const Value*> find_all(const std::vector<std::pair<std::string, Value::Ptr>>& fields,
                                   std::string_view key);

// Turns arbitrary read chunks into complete CR/LF-delimited MI records. A
// partial final line is rejected by finish(), preventing silent truncation.
class LineBuffer final {
 public:
  explicit LineBuffer(Limits limits = {}) : limits_(limits) {}
  std::vector<std::string> feed(std::string_view chunk);
  std::vector<std::string> finish();
  void clear() noexcept { buffer_.clear(); }

 private:
  Limits limits_;
  std::string buffer_;
};

}  // namespace phantom::mi
