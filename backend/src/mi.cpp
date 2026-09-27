#include "phantom/mi.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>

namespace phantom::mi {
namespace {

class Parser {
 public:
  Parser(std::string_view input, const Limits& limits) : s_(input), limits_(limits) {}
  Record record() {
    if (s_.size() > limits_.max_line_bytes) fail(ParseErrorCode::limit, "MI line exceeds limit");
    if (s_.substr(pos_, end_position() - pos_) == "(gdb)") { pos_ = s_.size(); return {RecordKind::prompt, {}, {}, {}, {}}; }
    std::optional<std::string> token;
    std::size_t begin = pos_;
    while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    if (pos_ > begin) token = std::string(s_.substr(begin, pos_ - begin));
    if (pos_ >= s_.size()) fail(ParseErrorCode::syntax, "missing MI record prefix");
    char prefix = s_[pos_++];
    Record result; result.token = std::move(token);
    if (prefix == '~' || prefix == '@' || prefix == '&') {
      result.kind = prefix == '~' ? RecordKind::console : prefix == '@' ? RecordKind::target : RecordKind::log;
      if (pos_ < s_.size() && s_[pos_] == '"') result.stream = parse_string();
      else result.stream = std::string(s_.substr(pos_, end_position() - pos_));
      consume_end(); return result;
    }
    switch (prefix) {
      case '^': result.kind = RecordKind::result; break;
      case '*': result.kind = RecordKind::exec; break;
      case '+': result.kind = RecordKind::status; break;
      case '=': result.kind = RecordKind::notify; break;
      default: fail(ParseErrorCode::syntax, "unknown MI record prefix");
    }
    result.klass = parse_word();
    if (prefix == '^' && result.klass != "done" && result.klass != "running" &&
        result.klass != "connected" && result.klass != "error" && result.klass != "exit")
      fail(ParseErrorCode::syntax, "unknown MI result class");
    while (pos_ < end_position()) {
      expect(','); result.fields.push_back(parse_result());
    }
    consume_end(); return result;
  }

 private:
  std::string_view s_; const Limits& limits_; std::size_t pos_ = 0; std::size_t depth_ = 0; std::size_t values_ = 0;
  std::size_t end_position() const {
    std::size_t end = s_.size();
    if (end && s_[end - 1] == '\n') --end;
    if (end && s_[end - 1] == '\r') --end;
    return end;
  }
  [[noreturn]] void fail(ParseErrorCode code, std::string msg) const { throw ParseError(code, pos_, std::move(msg)); }
  void check_value() { if (++values_ > limits_.max_values) fail(ParseErrorCode::limit, "too many MI values"); }
  void expect(char c) { if (pos_ >= end_position() || s_[pos_] != c) fail(ParseErrorCode::syntax, std::string("expected '") + c + "'"); ++pos_; }
  std::string parse_word() {
    std::size_t b = pos_;
    while (pos_ < end_position() && s_[pos_] != ',' && s_[pos_] != '=' && s_[pos_] != '}' && s_[pos_] != ']') ++pos_;
    if (b == pos_) fail(ParseErrorCode::syntax, "empty MI identifier");
    return std::string(s_.substr(b, pos_ - b));
  }
  std::string parse_string() {
    expect('"'); std::string out;
    while (pos_ < end_position()) {
      unsigned char c = static_cast<unsigned char>(s_[pos_++]);
      if (c == '"') return out;
      if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
      if (pos_ >= end_position()) fail(ParseErrorCode::invalid_escape, "unterminated C-string escape");
      char e = s_[pos_++];
      switch (e) {
        case 'a': out.push_back('\a'); break; case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
        case 'v': out.push_back('\v'); break; case '\\': out.push_back('\\'); break;
        case '"': out.push_back('"'); break; case '?': out.push_back('?'); break;
        case 'x': {
          if (pos_ + 2 > end_position() || !std::isxdigit(static_cast<unsigned char>(s_[pos_])) ||
              !std::isxdigit(static_cast<unsigned char>(s_[pos_ + 1])))
            fail(ParseErrorCode::invalid_escape, "invalid hexadecimal escape");
          auto hex = [](char x) -> int { return std::isdigit(static_cast<unsigned char>(x)) ? x - '0' : std::tolower(static_cast<unsigned char>(x)) - 'a' + 10; };
          out.push_back(static_cast<char>((hex(s_[pos_]) << 4) | hex(s_[pos_ + 1]))); pos_ += 2; break;
        }
        default:
          if (e < '0' || e > '7') fail(ParseErrorCode::invalid_escape, "unknown C-string escape");
          int value = e - '0'; int count = 1;
          while (count < 3 && pos_ < end_position() && s_[pos_] >= '0' && s_[pos_] <= '7') { value = value * 8 + s_[pos_++] - '0'; ++count; }
          out.push_back(static_cast<char>(value));
      }
    }
    fail(ParseErrorCode::syntax, "unterminated MI C-string");
  }
  std::pair<std::string, Value::Ptr> parse_result() {
    std::string key = parse_word(); expect('='); return {std::move(key), parse_value()};
  }
  std::vector<std::pair<std::string, Value::Ptr>> parse_results(char close) {
    std::vector<std::pair<std::string, Value::Ptr>> fields;
    if (pos_ < end_position() && s_[pos_] == close) return fields;
    fields.push_back(parse_result());
    while (pos_ < end_position() && s_[pos_] == ',') { ++pos_; fields.push_back(parse_result()); }
    return fields;
  }
  Value::Ptr parse_value() {
    check_value();
    if (++depth_ > limits_.max_depth) fail(ParseErrorCode::limit, "MI nesting exceeds limit");
    Value result;
    if (pos_ >= end_position()) fail(ParseErrorCode::syntax, "missing MI value");
    if (s_[pos_] == '"') result = Value::string_value(parse_string());
    else if (s_[pos_] == '{') {
      ++pos_; auto fields = parse_results('}'); expect('}'); result = Value::tuple_value(std::move(fields));
    } else if (s_[pos_] == '[') {
      ++pos_;
      if (pos_ < end_position() && s_[pos_] == ']') { ++pos_; result = Value::value_list({}); }
      else {
        // A list beginning with an identifier followed by '=' is a result list;
        // all other non-empty lists contain values.
        bool result_list = pos_ < end_position() &&
                           (std::isalpha(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '_');
        if (result_list) { auto fields = parse_results(']'); expect(']'); result = Value::result_list(std::move(fields)); }
        else {
          std::vector<Value::Ptr> values; values.push_back(parse_value());
          while (pos_ < end_position() && s_[pos_] == ',') { ++pos_; values.push_back(parse_value()); }
          expect(']'); result = Value::value_list(std::move(values));
        }
      }
    } else fail(ParseErrorCode::syntax, "invalid MI value");
    --depth_; return std::make_shared<Value>(std::move(result));
  }
  void consume_end() {
    std::size_t end = end_position();
    if (pos_ != end) fail(ParseErrorCode::trailing_data, "trailing MI record data");
    pos_ = s_.size();
  }
};

}  // namespace

ParseError::ParseError(ParseErrorCode code, std::size_t offset, std::string message)
    : std::runtime_error(std::move(message)), code_(code), offset_(offset) {}

Record parse_record(std::string_view line, const Limits& limits) { return Parser(line, limits).record(); }

std::string quote(std::string_view value) {
  std::ostringstream out; out << '"';
  for (unsigned char c : value) {
    switch (c) {
      case '\a': out << "\\a"; break; case '\b': out << "\\b"; break; case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break;
      case '\v': out << "\\v"; break; case '\\': out << "\\\\"; break; case '"': out << "\\\""; break;
      default: if (c < 0x20 || c == 0x7f) out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << std::dec; else out << static_cast<char>(c);
    }
  }
  out << '"'; return out.str();
}

const Value* find(const std::vector<std::pair<std::string, Value::Ptr>>& fields, std::string_view key) {
  for (const auto& [name, value] : fields) if (name == key) return value.get();
  return nullptr;
}

std::vector<const Value*> find_all(const std::vector<std::pair<std::string, Value::Ptr>>& fields, std::string_view key) {
  std::vector<const Value*> result; for (const auto& [name, value] : fields) if (name == key) result.push_back(value.get()); return result;
}

std::vector<std::string> LineBuffer::feed(std::string_view chunk) {
  buffer_.append(chunk.data(), chunk.size());
  std::vector<std::string> result;
  for (;;) {
    std::size_t pos = buffer_.find_first_of("\r\n"); if (pos == std::string::npos) break;
    if (pos > limits_.max_line_bytes) throw ParseError(ParseErrorCode::limit, pos, "MI line exceeds limit");
    if (buffer_[pos] == '\r' && pos + 1 == buffer_.size()) break; // await possible LF
    std::size_t consume = 1; if (buffer_[pos] == '\r' && pos + 1 < buffer_.size() && buffer_[pos + 1] == '\n') consume = 2;
    result.emplace_back(buffer_.substr(0, pos)); buffer_.erase(0, pos + consume);
  }
  if (buffer_.size() > limits_.max_line_bytes) throw ParseError(ParseErrorCode::limit, buffer_.size(), "MI line exceeds limit");
  return result;
}

std::vector<std::string> LineBuffer::finish() {
  if (buffer_.size() == 1 && buffer_[0] == '\r') { buffer_.clear(); return {""}; }
  if (!buffer_.empty() && buffer_.back() == '\r') { buffer_.pop_back(); auto line = std::move(buffer_); buffer_.clear(); return {std::move(line)}; }
  if (!buffer_.empty()) throw ParseError(ParseErrorCode::syntax, buffer_.size(), "incomplete MI line at EOF");
  return {};
}

}  // namespace phantom::mi
