#include "phantom/gdb.hpp"

#include "phantom/mi.hpp"
#include "phantom/process.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <mutex>
#include <poll.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <termios.h>
#include <unistd.h>

namespace phantom {
namespace {

using MiValue = mi::Value;
struct MiRecord {
  char type = 0;
  std::string token;
  std::string klass;
  std::vector<std::pair<std::string, MiValue::Ptr>> fields;
  std::string stream;
};

// Use the shared strict parser for all GDB/MI records.  The adapter keeps the
// small legacy record shape used by the engine below, while preserving every
// repeated field and anonymous list value from phantom::mi.
MiRecord parseMiRecord(std::string_view line) {
  const auto record = mi::parse_record(line);
  MiRecord result;
  if (record.token) result.token = *record.token;
  switch (record.kind) {
    case mi::RecordKind::result: result.type = '^'; break;
    case mi::RecordKind::exec: result.type = '*'; break;
    case mi::RecordKind::status: result.type = '+'; break;
    case mi::RecordKind::notify: result.type = '='; break;
    case mi::RecordKind::console: result.type = '~'; break;
    case mi::RecordKind::target: result.type = '@'; break;
    case mi::RecordKind::log: result.type = '&'; break;
    case mi::RecordKind::prompt: result.type = '('; break;
  }
  result.klass = record.klass;
  result.fields = record.fields;
  result.stream = record.stream;
  return result;
}

const MiValue* field(const std::vector<std::pair<std::string, MiValue::Ptr>>& fs,
                     std::string_view key) {
  for (const auto& [k, v] : fs) if (k == key) return v.get();
  return nullptr;
}
const MiValue* field(const MiValue& v, std::string_view key) {
  return field(v.fields, key);
}
std::string miQuote(std::string_view s) {
  std::string out = "\"";
  for (char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c; break;
    }
  }
  out += '"';
  return out;
}
// GDB's `-exec-arguments` accepts shell-like words. Every user supplied
// argument is put in a single-quoted word; embedded quotes use the standard
// ''' idiom, so metacharacters remain literal when GDB starts the inferior.
std::string shellQuote(std::string_view s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'') out += "'\"'\"'";
    else out += c;
  }
  out += '\'';
  return out;
}
bool validEnvironmentName(std::string_view name) {
  const auto alpha = [](unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  };
  const auto alnum = [&](unsigned char c) { return alpha(c) || (c >= '0' && c <= '9'); };
  if (name.empty() || !(alpha(static_cast<unsigned char>(name.front())) || name.front() == '_')) return false;
  for (const unsigned char c : name.substr(1)) if (!(alnum(c) || c == '_')) return false;
  return true;
}
bool safeMiArgument(std::string_view value) {
  return value.find('\0') == std::string_view::npos && value.find('\r') == std::string_view::npos &&
         value.find('\n') == std::string_view::npos;
}
std::string valText(const MiValue* v) { return v ? v->text : std::string{}; }

std::string base64(std::string_view bytes) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve((bytes.size() + 2) / 3 * 4);
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    unsigned n = static_cast<unsigned char>(bytes[i]) << 16;
    if (i + 1 < bytes.size()) n |= static_cast<unsigned char>(bytes[i + 1]) << 8;
    if (i + 2 < bytes.size()) n |= static_cast<unsigned char>(bytes[i + 2]);
    out.push_back(alphabet[(n >> 18) & 63]);
    out.push_back(alphabet[(n >> 12) & 63]);
    out.push_back(i + 1 < bytes.size() ? alphabet[(n >> 6) & 63] : '=');
    out.push_back(i + 2 < bytes.size() ? alphabet[n & 63] : '=');
  }
  return out;
}

bool appendHexBytes(std::string_view hex, std::string& bytes) {
  if (hex.size() % 2 != 0) return false;
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = digit(hex[i]);
    const int lo = digit(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    bytes.push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

std::optional<std::uint64_t> parseAddress(std::string_view s) {
  if (s.empty()) return std::nullopt;
  // Address arguments are data, not shell/MI fragments.  Parse the caller's
  // view directly so there is no temporary-buffer lifetime hazard (the old
  // strtoull implementation compared a dangling end pointer).
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  if (s.empty()) return std::nullopt;
  std::uint64_t value = 0;
  const auto parsed = std::from_chars(s.data(), s.data() + s.size(), value, 16);
  if (parsed.ec != std::errc{} || parsed.ptr != s.data() + s.size()) return std::nullopt;
  return value;
}

}  // namespace

struct GdbEngine::Impl {
  explicit Impl(GdbOptions o) : options(std::move(o)) {}
  GdbOptions options;
  std::unique_ptr<Process> process;
  mutable std::mutex processMutex;
  std::atomic<int> control{0};
  std::atomic<bool> live{false};
  int nextToken = 1;
  std::string lines;
  std::filesystem::path tempDir;
  int ptyMaster = -1;
  int ptySlave = -1;
  std::filesystem::path ptyPath;
  std::string ptyOutput;
  std::size_t ptyTotalBytes = 0;
  std::size_t ptyMaxCanonical = 4095;
  std::atomic<std::size_t> deliveredInputBytes{0};
  std::jthread inputFeeder;
  GdbSourceBundle sourceBundle;
  std::string inferiorPid;
  struct BreakpointEntry { std::string documentId; std::string number; };
  std::vector<BreakpointEntry> breakpoints;
  int selectedFrame = 0;
  nlohmann::json lastStack = nlohmann::json::array();

  void setError(GdbError& e, std::string code, std::string msg, bool retry = false) {
    e = GdbError{std::move(code), std::move(msg), retry};
  }
  bool prepareTemp(const std::string& input, GdbError& e) {
    std::string pattern = (std::filesystem::temp_directory_path() /
                           "phantom-gdb-XXXXXX").string();
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');
    if (!mkdtemp(buf.data())) { setError(e, "LAUNCH_FAILED", "cannot create debugger temp directory"); return false; }
    tempDir = buf.data();
    ptyMaster = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (ptyMaster < 0 || ::grantpt(ptyMaster) != 0 || ::unlockpt(ptyMaster) != 0) {
      setError(e, "LAUNCH_FAILED", "cannot create inferior PTY");
      cleanupTemp();
      return false;
    }
    const char* slaveName = ::ptsname(ptyMaster);
    if (!slaveName) { setError(e, "LAUNCH_FAILED", "cannot resolve inferior PTY"); cleanupTemp(); return false; }
    ptyPath = slaveName;
    ptySlave = ::open(ptyPath.c_str(), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (ptySlave < 0) { setError(e, "LAUNCH_FAILED", "cannot open inferior PTY"); cleanupTemp(); return false; }
    termios tty{};
    if (::tcgetattr(ptySlave, &tty) == 0) {
      tty.c_lflag |= ICANON;
      tty.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHONL | ISIG | IEXTEN));
      tty.c_iflag &= static_cast<tcflag_t>(~(ICRNL | INLCR | IGNCR | IXON | IXOFF | IXANY));
      tty.c_oflag &= static_cast<tcflag_t>(~OPOST);
      // Keep canonical mode for deterministic VEOF, but disable its line
      // editing controls so submitted bytes are not silently erased or
      // reprinted by the terminal driver.
#ifdef VERASE
      tty.c_cc[VERASE] = _POSIX_VDISABLE;
#endif
#ifdef VKILL
      tty.c_cc[VKILL] = _POSIX_VDISABLE;
#endif
#ifdef VWERASE
      tty.c_cc[VWERASE] = _POSIX_VDISABLE;
#endif
#ifdef VREPRINT
      tty.c_cc[VREPRINT] = _POSIX_VDISABLE;
#endif
#ifdef VLNEXT
      tty.c_cc[VLNEXT] = _POSIX_VDISABLE;
#endif
#ifdef VDISCARD
      tty.c_cc[VDISCARD] = _POSIX_VDISABLE;
#endif
      tty.c_cc[VEOF] = 4;
      (void)::tcsetattr(ptySlave, TCSANOW, &tty);
    }
    if (const long maxCanonical = ::fpathconf(ptySlave, _PC_MAX_CANON); maxCanonical > 0)
      ptyMaxCanonical = static_cast<std::size_t>(maxCanonical);
    std::size_t lineBytes = 0;
    for (const unsigned char byte : input) {
      if (byte == 4) {
        setError(e, "LIMIT_EXCEEDED", "input contains the PTY EOF control byte");
        cleanupTemp();
        return false;
      }
      if (byte == '\n') { lineBytes = 0; continue; }
      if (++lineBytes > ptyMaxCanonical) {
        setError(e, "LIMIT_EXCEEDED", "input line exceeds the PTY canonical line limit");
        cleanupTemp();
        return false;
      }
    }
    const int flags = ::fcntl(ptyMaster, F_GETFL);
    if (flags < 0 || ::fcntl(ptyMaster, F_SETFL, flags | O_NONBLOCK) < 0) {
      setError(e, "LAUNCH_FAILED", "cannot configure inferior PTY"); cleanupTemp(); return false;
    }
    ptyOutput.clear(); ptyTotalBytes = 0; deliveredInputBytes.store(0);
    (void)input;
    return true;
  }
  void cleanupTemp() noexcept {
    inputFeeder.request_stop();
    if (inputFeeder.joinable()) inputFeeder.join();
    if (ptySlave >= 0) { (void)::close(ptySlave); ptySlave = -1; }
    if (ptyMaster >= 0) { (void)::close(ptyMaster); ptyMaster = -1; }
    ptyPath.clear(); ptyOutput.clear(); ptyTotalBytes = 0; deliveredInputBytes.store(0);
    if (!tempDir.empty()) { std::error_code ec; std::filesystem::remove_all(tempDir, ec); }
    tempDir.clear();
  }

  void drainPty() noexcept {
    if (ptyMaster < 0) return;
    std::array<char, 8192> buffer{};
    for (;;) {
      const auto n = ::read(ptyMaster, buffer.data(), buffer.size());
      if (n > 0) {
        ptyTotalBytes += static_cast<std::size_t>(n);
        ptyOutput.append(buffer.data(), static_cast<std::size_t>(n));
        if (ptyOutput.size() > options.maxOutputBytes)
          ptyOutput.erase(0, ptyOutput.size() - options.maxOutputBytes);
      } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        if (errno == EINTR) continue;
        break;
      } else break;
    }
  }

  void startInputFeeder(std::string input) {
    inputFeeder = std::jthread([this, input = std::move(input)](std::stop_token stop) {
      std::size_t offset = 0;
      auto writeAvailable = [&](const char* data, std::size_t size) {
        while (offset < size && !stop.stop_requested()) {
          pollfd pollfdValue{ptyMaster, POLLOUT, 0};
          const int ready = ::poll(&pollfdValue, 1, 50);
          if (ready <= 0) continue;
          const auto n = ::write(ptyMaster, data + offset, size - offset);
          if (n > 0) { offset += static_cast<std::size_t>(n); deliveredInputBytes.store(offset); continue; }
          if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
          return false;
        }
        return offset == size;
      };
      if (!writeAvailable(input.data(), input.size()) || stop.stop_requested()) return;
      // Ctrl-D is the terminal driver's canonical EOF marker. It follows all
      // submitted bytes, so formatted extraction receives data then EOF.
      const char eof = 4;
      // With canonical input, the first VEOF flushes a final unterminated
      // line; the second VEOF is required to make the following read observe
      // EOF. Sending two is harmless after a newline and fixes empty/no-newline
      // input without pretending that PTY delivery is extraction tracing.
      for (int marker = 0; marker < 2 && !stop.stop_requested(); ++marker) {
        bool sent = false;
        while (!sent && !stop.stop_requested()) {
          pollfd pollfdValue{ptyMaster, POLLOUT, 0};
          if (::poll(&pollfdValue, 1, 50) <= 0) continue;
          const auto n = ::write(ptyMaster, &eof, 1);
          if (n > 0) sent = true;
          else if (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return;
        }
      }
    });
  }

  nlohmann::json sourceLocation(std::string_view fullName, int line) const {
    if (fullName.empty() || line < 1) return nullptr;
    std::error_code ec;
    const auto full = std::filesystem::weakly_canonical(std::filesystem::path(fullName), ec);
    if (ec) return nullptr;
    const GdbSourceDocument* document = nullptr;
    for (const auto& candidate : sourceBundle.documents) {
      std::error_code candidateError;
      const auto path = std::filesystem::weakly_canonical(candidate.path, candidateError);
      if (!candidateError && path == full) { document = &candidate; break; }
    }
    if (!document) return nullptr;

    // GDB reports a line but normally no column.  Use a zero-width span at
    // the beginning of that line.  It is precise about the available fact,
    // validates against the submitted UTF-16 source, and never invents a
    // character range from the editor's current buffer.
    std::size_t byte = 0;
    std::size_t utf16 = 0;
    int currentLine = 1;
    while (currentLine < line && byte < document->text.size()) {
      const unsigned char c = static_cast<unsigned char>(document->text[byte]);
      std::size_t width = c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
      if (c == '\n') ++currentLine;
      if (currentLine <= line) utf16 += (c < 0xf0 ? 1 : 2);
      byte += std::min(width, document->text.size() - byte);
    }
    if (currentLine != line) return nullptr;
    return { {"documentId", document->documentId}, {"revisionId", document->revisionId},
             {"range", {{"start", utf16}, {"end", utf16}}},
             {"start", {{"line", line}, {"column", 1}}},
             {"end", {{"line", line}, {"column", 1}}} };
  }

  bool processLine(std::string line, std::string wantToken, bool waitStop,
                   bool& commandDone, bool& running, MiRecord& stopped,
                   GdbError& e) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (line.empty() || (line.rfind("(gdb)", 0) == 0 &&
                        line.find_first_not_of(" \t", 5) == std::string::npos)) return false;
    if (line.size() > 1024u * 1024u) {
      setError(e, "LIMIT_EXCEEDED", "GDB/MI record exceeds the configured line limit");
      return false;
    }
    MiRecord r;
    try {
      r = parseMiRecord(line);
    } catch (const mi::ParseError& ex) {
      const auto code = ex.code() == mi::ParseErrorCode::limit ? "LIMIT_EXCEEDED" : "READ_FAILED";
      setError(e, code, std::string("malformed GDB/MI record: ") + ex.what(), true);
      return false;
    } catch (const std::exception& ex) {
      setError(e, "READ_FAILED", std::string("cannot parse GDB/MI record: ") + ex.what(), true);
      return false;
    }
    if (r.type == '=' && r.klass == "thread-group-started") {
      const auto* pid = field(r.fields, "pid");
      if (pid && !pid->text.empty()) inferiorPid = pid->text;
    }
    if (r.type == '*' && r.klass == "stopped") { stopped = std::move(r); return waitStop; }
    if (r.type == '*' && (r.klass == "exited" || r.klass == "exited-normally")) { stopped = std::move(r); return waitStop; }
    if (r.type != '^' || r.token != wantToken) return false;
    // The caller uses the same record object for command acknowledgements
    // such as `stack=[...]`, `variables=[...]`, and `memory=[...]`.  Preserve
    // the parsed result before signalling completion; previously only async
    // stop records were copied, so every post-stop query appeared empty.
    stopped = r;
    if (r.klass == "error") {
      setError(e, "READ_FAILED", valText(field(r.fields, "msg")), true);
      if (e.message.empty()) e.message = "GDB MI command failed";
      commandDone = true;
      return true;
    }
    if (r.klass == "running") running = true;
    else commandDone = true;
    return !waitStop && commandDone;
  }

  // Issue one MI command. For execution commands, wait for the async stopped
  // record as well as the command acknowledgement. This keeps every returned
  // GdbStop tied to a real stop, rather than a guessed source line.
  bool command(std::string_view commandText, bool waitStop, MiRecord& stop,
               GdbError& e, int preempt = 0) {
    if (!process) { setError(e, "INVALID_REQUEST", "GDB is not running"); return false; }
    int token = nextToken++;
    std::string tokenText = std::to_string(token);
    try {
      process->write(tokenText + std::string(commandText) + "\n",
                     std::chrono::steady_clock::now() + options.commandTimeout);
    } catch (const std::exception& ex) {
      setError(e, "INTERNAL", ex.what(), true); return false;
    }
    // A control frame may have arrived after the service accepted this
    // operation but just before resume() wrote its MI command. Preserve that
    // request across the command boundary: sending SIGINT/SIGTERM while GDB
    // is idle would be racy, while sending it immediately after the command
    // is on the wire has deterministic meaning.
    if (preempt >= 2) {
      process->terminate(); setError(e, "CANCELLED", "debugger stopped", true); return false;
    }
    if (preempt == 1) process->interrupt();
    bool done = false, running = false;
    auto deadline = std::chrono::steady_clock::now() + options.commandTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (control.load(std::memory_order_relaxed) >= 2) {
        process->terminate(); setError(e, "CANCELLED", "debugger stopped", true); return false;
      }
      ProcessOutput output;
      try { output = process->poll(std::chrono::milliseconds(20)); }
      catch (const std::exception& ex) { setError(e, "INTERNAL", ex.what(), true); return false; }
      drainPty();
      lines += output.out;
      std::size_t p = 0;
      while ((p = lines.find('\n')) != std::string::npos) {
        std::string line = lines.substr(0, p);
        lines.erase(0, p + 1);
        if (processLine(std::move(line), tokenText, waitStop, done, running, stop, e)) {
          if (!e.code.empty()) return false;
          if (waitStop && (stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally"))) return true;
          if (!waitStop && done) return e.code.empty();
        }
        // Execution commands can fail before producing an asynchronous stop
        // (for example ptrace denied or an invalid executable).  Do not spin
        // until the timeout after GDB has already returned ^error.
        if (!e.code.empty()) return false;
      }
      if (waitStop && stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally")) return true;
      if (!waitStop && done) return e.code.empty();
      if (output.exit) { setError(e, "LAUNCH_FAILED", "GDB exited before command completed", true); return false; }
    }
    setError(e, "TIMEOUT", "GDB command timed out", true);
    return false;
  }

  nlohmann::json runtimeValue(std::string type, std::string text) {
    nlohmann::json out;
    auto unavailable = [&](std::string reason) {
      out = { {"availability", "unavailable"}, {"reason", std::move(reason)} };
    };
    if (text.empty() || type.empty()) { unavailable("not-captured"); return out; }
    if (text == "<optimized out>") { unavailable("optimized-out"); return out; }
    if (text == "<unavailable>" || text == "<not available>") { unavailable("read-error"); return out; }
    if (text == "<uninitialized>") { unavailable("uninitialized"); return out; }
    nlohmann::json value;
    const auto hasWord = [&](std::string_view word) {
      std::size_t at = type.find(word);
      while (at != std::string::npos) {
        const bool left = at == 0 || !(std::isalnum(static_cast<unsigned char>(type[at - 1])) || type[at - 1] == '_');
        const auto end = at + word.size();
        const bool right = end == type.size() || !(std::isalnum(static_cast<unsigned char>(type[end])) || type[end] == '_');
        if (left && right) return true;
        at = type.find(word, at + 1);
      }
      return false;
    };
    // A user-defined type named e.g. `struct int_wrapper` is not an integer
    // merely because its spelling contains "int".  Keep aggregates opaque
    // unless GDB reports a builtin arithmetic type.
    const bool userAggregate = hasWord("struct") || hasWord("class") || hasWord("union") ||
        hasWord("enum") || type.find('<') != std::string::npos || type.find('>') != std::string::npos;
    if (text == "true" || text == "false") value = { {"kind", "boolean"}, {"value", text == "true"} };
    else if (!userAggregate && type.find('*') != std::string::npos &&
             (text.rfind("0x", 0) == 0 || text.rfind("0X", 0) == 0)) {
      const auto end = text.find_first_of(" \t");
      const auto address = text.substr(0, end);
      if (!parseAddress(address)) { unavailable("read-error"); return out; }
      value = { {"kind", "pointer"}, {"addressHex", address}, {"pointeeType", type} };
    }
    else if (!userAggregate && (hasWord("float") || hasWord("double"))) {
      std::string lower = text; std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      std::string classification = lower.find("nan") != std::string::npos ? "nan" :
          lower.find("inf") != std::string::npos ? (lower.find('-') != std::string::npos ? "negative-infinity" : "positive-infinity") :
          (text == "-0" || text == "-0.0" ? "negative-zero" : "finite");
      int bits = hasWord("long double") ? 128 : hasWord("double") ? 64 : 32;
      value = { {"kind", "float"}, {"text", text}, {"bits", bits}, {"classification", classification} };
    } else if (!userAggregate && hasWord("bool")) value = { {"kind", "boolean"}, {"value", text == "true"} };
    else {
      const bool integerType = !userAggregate &&
          (hasWord("int") || hasWord("char") || hasWord("short") || hasWord("long") ||
           hasWord("size_t") || hasWord("int8_t") || hasWord("int16_t") || hasWord("int32_t") ||
           hasWord("int64_t") || hasWord("uint8_t") || hasWord("uint16_t") || hasWord("uint32_t") ||
           hasWord("uint64_t") || hasWord("__int128") || hasWord("wchar_t") ||
           hasWord("char16_t") || hasWord("char32_t"));
      if (integerType) {
        int bits = 32;
        if (hasWord("__int128") || hasWord("int128_t") || hasWord("uint128_t")) bits = 128;
        else if (hasWord("int64_t") || hasWord("uint64_t") || hasWord("long long") || hasWord("long")) bits = 64;
        else if (hasWord("int32_t") || hasWord("uint32_t")) bits = 32;
        else if (hasWord("int16_t") || hasWord("uint16_t") || hasWord("short")) bits = 16;
        else if (hasWord("int8_t") || hasWord("uint8_t") || hasWord("char")) bits = 8;
        else if (hasWord("char16_t")) bits = 16;
        else if (hasWord("wchar_t") || hasWord("char32_t")) bits = 32;
        // GDB prints character values as `97 'a'`; retain only the confirmed
        // decimal token.  Never pass hexadecimal/labels or a suffix through
        // as a decimal integer, especially for unsigned __int128.
        auto tokenEnd = text.find_first_of(" \t\r\n");
        std::string decimal = text.substr(0, tokenEnd);
        const bool negative = !decimal.empty() && decimal.front() == '-';
        const std::size_t digits = negative || (!decimal.empty() && decimal.front() == '+') ? 1 : 0;
        const bool decimalDigits = decimal.size() > digits && decimal.find_first_not_of("0123456789", digits) == std::string::npos;
        if (!decimalDigits || (type.find("unsigned") != std::string::npos && negative)) {
          unavailable("unsupported"); return out;
        }
        value = { {"kind", "integer"}, {"decimal", decimal}, {"bits", bits}, {"signed", type.find("unsigned") == std::string::npos} };
      } else if (text.size() > options.maxOutputBytes) {
        value = { {"kind", "aggregate"}, {"summary", text.substr(0, options.maxOutputBytes)}, {"elementCount", "?"} };
      } else value = { {"kind", "aggregate"}, {"summary", text} };
    }
    out = { {"availability", "available"}, {"value", std::move(value)} };
    return out;
  }

  nlohmann::json varsFrom(const MiValue* list, int level) {
    nlohmann::json vars = nlohmann::json::array();
    if (!list) return vars;
    std::vector<const MiValue*> entries;
    for (const auto& v : list->values) entries.push_back(v.get());
    for (const auto& [k, v] : list->fields) if (k.empty()) entries.push_back(v.get());
    for (const MiValue* item : entries) {
      if (!item || item->kind != mi::ValueKind::tuple) continue;
      std::string name = valText(field(*item, "name"));
      if (name.empty()) continue;
      std::string type = valText(field(*item, "type"));
      std::string text = valText(field(*item, "value"));
      std::string activation = "frame:" + std::to_string(level);
      vars.push_back({{"id", activation + ":" + name}, {"name", name}, {"type", type},
                      {"scopeId", activation}, {"activationId", activation},
                      {"locator", activation + ":" + name}, {"value", runtimeValue(type, text)},
                      {"writable", false}});
    }
    // A few GDB versions omit the tuple braces and emit a result-list such as
    // [name="x",value="1",name="y",value="2"].  Reconstruct those entries
    // by the repeated `name` key instead of silently returning an empty page.
    if (list->kind == mi::ValueKind::result_list) {
      nlohmann::json current = nlohmann::json::object();
      auto flush = [&] {
        const auto name = current.value("name", "");
        if (name.empty()) return;
        const auto type = current.value("type", "");
        const auto text = current.value("value", "");
        const std::string activation = "frame:" + std::to_string(level);
        vars.push_back({{"id", activation + ":" + name}, {"name", name}, {"type", type},
                        {"scopeId", activation}, {"activationId", activation},
                        {"locator", activation + ":" + name}, {"value", runtimeValue(type, text)},
                        {"writable", false}});
      };
      for (const auto& [key, value] : list->fields) {
        if (key == "name" && current.contains("name")) { flush(); current.clear(); }
        current[key] = valText(value.get());
      }
      flush();
    }
    return vars;
  }

  void enrichVariableTypes(nlohmann::json& variables, GdbError& outerError) {
    // -stack-list-variables intentionally omits types on current GDB.  Ask
    // GDB's typed variable-object API for each plain identifier.  We never
    // pass an arbitrary expression from the client: names originate from the
    // debugger's local-variable list, and failures remain unavailable.
    for (auto& variable : variables) {
      const auto name = variable.value("name", "");
      if (name.empty() || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != std::string::npos)
        continue;
      MiRecord created;
      GdbError local;
      if (!command("-var-create - * " + name, false, created, local)) continue;
      const auto* type = field(created.fields, "type");
      const auto* value = field(created.fields, "value");
      if (type && !type->text.empty()) {
        variable["type"] = type->text;
        variable["value"] = runtimeValue(type->text, value ? value->text : std::string{});
      }
      const auto* objectName = field(created.fields, "name");
      if (objectName && !objectName->text.empty()) {
        MiRecord deleted;
        GdbError ignored;
        (void)command("-var-delete " + objectName->text, false, deleted, ignored);
      }
    }
    (void)outerError;
  }

  bool snapshotStack(GdbStop& result, GdbError& e) {
    MiRecord frames;
    if (!command("-stack-list-frames", false, frames, e)) return false;
    const MiValue* stack = field(frames.fields, "stack");
    nlohmann::json output = nlohmann::json::array();
    if (stack) {
      for (const auto& item : stack->values) {
        const MiValue* fr = item.get();
        if (fr->kind != mi::ValueKind::tuple) continue;
        int level = 0; try { level = std::stoi(valText(field(*fr, "level"))); } catch (...) {}
        std::string function = valText(field(*fr, "func"));
        if (function.empty()) function = "<unknown>";
        nlohmann::json loc = nullptr;
        std::string full = valText(field(*fr, "fullname"));
        std::string line = valText(field(*fr, "line"));
        if (!full.empty() && !line.empty()) {
          int ln = 0; try { ln = std::stoi(line); } catch (...) {}
          loc = sourceLocation(full, ln);
        }
        MiRecord vr;
        nlohmann::json variables = nlohmann::json::array();
        if (level == selectedFrame) {
          if (!command("-stack-list-variables --all-values", false, vr, e)) return false;
          variables = varsFrom(field(vr.fields, "variables"), level);
          enrichVariableTypes(variables, e);
        }
        auto activation = "frame:" + std::to_string(level);
        output.push_back({{"id", activation}, {"activationId", activation}, {"functionName", function},
                          {"location", loc}, {"variables", std::move(variables)}});
      }
      // GDB encodes a stack as a result-list (`frame={...},frame={...}`),
      // while some versions use a value-list. Preserve both forms and their
      // repeated frame keys.
      for (const auto& [key, item] : stack->fields) {
        if (key != "frame" || !item || item->kind != mi::ValueKind::tuple) continue;
        const MiValue* fr = item.get();
        int level = 0; try { level = std::stoi(valText(field(*fr, "level"))); } catch (...) {}
        std::string function = valText(field(*fr, "func")); if (function.empty()) function = "<unknown>";
        auto activation = "frame:" + std::to_string(level);
        nlohmann::json variables = nlohmann::json::array();
        if (level == selectedFrame) {
          MiRecord vr;
          if (!command("-stack-list-variables --all-values", false, vr, e)) return false;
          variables = varsFrom(field(vr.fields, "variables"), level);
          enrichVariableTypes(variables, e);
        }
        int sourceLine = 0;
        try { sourceLine = std::stoi(valText(field(*fr, "line"))); } catch (...) {}
        const auto location = sourceLocation(valText(field(*fr, "fullname")), sourceLine);
        output.push_back({{"id", activation}, {"activationId", activation}, {"functionName", function},
                          {"location", location},
                           {"variables", std::move(variables)}});
      }
    }
    lastStack = output;
    result.stack = std::move(output);
    return true;
  }

  bool makeStop(const MiRecord& stop, GdbStop& result, GdbError& e) {
    result = GdbStop{};
    result.stopped = stop.klass == "stopped";
    result.reason = valText(field(stop.fields, "reason"));
    result.exited = stop.klass == "exited" || stop.klass == "exited-normally" ||
                    result.reason == "exited-normally" || result.reason == "exited" ||
                    result.reason == "exited-signalled";
    result.threadId = valText(field(stop.fields, "thread-id"));
    if (const auto code = field(stop.fields, "exit-code")) {
      try { result.exitCode = static_cast<int>(std::stoul(code->text, nullptr, 0)); } catch (...) {}
    }
    if (const auto sig = field(stop.fields, "signal-name")) {
      // Keep the symbolic signal separately; a numeric signal is only
      // available on some GDB targets and must not be guessed from its name.
      result.signalName = sig->text;
    }
    if (const MiValue* fr = field(stop.fields, "frame")) {
      std::string full = valText(field(*fr, "fullname"));
      std::string line = valText(field(*fr, "line"));
      if (!full.empty() && !line.empty()) {
        int ln = 0; try { ln = std::stoi(line); } catch (...) {}
        result.location = sourceLocation(full, ln);
      }
    }
    // Once the inferior has exited, stack/variables are no longer a valid
    // query.  The exit record itself is the complete observation; asking GDB
    // for a stack here can yield a misleading stale frame or a secondary
    // READ_FAILED error.
    if (!result.exited && !snapshotStack(result, e)) return false;
    drainPty();
    result.stdoutSnapshot = {{"text", ptyOutput}, {"totalBytes", ptyTotalBytes},
                             {"retainedFromByte", ptyTotalBytes > ptyOutput.size() ? ptyTotalBytes - ptyOutput.size() : 0},
                             {"truncated", ptyTotalBytes > ptyOutput.size()}};
    result.stderrSnapshot = {{"text", ""}, {"totalBytes", 0}, {"retainedFromByte", 0}, {"truncated", false}};
    result.input = {{"tracking", "transport-only"}, {"deliveredBytes", deliveredInputBytes.load()}};
    result.raw = {{"reason", result.reason}, {"stack", result.stack}, {"location", result.location}};
    result.raw["exited"] = result.exited;
    if (result.exitCode) result.raw["exitCode"] = *result.exitCode;
    return true;
  }

  bool startGdb(const GdbLaunchRequest& request, GdbError& e) {
    std::vector<std::string> argv{options.gdbPath, "--interpreter=mi2", "-nx", "--quiet"};
    ProcessOptions po;
    po.argv = argv;
    po.cwd = options.workingDirectory.empty() ? request.binaryPath.parent_path().string() : options.workingDirectory.string();
    // The requested environment belongs to the inferior. Passing it to the
    // debugger itself makes PATH or LD_PRELOAD alter GDB's lookup/loading
    // behavior instead of only configuring the debugged program.
    po.max_output_bytes = options.maxOutputBytes;
    try { process = std::make_unique<Process>(Process::spawn(po)); }
    catch (const std::exception& ex) { setError(e, "LAUNCH_FAILED", ex.what()); return false; }
    live = true;
    auto setup = [&](std::string_view c) { MiRecord ignored; return command(c, false, ignored, e); };
    if (!setup("-gdb-set pagination off") || !setup("-gdb-set confirm off") ||
        !setup("-gdb-set startup-with-shell on") || !setup("-gdb-set print pretty off") ||
        !setup("-gdb-set print elements 128") ||
        !setup("-interpreter-exec console " + miQuote("set inferior-tty " + ptyPath.string()))) return false;
    for (const auto& [name, value] : request.environment) {
      // MI quoting preserves spaces, quotes and embedded newlines in the
      // console command. The validated POSIX name cannot introduce a second
      // `set environment` directive.
      if (!setup("-interpreter-exec console " + miQuote("set environment " + name + " " + value))) return false;
    }
    std::string file = "-file-exec-and-symbols " + miQuote(request.binaryPath.string());
    if (!setup(file)) return false;
    std::string args = "-exec-arguments";
    for (const auto& arg : request.argv) args += " " + shellQuote(arg);
    if (request.argv.size() && !setup(args)) return false;
    return true;
  }
};

GdbEngine::GdbEngine(GdbOptions options) : impl_(std::make_unique<Impl>(std::move(options))) {}
GdbEngine::~GdbEngine() { stop(); }

bool GdbEngine::launch(const GdbLaunchRequest& request, GdbStop& result, GdbError& error) {
  stop();
  for (const auto& argument : request.argv) {
    if (!safeMiArgument(argument)) {
      error = {"INVALID_REQUEST", "inferior arguments must not contain NUL or line breaks", false};
      return false;
    }
  }
  for (const auto& [name, value] : request.environment) {
    if (!validEnvironmentName(name) || value.find('\0') != std::string::npos) {
      error = {"INVALID_REQUEST", "invalid inferior environment entry", false};
      return false;
    }
  }
  impl_->control.store(0);
  impl_->inferiorPid.clear();
  impl_->sourceBundle = request.sourceBundle;
  if (!impl_->prepareTemp(request.input, error)) return false;
  if (!impl_->startGdb(request, error)) { stop(); return false; }
  if (request.stopAtEntry) {
    MiRecord entryBreakpoint;
    if (!impl_->command("-break-insert -t -f main", false, entryBreakpoint, error)) { stop(); return false; }
  }
  impl_->startInputFeeder(request.input);
  MiRecord stopped;
  if (!impl_->command("-exec-run", true, stopped, error)) { stop(); return false; }
  if (!impl_->makeStop(stopped, result, error)) { stop(); return false; }
  result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  return true;
}

bool GdbEngine::resume(std::string_view stepKind, GdbStop& result, GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live inferior", false}; return false; }
  const int preempt = impl_->control.exchange(0);
  std::string cmd;
  if (stepKind == "over") cmd = "-exec-next";
  else if (stepKind == "into") cmd = "-exec-step";
  else if (stepKind == "out") cmd = "-exec-finish";
  else if (stepKind == "instruction") cmd = "-exec-step-instruction";
  else if (stepKind == "continue") cmd = "-exec-continue";
  else { error = {"UNSUPPORTED", "unknown execution command", false}; return false; }
  MiRecord stopped;
  if (!impl_->command(cmd, true, stopped, error, preempt)) return false;
  if (!impl_->makeStop(stopped, result, error)) return false;
  if (impl_->process) result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  return true;
}

bool GdbEngine::pause(GdbStop& result, GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live inferior", false}; return false; }
  const int preempt = impl_->control.exchange(0);
  MiRecord stopped;
  if (!impl_->command("-exec-interrupt --all", true, stopped, error, preempt)) return false;
  if (!impl_->makeStop(stopped, result, error)) return false;
  if (impl_->process) result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  return true;
}

void GdbEngine::interrupt(int mode) noexcept {
  if (!impl_) return;
  int expected = impl_->control.load();
  while (expected < mode && !impl_->control.compare_exchange_weak(expected, mode)) {}
  std::lock_guard lock(impl_->processMutex);
  if (impl_->process) {
    if (mode >= 2) impl_->process->terminate();
    else impl_->process->interrupt();
  }
}
void GdbEngine::stop() noexcept {
  if (!impl_) return;
  impl_->control.store(2);
  std::lock_guard lock(impl_->processMutex);
  if (impl_->process) impl_->process->terminate();
  impl_->process.reset();
  impl_->live = false;
  impl_->breakpoints.clear();
  impl_->cleanupTemp();
}
bool GdbEngine::live() const noexcept { return impl_ && impl_->live.load(); }
std::optional<int> GdbEngine::gdbPid() const noexcept {
  std::lock_guard lock(impl_->processMutex);
  return impl_->process ? std::optional<int>(impl_->process->pid()) : std::nullopt;
}

bool GdbEngine::setBreakpoints(const nlohmann::json& request, nlohmann::json& result,
                               GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live debugger", false}; return false; }
  const std::string documentId = request.value("documentId", "");
  // A document-scoped replacement must leave breakpoints belonging to other
  // source documents intact.  The old global delete made an editor update in
  // helper.cpp silently remove all main.cpp breakpoints as well.
  std::vector<Impl::BreakpointEntry> retained;
  for (const auto& entry : impl_->breakpoints) {
    if (entry.documentId != documentId) { retained.push_back(entry); continue; }
    MiRecord ignored; GdbError ignoredError;
    (void)impl_->command("-break-delete " + entry.number, false, ignored, ignoredError);
  }
  impl_->breakpoints = std::move(retained);
  result = nlohmann::json::array();
  for (const auto& bp : request.value("breakpoints", nlohmann::json::array())) {
    nlohmann::json item = bp;
    bool enabled = bp.value("enabled", true);
    if (bp.contains("condition") || bp.contains("hitCount")) {
      if ((bp.contains("condition") && !bp["condition"].get<std::string>().empty()) || bp.contains("hitCount")) {
        item["verified"] = false; item["message"] = "conditional and hit-count breakpoints are unsupported"; result.push_back(item); continue;
      }
    }
    if (!enabled) { item["verified"] = false; item["message"] = "disabled"; result.push_back(item); continue; }
    int line = 0; try { line = bp.at("range").at("start").at("line").get<int>(); } catch (...) {}
    std::string doc = bp.value("documentId", request.value("documentId", ""));
    std::filesystem::path path;
    for (const auto& d : impl_->sourceBundle.documents) if (d.documentId == doc) path = d.path;
    if (path.empty() || line <= 0) { item["verified"] = false; item["message"] = "source document or line unavailable"; result.push_back(item); continue; }
    MiRecord rec;
    if (!impl_->command("-break-insert -f " + miQuote(path.string() + ":" + std::to_string(line)), false, rec, error)) return false;
    const MiValue* bkpt = field(rec.fields, "bkpt");
    std::string number = valText(bkpt ? field(*bkpt, "number") : nullptr);
    if (number.empty()) { item["verified"] = false; item["message"] = "GDB did not resolve breakpoint"; }
    else { impl_->breakpoints.push_back({documentId, number}); item["verified"] = true; item["resolvedRange"] = bp.value("range", nlohmann::json::object()); }
    result.push_back(item);
  }
  return true;
}

bool GdbEngine::readVariables(std::string_view reference, std::size_t start,
                              std::size_t count, nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live debugger", false}; return false; }
  if (count > impl_->options.maxVariablesPerPage) count = impl_->options.maxVariablesPerPage;
  int level = 0;
  std::string ref(reference);
  if (ref.rfind("frame:", 0) == 0) try { level = std::stoi(ref.substr(6)); } catch (...) {}
  impl_->selectedFrame = level;
  MiRecord ignored;
  if (!impl_->command("-stack-select-frame " + std::to_string(level), false, ignored, error)) return false;
  GdbStop snapshot;
  if (!impl_->snapshotStack(snapshot, error)) return false;
  for (const auto& frame : snapshot.stack) if (frame.value("id", "") == ref) {
    const auto& vars = frame["variables"];
    result = nlohmann::json::object(); result["variables"] = nlohmann::json::array();
    for (std::size_t i = start; i < vars.size() && i < start + count; ++i) result["variables"].push_back(vars[i]);
    result["hasMore"] = start + count < vars.size();
    return true;
  }
  result = {{"variables", nlohmann::json::array()}, {"hasMore", false}};
  return true;
}

bool GdbEngine::readMemory(std::string_view addressHex, std::size_t byteCount,
                           nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live debugger", false}; return false; }
  if (byteCount > impl_->options.maxMemoryReadBytes) { error = {"LIMIT_EXCEEDED", "memory request exceeds configured limit", false}; return false; }
  if (!parseAddress(addressHex)) { error = {"INVALID_REQUEST", "invalid memory address", false}; return false; }
  MiRecord rec;
  if (!impl_->command("-data-read-memory-bytes " + std::string(addressHex) + " " + std::to_string(byteCount), false, rec, error)) return false;
  std::string bytes;
  if (const MiValue* memory = field(rec.fields, "memory")) {
    auto appendCell = [&](const MiValue* cell) {
      if (!cell) return true;
      return appendHexBytes(valText(field(*cell, "contents")), bytes);
    };
    if (!memory->values.empty()) {
      for (const auto& cell : memory->values) if (!appendCell(cell.get())) {
        error = {"READ_FAILED", "GDB returned malformed memory bytes", true}; return false;
      }
    } else {
      for (const auto& [key, cell] : memory->fields) if (!appendCell(cell.get())) {
        error = {"READ_FAILED", "GDB returned malformed memory bytes", true}; return false;
      }
    }
  }
  if (bytes.size() > byteCount) bytes.resize(byteCount);
  result = {{"addressHex", std::string(addressHex)}, {"bytesBase64", base64(bytes)},
            {"unreadableBytes", byteCount > bytes.size() ? byteCount - bytes.size() : 0}};
  return true;
}

bool GdbEngine::disassemble(std::string_view addressHex, std::size_t maxInstructions,
                            nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"INVALID_REQUEST", "no live debugger", false}; return false; }
  if (maxInstructions == 0 || maxInstructions > impl_->options.maxInstructions) maxInstructions = impl_->options.maxInstructions;
  auto address = parseAddress(addressHex);
  if (!address) { error = {"INVALID_REQUEST", "invalid disassembly address", false}; return false; }
  // x86 instructions are variable length; 32 bytes per requested instruction
  // is a safe bounded window. GDB returns fewer records at unmapped memory.
  const std::uint64_t window = std::min<std::uint64_t>(0x10000, maxInstructions * 32ull);
  if (*address > std::numeric_limits<std::uint64_t>::max() - window) {
    error = {"INVALID_REQUEST", "disassembly address range overflows", false};
    return false;
  }
  const std::uint64_t end = *address + window;
  MiRecord rec;
  if (!impl_->command("-data-disassemble -s " + std::string(addressHex) + " -e 0x" + [&] { std::ostringstream o; o << std::hex << end; return o.str(); }() + " -- 0", false, rec, error)) return false;
  nlohmann::json instructions = nlohmann::json::array();
  if (const MiValue* list = field(rec.fields, "asm_insns")) {
    for (const auto& insn : list->values) {
      auto addr = valText(field(*insn, "address"));
      instructions.push_back({{"addressHex", addr}, {"bytesHex", valText(field(*insn, "opcodes"))},
                              {"text", valText(field(*insn, "inst"))}, {"current", addr == addressHex}});
      if (instructions.size() >= maxInstructions) break;
    }
    for (const auto& [key, insn] : list->fields) {
      if (!insn) continue;
      auto addr = valText(field(*insn, "address"));
      instructions.push_back({{"addressHex", addr}, {"bytesHex", valText(field(*insn, "opcodes"))},
                              {"text", valText(field(*insn, "inst"))}, {"current", addr == addressHex}});
      if (instructions.size() >= maxInstructions) break;
    }
  }
  result = {{"instructions", std::move(instructions)}, {"truncated", false}};
  return true;
}

bool GdbEngine::writeVariable(std::string_view, const nlohmann::json&,
                              nlohmann::json&, GdbError& error) {
  error = {"UNSUPPORTED", "writing variables is disabled: evaluating a C++ assignment can execute user code", false};
  return false;
}

}  // namespace phantom
