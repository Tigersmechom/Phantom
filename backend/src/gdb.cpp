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
#include <csignal>
#include <fstream>
#include <pthread.h>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <poll.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

// OutputSnapshotDTO carries Unicode text, while the inferior may write any
// bytes. Keep byte counters in the raw domain and replace malformed UTF-8
// deterministically (including a codepoint cut by the retained tail boundary).
std::string displayUtf8(std::string_view bytes) {
  std::string text;
  text.reserve(bytes.size());
  for (std::size_t i = 0; i < bytes.size();) {
    const auto c = static_cast<unsigned char>(bytes[i]);
    const std::size_t width = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 :
        c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    bool valid = width != 0 && width <= bytes.size() - i;
    for (std::size_t n = 1; valid && n < width; ++n) {
      const auto next = static_cast<unsigned char>(bytes[i + n]);
      valid = next >= 0x80 && next <= 0xbf;
      if (n == 1 && ((c == 0xe0 && next < 0xa0) || (c == 0xed && next >= 0xa0) ||
                    (c == 0xf0 && next < 0x90) || (c == 0xf4 && next >= 0x90))) valid = false;
    }
    if (valid) { text.append(bytes.substr(i, width)); i += width; }
    else { text += "\xef\xbf\xbd"; ++i; }
  }
  return text;
}

// Input range offsets in the protocol are UTF-16 code-unit offsets, while
// the pipe cursor is necessarily counted in bytes.  The native profile only
// exposes the transport boundary (`deliveredBytes`), but converting that
// boundary here keeps `exposedRanges` valid for non-ASCII drafts as well.
std::size_t utf16Length(std::string_view text, std::size_t bytes) {
  bytes = std::min(bytes, text.size());
  std::size_t units = 0;
  for (std::size_t at = 0; at < bytes;) {
    const auto c = static_cast<unsigned char>(text[at]);
    const std::size_t width = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 :
        c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 1;
    // Input is validated as UTF-8 at the protocol boundary. A pipe write can
    // nevertheless stop in the middle of a multibyte sequence; do not expose
    // a UTF-16 range that would split a code point.
    if (width > bytes - at) break;
    units += width == 4 ? 2 : 1;
    at += width;
  }
  return units;
}

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

std::optional<std::uint64_t> parseUnsigned(std::string_view s) {
  if (s.empty()) return std::nullopt;
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    base = 16;
    s.remove_prefix(2);
  }
  if (s.empty()) return std::nullopt;
  std::uint64_t value = 0;
  const auto parsed = std::from_chars(s.data(), s.data() + s.size(), value, base);
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
  std::stop_token launchCancellation;
  int inferiorPidFd = -1;
  std::uint64_t nextToken = 1;
  std::string lines;
  std::filesystem::path tempDir;
  int ptyMaster = -1;
  int ptySlave = -1;
  std::filesystem::path ptyPath;
  std::filesystem::path stdinFifo;
  std::filesystem::path stdoutFifo;
  std::filesystem::path stderrFifo;
  std::filesystem::path readyFifo;
  int stdinFd = -1;
  int stdinKeepFd = -1;
  int stdoutFd = -1;
  int stderrFd = -1;
  int readyFd = -1;
  int stdoutKeepFd = -1;
  int stderrKeepFd = -1;
  std::string stdoutOutput;
  std::string stderrOutput;
  std::size_t stdoutTotalBytes = 0;
  std::size_t stderrTotalBytes = 0;
  mutable std::mutex inputMutex;
  std::size_t deliveredInputBytes = 0;
  std::string pendingInput;
  std::string inputId;
  std::string inputRevisionId;
  std::string inputParentRevisionId;
  std::map<std::string, std::string> inputChunks;
  bool submittedInputClosed = true;
  bool closeInputAfterWrite = true;
  bool wrapperReady = false;
  GdbSourceBundle sourceBundle;
  std::string inferiorPid;
  struct BreakpointEntry { std::string documentId; std::string number; };
  std::vector<BreakpointEntry> breakpoints;
  int selectedFrame = 0;
  nlohmann::json lastStack = nlohmann::json::array();
  // When input blocks, the selected source frame is a caller of the native
  // input operation. Finish its immediate callee to return to that precise
  // activation; line+1 guesses can skip control flow or target no code.
  bool inputWaitActive = false;
  int inputWaitFrame = -1;
  nlohmann::json inputWaitLocation = nullptr;

  static bool isInputRuntimeFrame(std::string_view function) {
    return function.find("__GI___libc_read") != std::string_view::npos ||
           function.find("__libc_read") != std::string_view::npos ||
           function.find("_IO_new_file_underflow") != std::string_view::npos ||
           function.find("_IO_default_uflow") != std::string_view::npos ||
           function.find("stdio_sync_filebuf") != std::string_view::npos ||
           function.find("basic_istream") != std::string_view::npos ||
           function.find("_M_extract") != std::string_view::npos;
  }

  // Linux exposes blocked syscalls without running code in the inferior.
  // Verify the descriptor's inode against our actual FIFO: a read from a
  // socket/file (or a user function named getline) is not an input wait.
  bool isInputDescriptor(std::uint64_t fd) const {
    if (inferiorPid.empty() || fd > std::numeric_limits<int>::max()) return false;
    std::lock_guard inputLock(inputMutex);
    if (stdinFd < 0 || closeInputAfterWrite) return false;
    struct stat actual{}, expected{};
    const auto path = "/proc/" + inferiorPid + "/fd/" + std::to_string(fd);
    return ::stat(path.c_str(), &actual) == 0 && ::fstat(stdinFd, &expected) == 0 &&
        S_ISFIFO(actual.st_mode) && actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
  }

  bool inputReadInProgress() const {
    if (inferiorPid.empty()) return false;
    std::ifstream syscall("/proc/" + inferiorPid + "/syscall");
    long number = -1;
    std::string descriptor;
    if (!(syscall >> number >> descriptor) || number != SYS_read) return false;
    const auto fd = parseUnsigned(descriptor);
    return fd && isInputDescriptor(*fd);
  }

  bool interruptedInputRead() {
    // At the interrupt stop, verify Linux's restartable read registers again.
    // This rejects the race where data arrived or a breakpoint was hit after
    // the /proc sample. This adapter advertises x86_64 only.
    MiRecord record;
    GdbError ignored;
    if (!command("-stack-select-frame 0", false, record, ignored)) return false;
    if (!command("-data-evaluate-expression \"(long)$orig_rax\"", false, record, ignored) ||
        valText(field(record.fields, "value")) != std::to_string(SYS_read)) return false;
    if (!command("-data-evaluate-expression \"(long)$rax\"", false, record, ignored)) return false;
    const auto result = valText(field(record.fields, "value"));
    if (result != "-512" && result != "-513" && result != "-514" && result != "-516") return false;
    if (!command("-data-evaluate-expression \"(unsigned long)$rdi\"", false, record, ignored)) return false;
    const auto fd = parseUnsigned(valText(field(record.fields, "value")));
    return fd && isInputDescriptor(*fd);
  }

  void setError(GdbError& e, std::string code, std::string msg, bool retry = false) {
    e = GdbError{std::move(code), std::move(msg), retry};
  }
  void failClosed(GdbError& e, std::string code, std::string message, bool retry = true) {
    std::lock_guard lock(processMutex);
    if (process) process->terminate();
    process.reset();
    killInferior();
    live = false;
    breakpoints.clear();
    cleanupTemp();
    setError(e, std::move(code), std::move(message), retry);
  }
  void killInferior() noexcept {
    // A pidfd refers to this exact child even if its numeric PID is reused.
    // GDB normally kills it on exit; this covers abrupt debugger death too.
    if (inferiorPidFd >= 0) {
      (void)::syscall(SYS_pidfd_send_signal, inferiorPidFd, SIGKILL, nullptr, 0);
      (void)::close(inferiorPidFd); inferiorPidFd = -1;
    }
  }
  bool prepareTemp(const GdbLaunchRequest& request, GdbError& e) {
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
    // Only startup diagnostics use this PTY. The wrapper replaces fd 0/1/2
    // with pipes before exec; terminal line discipline never touches input.
    const int flags = ::fcntl(ptyMaster, F_GETFL);
    if (flags < 0 || ::fcntl(ptyMaster, F_SETFL, flags | O_NONBLOCK) < 0) {
      setError(e, "LAUNCH_FAILED", "cannot configure startup PTY"); cleanupTemp(); return false;
    }
    std::ofstream environment(tempDir / "environment", std::ios::binary);
    for (const auto& [name, value] : request.environment) {
      environment << name << '=' << value;
      environment.put('\0');
    }
    environment.close();
    if (!environment) { setError(e, "LAUNCH_FAILED", "cannot save target environment"); cleanupTemp(); return false; }
    stdinFifo = tempDir / "stdin";
    stdoutFifo = tempDir / "stdout";
    stderrFifo = tempDir / "stderr";
    readyFifo = tempDir / "ready";
    if (::mkfifo(stdinFifo.c_str(), 0600) != 0 ||
        ::mkfifo(stdoutFifo.c_str(), 0600) != 0 ||
        ::mkfifo(stderrFifo.c_str(), 0600) != 0 ||
        ::mkfifo(readyFifo.c_str(), 0600) != 0) {
      setError(e, "LAUNCH_FAILED", "cannot create inferior I/O pipes");
      cleanupTemp();
      return false;
    }
    // Keep the FIFO endpoints open across the wrapper's startup. Separate
    // read and keepalive descriptors let us close the latter after exit and
    // observe a genuine EOF while retaining every buffered byte.
    stdinKeepFd = ::open(stdinFifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    stdinFd = ::open(stdinFifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    stdoutFd = ::open(stdoutFifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    stderrFd = ::open(stderrFifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    readyFd = ::open(readyFifo.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    stdoutKeepFd = ::open(stdoutFifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    stderrKeepFd = ::open(stderrFifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (stdinKeepFd < 0 || stdinFd < 0 || stdoutFd < 0 || stderrFd < 0 || readyFd < 0 || stdoutKeepFd < 0 || stderrKeepFd < 0) {
      setError(e, "LAUNCH_FAILED", "cannot open inferior I/O pipes");
      cleanupTemp();
      return false;
    }
    stdoutOutput.clear(); stderrOutput.clear();
    stdoutTotalBytes = 0; stderrTotalBytes = 0; deliveredInputBytes = 0;
    pendingInput = request.input; inputId = request.inputId;
    inputRevisionId = request.inputId; inputParentRevisionId.clear();
    inputChunks.clear();
    inputChunks.emplace(inputId, request.input);
    submittedInputClosed = request.closeInputAfterWrite;
    closeInputAfterWrite = request.closeInputAfterWrite;
    wrapperReady = false;
    return true;
  }
  void cleanupTemp() noexcept {
    std::lock_guard inputLock(inputMutex);
    if (stdinKeepFd >= 0) { (void)::close(stdinKeepFd); stdinKeepFd = -1; }
    if (stdinFd >= 0) { (void)::close(stdinFd); stdinFd = -1; }
    if (readyFd >= 0) { (void)::close(readyFd); readyFd = -1; }
    if (stdoutKeepFd >= 0) { (void)::close(stdoutKeepFd); stdoutKeepFd = -1; }
    if (stderrKeepFd >= 0) { (void)::close(stderrKeepFd); stderrKeepFd = -1; }
    if (stdoutFd >= 0) { (void)::close(stdoutFd); stdoutFd = -1; }
    if (stderrFd >= 0) { (void)::close(stderrFd); stderrFd = -1; }
    if (ptySlave >= 0) { (void)::close(ptySlave); ptySlave = -1; }
    if (ptyMaster >= 0) { (void)::close(ptyMaster); ptyMaster = -1; }
    ptyPath.clear(); stdinFifo.clear(); stdoutFifo.clear(); stderrFifo.clear(); readyFifo.clear();
    stdoutOutput.clear(); stderrOutput.clear();
    stdoutTotalBytes = 0; stderrTotalBytes = 0; deliveredInputBytes = 0;
    pendingInput.clear(); inputId.clear(); inputChunks.clear();
    inputRevisionId.clear(); inputParentRevisionId.clear();
    submittedInputClosed = true; closeInputAfterWrite = true; wrapperReady = false;
    if (!tempDir.empty()) { std::error_code ec; std::filesystem::remove_all(tempDir, ec); }
    tempDir.clear();
  }

  void drainFd(int fd, std::string& output, std::size_t& total,
               std::size_t budget = 64 * 1024) {
    if (fd < 0) return;
    std::array<char, 8192> buffer{};
    // A program may write forever. Bound work per pump so stdout cannot
    // starve stderr, MI replies, deadlines or cancellation.
    while (budget != 0) {
      const auto n = ::read(fd, buffer.data(), std::min(buffer.size(), budget));
      if (n > 0) {
        const auto count = static_cast<std::size_t>(n);
        budget -= count; total += count;
        output.append(buffer.data(), count);
        if (output.size() > options.maxOutputBytes)
          output.erase(0, output.size() - options.maxOutputBytes);
      } else if (n < 0 && errno == EINTR) continue;
      else break;
    }
  }

  void feedInputLocked() {
    if (!wrapperReady && readyFd >= 0) {
      char marker = 0;
      if (::read(readyFd, &marker, 1) == 1 && marker == 1) {
        wrapperReady = true;
        (void)::close(readyFd); readyFd = -1;
        // Remove our bootstrap reader now: early close(0) in the target must
        // produce EPIPE rather than leave a writer waiting on its own reader.
        (void)::close(stdinKeepFd); stdinKeepFd = -1;
      }
    }
    if (!wrapperReady || stdinFd < 0) return;
    // Once the wrapper's bootstrap reader is gone, HUP/ERR means the
    // inferior closed fd 0. Mark the transport closed even when there are no
    // pending bytes to write; otherwise an interactive Continue could wait
    // forever for an EOF that the target can no longer observe.
    pollfd stdinStatus{stdinFd, POLLOUT | POLLERR | POLLHUP, 0};
    if (::poll(&stdinStatus, 1, 0) > 0 && (stdinStatus.revents & (POLLERR | POLLHUP))) {
      (void)::close(stdinFd); stdinFd = -1;
      return;
    }
    if (deliveredInputBytes < pendingInput.size()) {
      sigset_t blocked{}, previous{}, pending{};
      ::sigemptyset(&blocked); ::sigaddset(&blocked, SIGPIPE);
      if (::pthread_sigmask(SIG_BLOCK, &blocked, &previous) != 0)
        throw std::runtime_error("cannot block SIGPIPE for inferior stdin");
      (void)::sigpending(&pending);
      const auto n = ::write(stdinFd, pendingInput.data() + deliveredInputBytes,
                             std::min<std::size_t>(64 * 1024, pendingInput.size() - deliveredInputBytes));
      const int writeError = errno;
      if (n < 0 && writeError == EPIPE && !::sigismember(&pending, SIGPIPE)) {
        timespec zero{}; (void)::sigtimedwait(&blocked, nullptr, &zero);
      }
      (void)::pthread_sigmask(SIG_SETMASK, &previous, nullptr);
      if (n > 0) deliveredInputBytes += static_cast<std::size_t>(n);
      else if (n < 0 && writeError != EINTR && writeError != EAGAIN && writeError != EWOULDBLOCK) {
        (void)::close(stdinFd); stdinFd = -1;
        if (writeError != EPIPE) throw std::runtime_error("cannot write inferior stdin");
      }
    }
    if (stdinFd >= 0 && closeInputAfterWrite && deliveredInputBytes == pendingInput.size()) {
      (void)::close(stdinFd); stdinFd = -1;
    }
  }

  void feedInput() {
    std::lock_guard inputLock(inputMutex);
    feedInputLocked();
  }

  nlohmann::json inputSnapshotLocked() const {
    const auto submitted = inputChunks.find(inputId);
    const auto exposedUnits = utf16Length(pendingInput, deliveredInputBytes);
    nlohmann::json exposed = nlohmann::json::array();
    if (exposedUnits != 0) exposed.push_back({{"start", 0}, {"end", exposedUnits}});
    const auto eof = closeInputAfterWrite ? "requested" : "open";
    const auto status = stdinFd < 0 ? "complete" :
        deliveredInputBytes < pendingInput.size() ? "reading" : "idle";
    nlohmann::json snapshot = {
        {"submitted", {{"id", inputId},
                        {"text", submitted == inputChunks.end() ? std::string{} : submitted->second},
                        {"encoding", "utf-8"}, {"closeAfterWrite", submittedInputClosed}}},
        {"revision", {{"id", inputRevisionId.empty() ? inputId : inputRevisionId},
                       {"parentId", inputParentRevisionId.empty() ? nlohmann::json(nullptr) : nlohmann::json(inputParentRevisionId)},
                       {"text", pendingInput}}},
        {"exposedRanges", std::move(exposed)}, {"status", status}, {"eof", eof},
        {"tracking", "transport-only"}, {"deliveredBytes", deliveredInputBytes},
        {"trace", nullptr}, {"stream", nullptr}};
    // Exact extraction and the currently requested range are semantic facts.
    // Native GDB cannot prove either one, so omitting them is preferable to a
    // misleading null range (and keeps the DTO distinguishable from an empty
    // confirmed range).
    return snapshot;
  }

  bool inputRemainsOpen() const {
    std::lock_guard inputLock(inputMutex);
    return stdinFd >= 0 && !closeInputAfterWrite;
  }

  void drainIo() {
    drainFd(stdoutFd, stdoutOutput, stdoutTotalBytes);
    drainFd(stderrFd, stderrOutput, stderrTotalBytes);
    // Discard startup chatter before wrapper exec (kept separate from target
    // stdout/stderr); otherwise a noisy shell could fill its controlling tty.
    std::string startup;
    std::size_t ignored = 0;
    drainFd(ptyMaster, startup, ignored);
    feedInput();
  }

  // glibc keeps bytes written through the C stdout stream (and through a
  // synchronised std::cout) in stdout's _IO_FILE write window until a flush.
  // GDB can inspect that window while the inferior is stopped. This is
  // deliberately an optional probe: the layout is not a C++ or POSIX
  // contract, and sync_with_stdio(false) means that std::cout may no longer
  // use this C stream. Therefore the public snapshot identifies itself as
  // glibc stdout and never claims that the bytes definitely came from cout.
  nlohmann::json captureBufferedStdout() {
    const auto unavailable = [](std::string reason) {
      return nlohmann::json{{"available", false}, {"reason", std::move(reason)}};
    };
    if (!process || !live) return unavailable("no-live-inferior");
    const auto evaluate = [&](std::string_view expression, std::string& value) {
      MiRecord record;
      GdbError error;
      if (!command("-data-evaluate-expression " + miQuote(expression), false, record, error)) return false;
      const auto* result = field(record.fields, "value");
      if (!result || result->text.empty()) return false;
      value = result->text;
      return true;
    };
    std::string identity;
    if (!evaluate("(int)((unsigned long)::stdout == (unsigned long)&'_IO_2_1_stdout_')", identity) || identity != "1")
      return unavailable("stdout-runtime-unavailable");
    // Name the known libc object directly: a user local named stdout must
    // not redirect this probe into arbitrary user storage. GDB casts and
    // memory reads never call functions in the stopped inferior.
    const auto member = [&](std::string_view name) -> std::optional<std::uint64_t> {
      std::string text;
      if (!evaluate("(unsigned long)((struct _IO_FILE*)&'_IO_2_1_stdout_')->" + std::string(name), text))
        return std::nullopt;
      return parseUnsigned(text);
    };
    const auto flags = member("_flags");
    const auto descriptor = member("_fileno");
    std::string narrow;
    if (!flags || ((*flags & 0xffff0000u) != 0xfbad0000u) || !descriptor || *descriptor != STDOUT_FILENO ||
        !evaluate("(int)(((struct _IO_FILE*)&'_IO_2_1_stdout_')->_mode <= 0)", narrow) || narrow != "1")
      return unavailable("stdout-layout-unsupported");
    const auto base = member("_IO_write_base");
    const auto pointer = member("_IO_write_ptr");
    const auto writeEnd = member("_IO_write_end");
    const auto bufferBase = member("_IO_buf_base");
    const auto bufferEnd = member("_IO_buf_end");
    if (!base || !pointer || !writeEnd || !bufferBase || !bufferEnd || *pointer < *base || *writeEnd < *base ||
        *bufferEnd < *bufferBase ||
        (*bufferBase == 0 && (*base != 0 || *pointer != 0 || *writeEnd != 0 || *bufferEnd != 0)) ||
        (*bufferBase != 0 && (*base < *bufferBase || *base > *bufferEnd || *writeEnd > *bufferEnd ||
                              *pointer > *bufferEnd)))
      return unavailable("stdout-buffer-range-unavailable");
    const auto count = *pointer - *base;
    // _IO_UNBUFFERED and _IO_LINE_BUF are private glibc constants. Keep the
    // values local to this ABI-specific probe instead of exporting them as a
    // general C++ stream contract.
    const bool unbuffered = (*flags & 0x0002u) != 0;
    const bool lineBuffered = (*flags & 0x0200u) != 0;
    const std::string mode = unbuffered ? "unbuffered" :
        lineBuffered ? "line" : "full";
    std::optional<std::uint64_t> capacity;
    std::optional<std::uint64_t> remaining;
    if (!unbuffered && !lineBuffered && *bufferBase != 0) {
      // _IO_buf_* describes physical storage.  The active write window is
      // _IO_write_base.._IO_write_end; line-buffered and unbuffered modes may
      // deliberately have no writable window despite owning storage.
      if (*pointer > *writeEnd) return unavailable("stdout-buffer-range-unavailable");
      capacity = *writeEnd - *base;
      remaining = *writeEnd - *pointer;
    } else if (unbuffered) {
      capacity = 0;
      remaining = 0;
    }
    const auto flushPolicy = unbuffered ? "every-write" :
        lineBuffered ? "newline-or-explicit" : "buffer-full-or-explicit";
    const auto storageCapacity = *bufferBase != 0
        ? std::optional<std::uint64_t>(*bufferEnd - *bufferBase) : std::nullopt;
    const bool metadataAvailable = storageCapacity.has_value() || unbuffered;
    // Counters cross into JavaScript as numbers; reject corrupt spans which
    // could no longer be represented exactly, before doing any memory read.
    constexpr std::uint64_t maxSafeInteger = 9007199254740991ULL;
    if (count > maxSafeInteger ||
        (capacity && *capacity > maxSafeInteger) ||
        (remaining && *remaining > maxSafeInteger) ||
        (storageCapacity && *storageCapacity > maxSafeInteger))
      return unavailable("stdout-buffer-range-unavailable");
    nlohmann::json result = {
        {"available", true},
        {"source", "glibc-_IO_FILE"},
        {"stream", "stdout"},
        {"association", "cout-if-synchronized"},
        {"mode", mode},
        {"flushPolicy", flushPolicy},
        {"pendingBytes", count},
        {"writeWindowCapacityBytes", capacity ? nlohmann::json(*capacity) : nlohmann::json(nullptr)},
        {"writeWindowRemainingBytes", remaining ? nlohmann::json(*remaining) : nlohmann::json(nullptr)},
        {"capacityBytes", capacity ? nlohmann::json(*capacity) : nlohmann::json(nullptr)},
        {"remainingCapacityBytes", remaining ? nlohmann::json(*remaining) : nlohmann::json(nullptr)},
        {"storageCapacityBytes", storageCapacity ? nlohmann::json(*storageCapacity) : nlohmann::json(nullptr)},
        {"metadataAvailable", metadataAvailable},
        {"text", ""},
        {"totalBytes", count},
        {"retainedFromByte", 0},
        {"truncated", false}};
    if (!metadataAvailable) result["metadataReason"] = "stdout-buffer-not-initialized";
    // No pending bytes is useful information too: direct write(2), flushed
    // cout, and unbuffered/line-buffered streams should not make the field
    // disappear.  Keep the runtime status in the snapshot even in this case.
    if (count == 0) return result;
    // GDB/MI returns the memory contents in one result record. Keep the
    // optional probe well below the 1 MiB MI record limit even when the
    // retained stdout budget is larger; a huge buffered write is reported as
    // unavailable rather than risking a fatal parser overflow.
    const auto maxProbeBytes = std::min<std::size_t>(options.maxOutputBytes, 64u * 1024u);
    if (count > maxProbeBytes || *base > std::numeric_limits<std::uint64_t>::max() - count) {
      result["retainedFromByte"] = count;
      result["truncated"] = true;
      result["textStatus"] = "unavailable";
      result["textReason"] = "stdout-buffer-too-large";
      result["available"] = true;
      return result;
    }
    std::ostringstream address;
    address << "0x" << std::hex << *base;
    MiRecord record;
    GdbError error;
    if (!command("-data-read-memory-bytes " + address.str() + " " + std::to_string(count), false, record, error)) {
      result["textStatus"] = "unavailable";
      result["textReason"] = "stdout-buffer-read-failed";
      return result;
    }
    std::string bytes;
    if (const auto* memory = field(record.fields, "memory")) {
      auto appendCell = [&](const MiValue* cell) {
        if (!cell) return true;
        return appendHexBytes(valText(field(*cell, "contents")), bytes);
      };
      if (!memory->values.empty()) {
        for (const auto& cell : memory->values) if (!appendCell(cell.get())) {
          result["textStatus"] = "unavailable";
          result["textReason"] = "stdout-buffer-malformed";
          return result;
        }
      } else {
        for (const auto& [key, cell] : memory->fields) if (!appendCell(cell.get())) {
          result["textStatus"] = "unavailable";
          result["textReason"] = "stdout-buffer-malformed";
          return result;
        }
      }
    }
    if (bytes.size() != count) {
      result["textStatus"] = "unavailable";
      result["textReason"] = "stdout-buffer-read-incomplete";
      return result;
    }
    result["text"] = displayUtf8(bytes);
    return result;
  }

  void captureIo(GdbStop& result) {
    // A FIFO can exceed the live pump's 64 KiB budget (F_SETPIPE_SZ or a
    // larger system page size). Capture the queued byte count once so the
    // final snapshot includes the complete pending tail without waiting for
    // EOF or following an untraced descendant that keeps writing forever.
    const auto queued = [](int fd) -> std::size_t {
      if (fd < 0) return 0;
      int bytes = 0;
      if (::ioctl(fd, FIONREAD, &bytes) != 0 || bytes < 0)
        throw std::runtime_error("cannot inspect pending inferior output");
      return static_cast<std::size_t>(bytes);
    };
    const auto stdoutQueued = queued(stdoutFd);
    const auto stderrQueued = queued(stderrFd);
    drainFd(stdoutFd, stdoutOutput, stdoutTotalBytes, stdoutQueued);
    drainFd(stderrFd, stderrOutput, stderrTotalBytes, stderrQueued);
    feedInput();
    const auto snapshot = [](const std::string& bytes, std::size_t total) {
      return nlohmann::json{{"text", displayUtf8(bytes)}, {"totalBytes", total},
                            {"retainedFromByte", total - bytes.size()},
                            {"truncated", total > bytes.size()}};
    };
    result.stdoutSnapshot = snapshot(stdoutOutput, stdoutTotalBytes);
    result.stderrSnapshot = snapshot(stderrOutput, stderrTotalBytes);
    if (!result.exited) {
      const auto buffered = captureBufferedStdout();
      // Keep the optional extension absent for a stop where stdout's runtime
      // buffer has not even been initialized. This preserves the v1 output
      // shape for ordinary programs while still reporting a confirmed empty
      // buffer after a real cout interaction (metadataAvailable=true).
      if (buffered.is_object() && buffered.contains("available") &&
          (buffered.value("pendingBytes", 0ULL) != 0 || buffered.value("metadataAvailable", false))) {
        result.stdoutBufferedSnapshot = buffered;
        result.stdoutSnapshot["buffered"] = buffered;
      }
    }
    {
      std::lock_guard inputLock(inputMutex);
      result.input = inputSnapshotLocked();
    }
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
      // Source text has already passed UTF-8 validation. Advance once per
      // code point, rather than once per byte: a supplementary character is
      // two UTF-16 code units, all other valid code points are one.
      const std::size_t width = c < 0x80 ? 1 : c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
      utf16 += c < 0xf0 ? 1 : 2;
      if (c == '\n') ++currentLine;
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
      failClosed(e, "LIMIT_EXCEEDED", "GDB/MI record exceeds the configured line limit");
      return false;
    }
    MiRecord r;
    try {
      r = parseMiRecord(line);
    } catch (const mi::ParseError& ex) {
      const auto code = ex.code() == mi::ParseErrorCode::limit ? "LIMIT_EXCEEDED" : "READ_FAILED";
      failClosed(e, code, std::string("malformed GDB/MI record: ") + ex.what());
      return false;
    } catch (const std::exception& ex) {
      failClosed(e, "READ_FAILED", std::string("cannot parse GDB/MI record: ") + ex.what());
      return false;
    }
    if (r.type == '=' && r.klass == "thread-group-started") {
      const auto* pid = field(r.fields, "pid");
      if (pid && !pid->text.empty()) {
        inferiorPid = pid->text;
        int numericPid = 0;
        const auto parsed = std::from_chars(inferiorPid.data(), inferiorPid.data() + inferiorPid.size(), numericPid);
        if (parsed.ec == std::errc{} && parsed.ptr == inferiorPid.data() + inferiorPid.size() && numericPid > 0) {
          if (inferiorPidFd >= 0) (void)::close(inferiorPidFd);
          inferiorPidFd = static_cast<int>(::syscall(SYS_pidfd_open, numericPid, 0));
        }
      }
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
    e = {};
    // Callers may reuse the record for a finish followed by a source step.
    // A poll containing only the previous prompt must not let that old stop
    // satisfy the new command before its acknowledgement arrives.
    stop = MiRecord{};
    if (!process) { setError(e, "INVALID_REQUEST", "GDB is not running"); return false; }
    const auto token = nextToken++;
    std::string tokenText = std::to_string(token);
    try {
      process->write(tokenText + std::string(commandText) + "\n",
                     std::chrono::steady_clock::now() + options.commandTimeout);
    } catch (const std::exception& ex) {
      failClosed(e, "INTERNAL", ex.what()); return false;
    }
    // Control-thread calls only publish intent. The owning worker sends an
    // interrupt after ^running, so same-packet pause cannot signal idle GDB.
    const bool recoverableStep = waitStop &&
        (commandText == "-exec-next" || commandText == "-exec-step" ||
         commandText == "-exec-finish" || commandText == "-exec-step-instruction");
    bool recoveringStep = false;
    bool checkingInput = false;
    auto nextInputProbe = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    bool pendingInterrupt = preempt == 1;
    bool interruptSent = false;
    bool done = false, running = false;
    bool interactiveContinue = commandText == "-exec-continue" && inputRemainsOpen();
    auto deadline = interactiveContinue ? std::chrono::steady_clock::time_point::max() :
        std::chrono::steady_clock::now() + (recoverableStep ? options.stepTimeout : options.commandTimeout);
    while (std::chrono::steady_clock::now() < deadline) {
      if (interactiveContinue && !inputRemainsOpen()) {
        interactiveContinue = false;
        deadline = std::chrono::steady_clock::now() + options.commandTimeout;
      }
      const int mode = control.exchange(0);
      if (preempt >= 2 || mode >= 2 || launchCancellation.stop_requested()) {
        process->terminate(); live = false;
        setError(e, "CANCELLED", "debugger stopped", true); return false;
      }
      pendingInterrupt = pendingInterrupt || mode == 1;
      if (waitStop && running && pendingInterrupt && !interruptSent) {
        process->interrupt(); interruptSent = true;
      }
      if (waitStop && running && !interruptSent && !pendingInterrupt &&
          (recoverableStep || commandText == "-exec-continue") &&
          std::chrono::steady_clock::now() >= nextInputProbe) {
        nextInputProbe = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        if (inputReadInProgress()) {
          process->interrupt();
          interruptSent = true;
          checkingInput = true;
          interactiveContinue = false;
          deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
        }
      }
      ProcessOutput output;
      try { drainIo(); output = process->poll(std::chrono::milliseconds(5)); drainIo(); }
      catch (const std::exception& ex) { failClosed(e, "INTERNAL", ex.what()); return false; }
      lines += output.out;
      std::size_t p = 0;
      while ((p = lines.find('\n')) != std::string::npos) {
        std::string line = lines.substr(0, p);
        lines.erase(0, p + 1);
        if (processLine(std::move(line), tokenText, waitStop, done, running, stop, e)) {
          if (waitStop && (stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally"))) {
            if (checkingInput) setError(e, "INPUT_CHECK", "interrupted a pending stdin read", true);
            else if (recoveringStep) {
              setError(e, "STEP_TIMEOUT",
                       "source step did not reach a different source line before the step deadline; inferior was interrupted",
                       true);
            }
            return true;
          }
          if (!e.code.empty()) return false;
          if (!waitStop && done) return e.code.empty();
        }
        // Execution commands can fail before producing an asynchronous stop
        // (for example ptrace denied or an invalid executable).  Do not spin
        // until the timeout after GDB has already returned ^error.
        if (!e.code.empty()) return false;
      }
      if (lines.size() > 1024u * 1024u) {
        failClosed(e, "LIMIT_EXCEEDED", "unterminated GDB/MI record exceeds line limit"); return false;
      }
      if (waitStop && stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally")) {
        if (checkingInput) setError(e, "INPUT_CHECK", "interrupted a pending stdin read", true);
        else if (recoveringStep) {
          setError(e, "STEP_TIMEOUT",
                   "source step did not reach a different source line before the step deadline; inferior was interrupted",
                   true);
        }
        return true;
      }
      if (!waitStop && done) return e.code.empty();
      if (output.exit) { failClosed(e, "LAUNCH_FAILED", "GDB exited before command completed"); return false; }
    }
    if (recoverableStep && !recoveringStep) {
      // GDB's line stepping command has no completion point when execution
      // remains on the same source line.  Interrupt the process group so GDB
      // emits a real `*stopped` record, then retain the debugger session for
      // the caller to inspect or continue.  This is intentionally surfaced as
      // an incomplete step rather than pretending that a source transition
      // happened.
      process->interrupt();
      recoveringStep = true;
      deadline = std::chrono::steady_clock::now() +
          std::min(options.commandTimeout, std::chrono::milliseconds(1000));
      while (std::chrono::steady_clock::now() < deadline) {
        ProcessOutput output;
        try { drainIo(); output = process->poll(std::chrono::milliseconds(5)); drainIo(); }
        catch (const std::exception& ex) { failClosed(e, "INTERNAL", ex.what()); return false; }
        lines += output.out;
        std::size_t p = 0;
        while ((p = lines.find('\n')) != std::string::npos) {
          std::string line = lines.substr(0, p);
          lines.erase(0, p + 1);
          if (processLine(std::move(line), tokenText, waitStop, done, running, stop, e)) {
            if (waitStop && stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally")) {
              setError(e, "STEP_TIMEOUT",
                       "source step did not reach a different source line before the step deadline; inferior was interrupted",
                       true);
              return true;
            }
            if (!e.code.empty()) return false;
          }
        }
        if (waitStop && stop.type == '*' && (stop.klass == "stopped" || stop.klass == "exited" || stop.klass == "exited-normally")) {
          setError(e, "STEP_TIMEOUT",
                   "source step did not reach a different source line before the step deadline; inferior was interrupted",
                   true);
          return true;
        }
        if (output.exit) { failClosed(e, "LAUNCH_FAILED", "GDB exited before interrupted step completed"); return false; }
      }
    }
    failClosed(e, "TIMEOUT", "GDB command timed out");
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
                      // The address is filled by enrichVariableTypes.  Keep
                      // an explicit null for names for which GDB cannot
                      // prove a current storage location.
                      {"addressHex", nullptr},
                      {"storage", {{"state", "unknown"}, {"lifetime", "unknown"},
                                    {"addressHex", nullptr},
                                    {"byteLength", nullptr}, {"reason", "location-unavailable"}}},
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
                        {"addressHex", nullptr},
                        {"storage", {{"state", "unknown"}, {"lifetime", "unknown"},
                                      {"addressHex", nullptr},
                                      {"byteLength", nullptr}, {"reason", "location-unavailable"}}},
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
    // Resolve the address and a bounded raw byte slice separately from the
    // semantic value.  A fixed stack slot can be physically readable before
    // a C++ object's lifetime begins; therefore `lifetime` deliberately stays
    // `unknown` and raw bytes must never be presented as an initialized value.
    const auto unknownStorage = [](std::string reason) {
      return nlohmann::json{{"state", "unknown"}, {"lifetime", "unknown"},
                            {"addressHex", nullptr},
                            {"byteLength", nullptr}, {"reason", std::move(reason)}};
    };
    const auto canonicalAddress = [](std::uint64_t address) {
      std::ostringstream out; out << "0x" << std::hex << address; return out.str();
    };
    const auto hexBytes = [](std::string_view bytes) {
      static constexpr char digits[] = "0123456789abcdef";
      std::string out; out.reserve(bytes.size() * 2);
      for (const unsigned char byte : bytes) {
        out.push_back(digits[byte >> 4]); out.push_back(digits[byte & 0x0f]);
      }
      return out;
    };
    const auto readMemoryHex = [&](std::string_view address, std::size_t count,
                                   std::string& bytes) {
      MiRecord record;
      GdbError local;
      if (!command("-data-read-memory-bytes " + std::string(address) + " " +
                    std::to_string(count), false, record, local)) return false;
      const auto* memory = field(record.fields, "memory");
      if (!memory) return false;
      auto appendCell = [&](const MiValue* cell) {
        return cell && appendHexBytes(valText(field(*cell, "contents")), bytes);
      };
      if (!memory->values.empty()) {
        for (const auto& cell : memory->values) if (!appendCell(cell.get())) return false;
      } else {
        for (const auto& [key, cell] : memory->fields)
          if (!appendCell(cell.get())) return false;
      }
      return bytes.size() == count;
    };
    const auto evaluate = [&](std::string_view expression, std::string& value) {
      MiRecord record;
      GdbError local;
      if (!command("-data-evaluate-expression " + std::string(expression), false, record, local)) return false;
      const auto* result = field(record.fields, "value");
      if (!result || result->text.empty()) return false;
      value = result->text;
      return true;
    };
    for (auto& variable : variables) {
      const auto name = variable.value("name", "");
      if (name.empty() || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != std::string::npos) {
        variable["addressHex"] = nullptr;
        variable["storage"] = unknownStorage("unsupported-name");
        continue;
      }
      variable["addressHex"] = nullptr;
      variable["storage"] = unknownStorage("location-unavailable");
      // The name was supplied by GDB's local-variable list and is restricted
      // to an identifier. `&name` and `sizeof(name)` do not execute an
      // inferior function; startup also disables GDB's function calls below.
      std::string addressText;
      if (evaluate("&" + name, addressText)) {
        const auto address = parseAddress(addressText);
        if (address) {
          const auto addressHex = canonicalAddress(*address);
          variable["addressHex"] = addressHex;
          std::string sizeText;
          const auto unknownSize = [&] (std::string reason) {
            variable["storage"] = {{"state", "unknown"}, {"lifetime", "unknown"},
                                    {"addressHex", addressHex}, {"byteLength", nullptr},
                                    {"reason", std::move(reason)}};
          };
          // A stop can contain many locals; cap each raw slice below the
          // protocol's general memory-read limit so 128 variables cannot
          // inflate one observation into megabytes of hex text.
          constexpr std::size_t maxStorageSliceBytes = 4096;
          const auto storageLimit = std::min(options.maxMemoryReadBytes, maxStorageSliceBytes);
          if (!evaluate("sizeof(" + name + ")", sizeText)) { unknownSize("size-unavailable"); }
          else if (const auto size = parseUnsigned(sizeText); !size || *size > storageLimit) {
            unknownSize(size ? "too-large" : "size-unavailable");
            if (size) variable["storage"]["byteLength"] = *size;
          } else {
            std::string bytes;
            if (readMemoryHex(addressHex, static_cast<std::size_t>(*size), bytes)) {
              variable["storage"] = {{"state", "observed"}, {"lifetime", "unknown"},
                                      {"addressHex", addressHex}, {"byteLength", *size},
                                      {"rawBytesHex", hexBytes(bytes)}};
            } else {
              variable["storage"] = {{"state", "unknown"}, {"lifetime", "unknown"},
                                      {"addressHex", addressHex}, {"byteLength", *size},
                                      {"reason", "read-error"}};
            }
          }
        }
      }
      MiRecord created;
      GdbError local;
      if (!command("-var-create - * " + name, false, created, local)) {
        if (!live) { outerError = local; return; }
        continue;
      }
      const auto* type = field(created.fields, "type");
      const auto* value = field(created.fields, "value");
      if (type && !type->text.empty()) {
        variable["type"] = type->text;
        variable["value"] = runtimeValue(type->text, value ? value->text : std::string{});
        // A C++ reference aliases another object; `&reference` names that
        // pointee and is not the reference's own storage. Do not publish it
        // as this variable's address/raw bytes.
        if (type->text.find('&') != std::string::npos) {
          variable["addressHex"] = nullptr;
          variable["storage"] = unknownStorage("no-own-storage");
        }
      }
      const auto* objectName = field(created.fields, "name");
      if (objectName && !objectName->text.empty()) {
        MiRecord deleted;
        GdbError ignored;
        if (!command("-var-delete " + objectName->text, false, deleted, ignored) && !live) {
          outerError = ignored; return;
        }
      }
    }
    (void)outerError;
  }

  bool snapshotStack(GdbStop& result, GdbError& e, bool chooseUserFrame = true) {
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
          if (!e.code.empty()) return false;
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
          if (!e.code.empty()) return false;
        }
        int sourceLine = 0;
        try { sourceLine = std::stoi(valText(field(*fr, "line"))); } catch (...) {}
        const auto location = sourceLocation(valText(field(*fr, "fullname")), sourceLine);
        output.push_back({{"id", activation}, {"activationId", activation}, {"functionName", function},
                          {"location", location},
                           {"variables", std::move(variables)}});
      }
    }
    // If GDB stopped inside libc while servicing a blocking stdin read, the
    // selected frame is usually frame 0 and consequently has no user locals.
    // Re-select the first submitted source frame and collect variables there,
    // while preserving every native frame in the returned stack.  This keeps
    // `main` visible without fabricating a source location for libc.
    if (chooseUserFrame && selectedFrame == 0 && !output.empty() &&
        output.front().value("location", nlohmann::json(nullptr)).is_null() &&
        isInputRuntimeFrame(output.front().value("functionName", ""))) {
      for (const auto& frame : output) {
        const auto levelText = frame.value("id", "frame:0");
        if (frame.value("location", nlohmann::json(nullptr)).is_null() ||
            isInputRuntimeFrame(frame.value("functionName", ""))) continue;
        const auto colon = levelText.find(':');
        if (colon == std::string::npos) continue;
        int level = 0;
        try { level = std::stoi(levelText.substr(colon + 1)); } catch (...) { continue; }
        MiRecord selected;
        GdbError selectedError;
        if (command("-stack-select-frame " + std::to_string(level), false, selected, selectedError)) {
          selectedFrame = level;
          return snapshotStack(result, e, false);
        }
        break;
      }
    }
    lastStack = output;
    result.stack = std::move(output);
    return true;
  }

  bool makeStop(const MiRecord& stop, GdbStop& result, GdbError& e) {
    result = GdbStop{};
    selectedFrame = 0;
    result.stopped = stop.klass == "stopped";
    result.reason = valText(field(stop.fields, "reason"));
    result.exited = stop.klass == "exited" || stop.klass == "exited-normally" ||
                    result.reason == "exited-normally" || result.reason == "exited" ||
                    result.reason == "exited-signalled";
    if (stop.klass == "exited-normally" || result.reason == "exited-normally") result.exitCode = 0;
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
    // At an inferior stop its completed writes are already queued in the
    // kernel. Capture that backlog without a sleep or EOF heuristic.
    captureIo(result);
    result.raw = {{"reason", result.reason}, {"stack", result.stack}, {"location", result.location}};
    result.raw["exited"] = result.exited;
    if (result.exitCode) result.raw["exitCode"] = *result.exitCode;
    return true;
  }

  bool startGdb(const GdbLaunchRequest& request, GdbError& e) {
    if (options.execWrapper.empty() || ::access(options.execWrapper.c_str(), X_OK) != 0) {
      setError(e, "LAUNCH_FAILED", "the inferior I/O wrapper is unavailable", true);
      return false;
    }
    std::vector<std::string> argv{options.gdbPath, "--interpreter=mi2", "-nx", "--quiet",
                                  "-iex", "set auto-load off"};
    ProcessOptions po;
    po.argv = argv;
    po.cwd = options.workingDirectory.empty() ? request.binaryPath.parent_path().string() : options.workingDirectory.string();
    // The requested environment belongs to the inferior. Passing it to the
    // debugger itself makes PATH or LD_PRELOAD alter GDB's lookup/loading
    // behavior instead of only configuring the debugged program.
    po.environment.emplace_back("SHELL", "/bin/sh");
    po.environment.emplace_back("DEBUGINFOD_URLS", "");
    // MI belongs to an unbounded-duration conversation. Retaining already
    // consumed replies would eventually kill a healthy debugging session.
    // Process bounds each poll; command() bounds individual MI records.
    po.capture_output = false;
    try { std::lock_guard lock(processMutex); process = std::make_unique<Process>(Process::spawn(po)); }
    catch (const std::exception& ex) { setError(e, "LAUNCH_FAILED", ex.what()); return false; }
    live = true;
    auto setup = [&](std::string_view c) { MiRecord ignored; return command(c, false, ignored, e); };
    if (!setup("-gdb-set pagination off") || !setup("-gdb-set confirm off") ||
        // Address/sizeof probes are intentionally non-evaluating.  Refuse
        // any fallback that would invoke a user function or overloaded call.
        !setup("-gdb-set may-call-functions off") || !setup("-gdb-set overload-resolution off") ||
        !setup("-gdb-set startup-with-shell on") || !setup("-gdb-set print pretty off") ||
        !setup("-gdb-set print elements 128") ||
        !setup("-interpreter-exec console " + miQuote("set inferior-tty " + ptyPath.string()))) return false;
    // GDB runs exec-wrapper through its startup shell; quote both trusted
    // paths. Target environment is a private NUL-delimited file consumed by
    // the helper immediately before exec, so LD_*/BASH_ENV never affect GDB,
    // the shell or the helper itself.
    if (!setup("-interpreter-exec console " + miQuote("set exec-wrapper " +
        shellQuote(options.execWrapper.string()) + " " + shellQuote(tempDir.string())))) return false;
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

bool GdbEngine::launch(const GdbLaunchRequest& request, GdbStop& result, GdbError& error,
                       std::stop_token cancellation) {
  stop();
  impl_->launchCancellation = cancellation;
  struct ResetCancellation {
    std::stop_token& token;
    ~ResetCancellation() { token = {}; }
  } reset{impl_->launchCancellation};
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
  impl_->lines.clear(); impl_->nextToken = 1; impl_->selectedFrame = 0;
  impl_->inputWaitActive = false;
  impl_->inputWaitFrame = -1;
  impl_->inputWaitLocation = nullptr;
  impl_->sourceBundle = request.sourceBundle;
  if (!impl_->prepareTemp(request, error)) return false;
  if (!impl_->startGdb(request, error)) { stop(); return false; }
  if (request.stopAtEntry) {
    MiRecord entryBreakpoint;
    if (!impl_->command("-break-insert -t -f main", false, entryBreakpoint, error)) { stop(); return false; }
  }
  MiRecord stopped;
  if (!impl_->command("-exec-run", true, stopped, error)) { stop(); return false; }
  if (!impl_->makeStop(stopped, result, error)) { stop(); return false; }
  result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  return true;
}

bool GdbEngine::appendInput(std::string_view id, std::string_view text,
                            nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  if (id.empty()) { error = {"INVALID_REQUEST", "input id must not be empty", false}; return false; }
  std::lock_guard inputLock(impl_->inputMutex);
  if (!impl_->live.load() || impl_->control.load() >= 2) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  const auto existing = impl_->inputChunks.find(std::string(id));
  if (existing != impl_->inputChunks.end()) {
    if (existing->second != text) {
      error = {"STALE_CONTEXT", "input id was already used with different text", false}; return false;
    }
    result = impl_->inputSnapshotLocked();
    return true;
  }
  if (impl_->closeInputAfterWrite) {
    error = {"STALE_CONTEXT", "EOF has already been requested for stdin", false}; return false;
  }
  if (impl_->stdinFd < 0 && impl_->wrapperReady) {
    error = {"STALE_CONTEXT", "inferior stdin is already closed", false}; return false;
  }
  // Empty chunks still consume bookkeeping and must not provide an unbounded
  // way to grow a session while keeping the byte budget at zero.
  if (impl_->inputChunks.size() >= 4096) {
    error = {"LIMIT_EXCEEDED", "too many interactive input chunks", false}; return false;
  }
  if (impl_->pendingInput.size() > impl_->options.maxInputBytes ||
      text.size() > impl_->options.maxInputBytes - impl_->pendingInput.size()) {
    error = {"LIMIT_EXCEEDED", "interactive input exceeds configured limit", false}; return false;
  }
  impl_->inputChunks.emplace(std::string(id), std::string(text));
  impl_->inputParentRevisionId = impl_->inputRevisionId;
  impl_->inputRevisionId = std::string(id);
  impl_->pendingInput.append(text);
  impl_->feedInputLocked();
  result = impl_->inputSnapshotLocked();
  return true;
}

bool GdbEngine::closeInput(nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  std::lock_guard inputLock(impl_->inputMutex);
  if (!impl_->live.load() || impl_->control.load() >= 2) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  impl_->closeInputAfterWrite = true;
  impl_->feedInputLocked();
  result = impl_->inputSnapshotLocked();
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
  const auto waitLocation = impl_->inputWaitLocation;
  const bool recoverInputStep = impl_->inputWaitActive && impl_->inputWaitFrame > 0 &&
      (stepKind == "over" || stepKind == "into" || stepKind == "out");
  if (recoverInputStep) {
    MiRecord selected;
    // `finish` from the immediate callee completes the pending extraction.
    // GDB owns its momentary return breakpoint and honors intervening user
    // breakpoints, signals, another input wait and cancellation. Step-out
    // instead finishes the visible user frame as explicitly requested.
    const int frame = stepKind == "out" ? impl_->inputWaitFrame : impl_->inputWaitFrame - 1;
    if (!impl_->command("-stack-select-frame " + std::to_string(frame), false, selected, error)) return false;
    cmd = "-exec-finish";
  }
  impl_->inputWaitActive = false;
  if (!impl_->command(cmd, true, stopped, error, preempt)) {
    // An unsupported finish (for example an inline frame) rejects before
    // running. Keep the waiting context usable for retry or Continue.
    if (recoverInputStep && impl_->live.load()) impl_->inputWaitActive = true;
    return false;
  }
  if (recoverInputStep && stepKind != "out" && error.code.empty()) {
    const auto reason = valText(field(stopped.fields, "reason"));
    const auto* frame = field(stopped.fields, "frame");
    int line = 0;
    if (frame) { try { line = std::stoi(valText(field(*frame, "line"))); } catch (...) {} }
    const auto location = frame ? impl_->sourceLocation(valText(field(*frame, "fullname")), line) : nlohmann::json(nullptr);
    // Some compilers attribute the return instruction to the cin line. Once
    // GDB has finished that call, perform the requested source step normally.
    // Never step over a user breakpoint or a signal encountered on the way.
    if ((reason.empty() || reason == "function-finished") && location == waitLocation && !location.is_null()) {
      if (!impl_->command(stepKind == "into" ? "-exec-step" : "-exec-next", true, stopped, error)) return false;
    }
  }
  const bool incompleteStep = error.code == "STEP_TIMEOUT";
  const bool inputCandidate = error.code == "INPUT_CHECK" || incompleteStep;
  const bool inputWait = inputCandidate && valText(field(stopped.fields, "signal-name")) == "SIGINT" &&
      impl_->interruptedInputRead();
  if (error.code == "INPUT_CHECK" && !inputWait) error = {};
  GdbError snapshotError;
  if (!impl_->makeStop(stopped, result, snapshotError)) { error = std::move(snapshotError); return false; }
  if (impl_->process) result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  if (inputWait && result.stopped && !result.exited) {
    impl_->inputWaitActive = true;
    impl_->inputWaitFrame = -1;
    impl_->inputWaitLocation = nullptr;
    result.reason = "input-wait";
    result.signalName.clear(); // SIGINT is debugger bookkeeping, not a program failure.
    for (const auto& frame : result.stack) {
      const auto location = frame.value("location", nlohmann::json(nullptr));
      if (location.is_null()) continue;
      const auto id = frame.value("id", std::string{});
      const auto colon = id.find(':');
      if (colon == std::string::npos) continue;
      try { impl_->inputWaitFrame = std::stoi(id.substr(colon + 1)); } catch (...) { continue; }
      impl_->inputWaitLocation = location;
      if (result.location.is_null()) result.location = location;
      break;
    }
    error = {"INPUT_WAIT", "program is waiting for stdin; provide input to continue", true};
    return false;
  }
  if (incompleteStep) return false;
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
}
void GdbEngine::clearInterrupt() noexcept { impl_->control.store(0); }
GdbStop GdbEngine::stopAndSnapshot() {
  GdbStop result;
  result.exited = true;
  result.reason = "stop";
  result.processInstanceId = impl_->inferiorPid;
  impl_->control.store(2);
  {
    std::lock_guard lock(impl_->processMutex);
    if (impl_->process) impl_->process->terminate();
  }
  impl_->killInferior();
  try { impl_->captureIo(result); }
  catch (...) { stop(); throw; }
  stop();
  return result;
}
void GdbEngine::stop() noexcept {
  if (!impl_) return;
  impl_->control.store(2);
  std::lock_guard lock(impl_->processMutex);
  if (impl_->process) impl_->process->terminate();
  impl_->process.reset();
  impl_->killInferior();
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
  const auto previousBreakpoints = impl_->breakpoints;
  for (const auto& entry : previousBreakpoints) {
    if (entry.documentId != documentId) { retained.push_back(entry); continue; }
    MiRecord ignored;
    if (!impl_->command("-break-delete " + entry.number, false, ignored, error)) return false;
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
    if (number.empty()) {
      item["verified"] = false; item["message"] = "GDB did not resolve breakpoint";
    } else {
      impl_->breakpoints.push_back({documentId, number});
      item["verified"] = true;
      // The requested editor range is not evidence of where GDB resolved the
      // line. Publish a resolved span only when MI returned a concrete file
      // and line that can be mapped back to the immutable source bundle.
      const auto fullName = valText(bkpt ? field(*bkpt, "fullname") : nullptr);
      const auto lineText = valText(bkpt ? field(*bkpt, "line") : nullptr);
      int resolvedLine = 0;
      const auto parsed = std::from_chars(lineText.data(), lineText.data() + lineText.size(), resolvedLine);
      if (!fullName.empty() && parsed.ec == std::errc{} && parsed.ptr == lineText.data() + lineText.size()) {
        const auto resolved = impl_->sourceLocation(fullName, resolvedLine);
        if (!resolved.is_null()) item["resolvedRange"] = resolved;
      }
    }
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
  const auto isCurrent = [&](std::string_view text) {
    const auto parsed = parseAddress(text);
    return parsed && *parsed == *address;
  };
  if (const MiValue* list = field(rec.fields, "asm_insns")) {
    for (const auto& insn : list->values) {
      auto addr = valText(field(*insn, "address"));
      instructions.push_back({{"addressHex", addr}, {"bytesHex", valText(field(*insn, "opcodes"))},
                              {"text", valText(field(*insn, "inst"))}, {"current", isCurrent(addr)}});
      if (instructions.size() >= maxInstructions) break;
    }
    for (const auto& [key, insn] : list->fields) {
      if (!insn) continue;
      auto addr = valText(field(*insn, "address"));
      instructions.push_back({{"addressHex", addr}, {"bytesHex", valText(field(*insn, "opcodes"))},
                              {"text", valText(field(*insn, "inst"))}, {"current", isCurrent(addr)}});
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
