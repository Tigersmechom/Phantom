#include "phantom/gdb.hpp"
#include "phantom/memory_map.hpp"

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
  MiRecord latestStop;
  std::vector<std::string> registerNames;
  // Preserve a Pause arriving during boundary reads until the trace loop
  // handles it. A read command itself never needs to interrupt a stopped task.
  bool traceActive = false;
  bool lastExecutionInterrupted = false;
  std::string recordingProfile = "native";
  std::size_t maxRecordedInstructions = 200000;
  bool recordingActive = false;
  bool captureConsole = false;
  std::string consoleOutput;
  bool captureRecordingDiagnostics = false;
  std::string recordingDiagnostics;

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
  void interruptExecution() noexcept {
    // In synchronous record-full source stepping GDB can defer its own
    // SIGINT indefinitely while following an endless single source line.
    // Signal the exact owned inferior through its pidfd instead: ptrace
    // reports a real SIGINT stop and GDB retains the recording. No PID lookup
    // or process-wide/global debugger setting is involved.
    if (recordingActive && inferiorPidFd >= 0 &&
        ::syscall(SYS_pidfd_send_signal, inferiorPidFd, SIGINT, nullptr, 0) == 0) return;
    if (process) process->interrupt();
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
    if (request.recordingProfile == "gdb-record-full" &&
        std::none_of(request.environment.begin(), request.environment.end(),
                     [](const auto& item) { return item.first == "LC_ALL"; })) {
      // The debugger's status parser uses English, but the target retains its
      // original locale. GDB's inherited LC_ALL is removed before exec below.
      if (const char* locale = std::getenv("LC_ALL")) {
        environment << "LC_ALL=" << locale;
        environment.put('\0');
      }
    }
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

  // Read a bounded pending window, never execute a streambuf method in the
  // inferior. Metadata can remain useful even if bytes are unavailable.
  nlohmann::json captureBufferText(nlohmann::json result, std::uint64_t base,
                                    std::uint64_t count, std::string_view prefix) {
    if (count == 0) return result;
    const auto maxProbeBytes = std::min<std::size_t>(options.maxOutputBytes, 64u * 1024u);
    const auto failText = [&](std::string_view reason) {
      result["retainedFromByte"] = count;
      result["truncated"] = true;
      result["textStatus"] = "unavailable";
      result["textReason"] = std::string(prefix) + std::string(reason);
      return result;
    };
    if (count > maxProbeBytes || base > std::numeric_limits<std::uint64_t>::max() - count)
      return failText("-buffer-too-large");
    std::ostringstream address;
    address << "0x" << std::hex << base;
    MiRecord record;
    GdbError error;
    if (!command("-data-read-memory-bytes " + address.str() + " " + std::to_string(count), false, record, error))
      return failText("-buffer-read-failed");
    std::string bytes;
    if (const auto* memory = field(record.fields, "memory")) {
      const auto appendCell = [&](const MiValue* cell) {
        return cell && appendHexBytes(valText(field(*cell, "contents")), bytes);
      };
      if (!memory->values.empty()) {
        for (const auto& cell : memory->values)
          if (!appendCell(cell.get())) return failText("-buffer-malformed");
      } else {
        for (const auto& [key, cell] : memory->fields)
          if (!appendCell(cell.get())) return failText("-buffer-malformed");
      }
    }
    if (bytes.size() != count) return failText("-buffer-read-incomplete");
    result["text"] = displayUtf8(bytes);
    return result;
  }

  bool stdoutFeedsOwnedTransport() const {
    int pid = 0;
    const auto parsed = std::from_chars(inferiorPid.data(), inferiorPid.data() + inferiorPid.size(), pid);
    if (stdoutFd < 0 || parsed.ec != std::errc{} ||
        parsed.ptr != inferiorPid.data() + inferiorPid.size() || pid <= 0) return false;
    struct stat expected{}, actual{};
    const auto path = "/proc/" + std::to_string(pid) + "/fd/1";
    // FILE* identity and _fileno alone survive freopen/dup2. Pending bytes
    // belong in captured stdout only if the descriptor still targets our FIFO.
    return ::fstat(stdoutFd, &expected) == 0 && S_ISFIFO(expected.st_mode) &&
        ::stat(path.c_str(), &actual) == 0 && S_ISFIFO(actual.st_mode) &&
        actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
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
    if (!stdoutFeedsOwnedTransport()) return unavailable("stdout-sink-unavailable");
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
    return captureBufferText(std::move(result), *base, count, "stdout");
  }

  // The libstdc++ Linux LP64 ABI is usable even when the installed library
  // has no DWARF (std::cout is commonly an incomplete type in GDB). This
  // profile uses its stable object layout, guarded by target pointer sizes,
  // ostream vtable/virtual-base geometry and the ACTUAL rdbuf RTTI. Hidden
  // stdio_filebuf vtables are identified through their exported typeinfo.
  // A custom/redirected rdbuf must never be mislabeled as pending stdout.
  // Layout references: libstdc++ basic_ios.h, streambuf, fstream,
  // config/io/basic_file_stdio.h and ext/stdio_sync_filebuf.h; RTTI uses the
  // Itanium C++ ABI. No user expressions or inferior function calls occur.
  nlohmann::json captureBufferedCout(const nlohmann::json& cStdout) {
    const auto unavailable = [](std::string reason) {
      return nlohmann::json{{"available", false}, {"reason", std::move(reason)}};
    };
    const auto number = [&](const std::string& expression) -> std::optional<std::uint64_t> {
      MiRecord record;
      GdbError error;
      if (!command("-data-evaluate-expression " + miQuote("(unsigned long)(" + expression + ")"),
                   false, record, error)) return std::nullopt;
      return parseUnsigned(valText(field(record.fields, "value")));
    };
    if (!process || !live) return unavailable("no-live-inferior");
    if (!stdoutFeedsOwnedTransport()) return unavailable("cout-stdout-sink-unavailable");
    const auto supported = number("sizeof(void*) == 8 && sizeof(long) == 8 && sizeof(int) == 4");
    const auto coutAddress = number("&'_ZSt4cout'");
    const auto ostreamVtable = number("&'_ZTVSo'");
    constexpr auto maxAddress = std::numeric_limits<std::uint64_t>::max();
    if (!supported || *supported != 1 || !coutAddress || !ostreamVtable ||
        *coutAddress > maxAddress - 264 || *ostreamVtable > maxAddress - 64)
      return unavailable("cout-runtime-unavailable");
    const auto word = [&](std::uint64_t address, std::size_t offset = 0) -> std::optional<std::uint64_t> {
      if (address == 0 || address > std::numeric_limits<std::uint64_t>::max() - offset)
        return std::nullopt;
      return number("*(unsigned long*)" + std::to_string(address + offset));
    };
    const auto primaryVptr = word(*coutAddress);
    const auto virtualBaseVptr = word(*coutAddress, 8);
    // basic_ostream has one virtual basic_ios base, at offset 8 in this ABI.
    // Its vtable address points 24 bytes past the vbase/offset/RTTI prefix.
    if (!primaryVptr || !virtualBaseVptr || *primaryVptr != *ostreamVtable + 24 ||
        *virtualBaseVptr != *ostreamVtable + 64 ||
        word(*ostreamVtable) != std::optional<std::uint64_t>(8))
      return unavailable("cout-layout-unsupported");
    const auto streambuf = word(*coutAddress, 240);  // basic_ios::_M_streambuf
    if (!streambuf || *streambuf == 0) return unavailable("cout-streambuf-unavailable");
    if ((*streambuf & 7u) != 0 || *streambuf > maxAddress - 208)
      return unavailable("cout-streambuf-layout-unsupported");
    const auto vptr = word(*streambuf);
    if (!vptr || *vptr < 16 || (*vptr & 7u) != 0) return unavailable("cout-streambuf-layout-unsupported");
    const auto typeinfo = word(*vptr - 8);
    if (!typeinfo || word(*vptr - 16) != std::optional<std::uint64_t>(0))
      return unavailable("cout-streambuf-layout-unsupported");
    const auto syncTypeinfo = number("&'_ZTIN9__gnu_cxx18stdio_sync_filebufIcSt11char_traitsIcEEE'");
    const auto fileTypeinfo = number("&'_ZTIN9__gnu_cxx13stdio_filebufIcSt11char_traitsIcEEE'");
    const bool synchronized = syncTypeinfo && *typeinfo == *syncTypeinfo;
    if (!synchronized && (!fileTypeinfo || *typeinfo != *fileTypeinfo))
      return unavailable("cout-custom-streambuf-unsupported");
    const auto stdoutAddress = number("&'_IO_2_1_stdout_'");
    const auto file = word(*streambuf, synchronized ? 64 : 104);
    if (!stdoutAddress || !file || *file != *stdoutAddress)
      return unavailable("cout-streambuf-not-stdout");
    const auto flags = number("*(unsigned int*)" + std::to_string(*coutAddress + 32));
    if (!flags) return unavailable("cout-layout-unsupported");
    const bool unitbuf = (*flags & 0x2000u) != 0;
    if (synchronized) {
      if (!cStdout.value("available", false)) return unavailable("cout-stdout-buffer-unavailable");
      auto result = cStdout;
      result["stream"] = "cout";
      // This is an explicit identity relationship, not a text comparison.
      result["association"] = "cout-synchronized";
      if (unitbuf) result["flushPolicy"] = "every-write";
      return result;
    }
    // basic_filebuf's put area contains INTERNAL characters. A user codecvt
    // can transform/expand them during flush, so they are not confirmed
    // pending stdout bytes. Only the exact standard char no-conversion facet
    // is supported; inspecting its vtable/RTTI avoids a virtual inferior call.
    const auto codecvt = word(*streambuf, 200);
    const auto codecvtVtable = number("&'_ZTVSt7codecvtIcc11__mbstate_tE'");
    const auto codecvtTypeinfo = number("&'_ZTISt7codecvtIcc11__mbstate_tE'");
    if (!codecvt || *codecvt == 0 || !codecvtVtable || !codecvtTypeinfo ||
        *codecvtVtable > maxAddress - 16 ||
        word(*codecvt) != std::optional<std::uint64_t>(*codecvtVtable + 16) ||
        word(*codecvtVtable) != std::optional<std::uint64_t>(0) ||
        word(*codecvtVtable, 8) != codecvtTypeinfo)
      return unavailable("cout-codecvt-unsupported");
    // glibc's FILE layout is inspected by name when its debug type exists;
    // stdout identity, narrow orientation and fd 1 must still be proven.
    const auto fileValid = number("((struct _IO_FILE*)&'_IO_2_1_stdout_')->_fileno == 1 && "
        "((struct _IO_FILE*)&'_IO_2_1_stdout_')->_mode <= 0 && "
        "(((struct _IO_FILE*)&'_IO_2_1_stdout_')->_flags & 0xffff0000u) == 0xfbad0000u");
    const auto mode = number("*(unsigned int*)" + std::to_string(*streambuf + 120));
    const auto base = word(*streambuf, 32);      // basic_streambuf::_M_out_beg
    const auto pointer = word(*streambuf, 40);   // basic_streambuf::_M_out_cur
    const auto end = word(*streambuf, 48);       // basic_streambuf::_M_out_end
    const auto storage = word(*streambuf, 152); // basic_filebuf::_M_buf
    const auto capacity = word(*streambuf, 160);// basic_filebuf::_M_buf_size
    constexpr std::uint64_t maxSafeInteger = 9007199254740991ULL;
    if (!fileValid || *fileValid != 1 || !mode || (*mode & 16) == 0 || (*mode & 8) != 0 ||
        !base || !pointer || !end || !storage || !capacity || *capacity > maxSafeInteger ||
        *pointer < *base || *end < *pointer ||
        (*base == 0 && (*pointer != 0 || *end != 0)) ||
        (*storage == 0 && *base != 0) ||
        (*storage != 0 && *capacity > std::numeric_limits<std::uint64_t>::max() - *storage) ||
        (*base != 0 && (*base < *storage || *end > *storage + *capacity)))
      return unavailable("cout-buffer-range-unavailable");
    const auto count = *pointer - *base;
    const auto window = *end - *base;
    const auto remaining = *end - *pointer;
    // unitbuf flushes after ostream operations, but the streambuf can still
    // have a put area. Keep physical capacity separate from flush policy.
    nlohmann::json result = {{"available", true}, {"source", "libstdc++-stdio_filebuf"},
        {"stream", "cout"}, {"association", "cout-unsynchronized"},
        {"mode", "full"}, {"flushPolicy", unitbuf ? "every-write" : "buffer-full-or-explicit"},
        {"pendingBytes", count}, {"writeWindowCapacityBytes", window},
        {"writeWindowRemainingBytes", remaining}, {"capacityBytes", window},
        {"remainingCapacityBytes", remaining},
        {"storageCapacityBytes", *storage != 0 ? nlohmann::json(*capacity) : nlohmann::json(nullptr)},
        {"metadataAvailable", true}, {"text", ""}, {"totalBytes", count},
        {"retainedFromByte", 0}, {"truncated", false}};
    return captureBufferText(std::move(result), *base, count, "cout");
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
    result.stdoutRaw = stdoutOutput;
    result.stderrRaw = stderrOutput;
    if (!result.exited && result.location.is_null()) {
      // An interrupt inside a flush can observe bytes already written into
      // the FIFO while the native put pointers still include them. Until
      // execution returns to submitted source, do not claim those windows
      // are disjoint from transported output. The caller location may later
      // be promoted for an input wait, but this decision uses the actual PC.
      const nlohmann::json unavailable = {{"available", false},
          {"reason", "output-state-unconfirmed-at-runtime-stop"}};
      result.stdoutBufferedSnapshot = unavailable;
      result.stdoutSnapshot["buffered"] = unavailable;
      result.stdoutSnapshot["coutBuffered"] = unavailable;
    } else if (!result.exited) {
      const auto buffered = captureBufferedStdout();
      // Keep the optional extension absent for a stop where stdout's runtime
      // buffer has not even been initialized. This preserves the v1 output
      // shape for ordinary programs while still reporting a confirmed empty
      // buffer after a real cout interaction (metadataAvailable=true).
      if (buffered.is_object() && buffered.contains("available") &&
          (!buffered.value("available", false) || buffered.value("pendingBytes", 0ULL) != 0 ||
           buffered.value("metadataAvailable", false))) {
        result.stdoutBufferedSnapshot = buffered;
        result.stdoutSnapshot["buffered"] = buffered;
      }
      result.stdoutSnapshot["coutBuffered"] = captureBufferedCout(buffered);
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
    if (r.type == '~' && captureConsole) {
      if (r.stream.size() > 1024u * 1024u - consoleOutput.size()) {
        failClosed(e, "LIMIT_EXCEEDED", "GDB console response exceeds the bounded command capture");
        return false;
      }
      consoleOutput += r.stream;
    }
    if ((r.type == '~' || r.type == '&') && captureRecordingDiagnostics) {
      constexpr std::size_t diagnosticLimit = 4096;
      if (r.stream.size() >= diagnosticLimit) recordingDiagnostics = r.stream.substr(r.stream.size() - diagnosticLimit);
      else {
        if (recordingDiagnostics.size() > diagnosticLimit - r.stream.size())
          recordingDiagnostics.erase(0, recordingDiagnostics.size() - (diagnosticLimit - r.stream.size()));
        recordingDiagnostics += r.stream;
      }
    }
    if (r.type == '=' && r.klass == "record-stopped") recordingActive = false;
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
    consoleOutput.clear();
    captureConsole = commandText == "-interpreter-exec console \"info record\"";
    captureRecordingDiagnostics = recordingActive && waitStop;
    if (waitStop) recordingDiagnostics.clear();
    if (waitStop) lastExecutionInterrupted = false;
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
    const bool reverseStep = commandText == "-exec-step-instruction --reverse";
    const bool seekingRecord = commandText.starts_with("-interpreter-exec console \"record goto ");
    const bool recoverableStep = waitStop &&
        (commandText == "-exec-next" || commandText == "-exec-step" ||
         commandText == "-exec-finish" || commandText == "-exec-step-instruction" || reverseStep);
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
      if (traceActive && !waitStop && mode == 1) {
        int idle = 0;
        (void)control.compare_exchange_strong(idle, 1);
      }
      if (((waitStop && running) || seekingRecord) && pendingInterrupt && !interruptSent) {
        if (seekingRecord) process->interrupt(); else interruptExecution();
        interruptSent = true;
        lastExecutionInterrupted = true;
      }
      if (waitStop && !reverseStep && running && !interruptSent && !pendingInterrupt &&
          (recoverableStep || commandText == "-exec-continue") &&
          std::chrono::steady_clock::now() >= nextInputProbe) {
        nextInputProbe = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        if (inputReadInProgress()) {
          interruptExecution();
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
      interruptExecution();
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

  bool resolveRegisters(const std::vector<std::string>& requested,
                        std::vector<std::pair<std::size_t, std::string>>& selection,
                        GdbError& error, bool includePc = false) {
    if (requested.size() > 64) {
      setError(error, "LIMIT_EXCEEDED", "at most 64 registers may be selected"); return false;
    }
    std::vector<std::string> names = requested;
    if (names.empty()) names = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"};
    for (std::size_t i = 0; i < names.size(); ++i) {
      if (names[i].empty() || names[i].size() > 64 ||
          names[i].find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != std::string::npos ||
          std::find(names.begin(), names.begin() + i, names[i]) != names.begin() + i) {
        setError(error, "INVALID_REQUEST", "register names must be unique plain names"); return false;
      }
    }
    if (registerNames.empty()) {
      MiRecord metadata;
      if (!command("-data-list-register-names", false, metadata, error)) return false;
      const auto* list = field(metadata.fields, "register-names");
      if (!list || list->values.empty() || list->values.size() > 4096) {
        setError(error, "READ_FAILED", "GDB returned invalid register metadata", true); return false;
      }
      for (const auto& name : list->values) registerNames.push_back(name ? name->text : "");
    }
    if (includePc && std::find(names.begin(), names.end(), "rip") == names.end()) names.push_back("rip");
    selection.clear();
    for (const auto& name : names) {
      const auto found = std::find(registerNames.begin(), registerNames.end(), name);
      if (found == registerNames.end()) {
        setError(error, "INVALID_REQUEST", "unknown register name: " + name); return false;
      }
      selection.emplace_back(static_cast<std::size_t>(found - registerNames.begin()), name);
    }
    return true;
  }

  bool captureRegisters(const std::vector<std::pair<std::size_t, std::string>>& selection,
                        nlohmann::json& result, GdbError& error) {
    std::string request = "-data-list-register-values x";
    for (const auto& [number, name] : selection) request += " " + std::to_string(number);
    MiRecord record;
    if (!command(request, false, record, error)) return false;
    std::map<std::size_t, std::string> values;
    const auto* list = field(record.fields, "register-values");
    if (!list) { setError(error, "READ_FAILED", "GDB omitted register values", true); return false; }
    const auto append = [&](const MiValue* value) {
      if (!value) return false;
      const auto number = parseUnsigned(valText(field(*value, "number")));
      if (!number || *number >= registerNames.size()) return false;
      return values.emplace(static_cast<std::size_t>(*number), valText(field(*value, "value"))).second;
    };
    for (const auto& value : list->values) if (!append(value.get())) {
      setError(error, "READ_FAILED", "GDB returned malformed register values", true); return false;
    }
    for (const auto& [key, value] : list->fields) if (!append(value.get())) {
      setError(error, "READ_FAILED", "GDB returned malformed register values", true); return false;
    }
    result = nlohmann::json::array();
    for (const auto& [number, name] : selection) {
      nlohmann::json value = {{"number", number}, {"name", name}, {"available", false}};
      const auto found = values.find(number);
      // Some vector/pseudo registers have a structured MI representation even
      // with format x. Never label that structure as raw hexadecimal bytes.
      if (found != values.end() && found->second.size() > 2 && found->second.size() <= 258 &&
          found->second.rfind("0x", 0) == 0 &&
          found->second.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos) {
        value["available"] = true;
        value["valueHex"] = found->second;
      } else {
        value["reason"] = found == values.end() ? "not-returned" : "non-hex-or-unavailable";
      }
      result.push_back(std::move(value));
    }
    return true;
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

  bool recordingSnapshot(nlohmann::json& result, GdbError& error) {
    result = {{"profile", recordingProfile}, {"available", false}};
    if (recordingProfile == "native") {
      result["reason"] = "recording-not-requested";
      return true;
    }
    if (!recordingActive) {
      result["reason"] = "recording-not-active";
      return true;
    }
    MiRecord response;
    if (!command("-interpreter-exec console \"info record\"", false, response, error)) {
      result["reason"] = "recording-state-unavailable";
      return false;
    }
    const auto transcript = consoleOutput;
    const auto counter = [&](std::string_view label) -> std::optional<std::uint64_t> {
      const auto begin = transcript.find(label);
      if (begin == std::string::npos) return std::nullopt;
      const auto first = begin + label.size();
      const auto end = transcript.find_first_not_of("0123456789", first);
      if (end == first) return std::nullopt;
      return parseUnsigned(std::string_view(transcript).substr(first, end - first));
    };
    const bool replay = transcript.find("\nReplay mode:\n") != std::string::npos;
    const bool record = transcript.find("\nRecord mode:\n") != std::string::npos;
    const bool empty = transcript.find("No instructions have been logged.") != std::string::npos;
    const auto maximum = counter("Max logged instructions is ");
    const auto first = empty ? std::optional<std::uint64_t>(0) : counter("Lowest recorded instruction number is ");
    const auto last = empty ? std::optional<std::uint64_t>(0) : counter("Highest recorded instruction number is ");
    const auto count = empty ? std::optional<std::uint64_t>(0) : counter("Log contains ");
    const auto current = replay ? counter("Current instruction number is ") : last;
    if (transcript.find("Active record target: record-full\n") == std::string::npos ||
        replay == record || !maximum || *maximum != maxRecordedInstructions ||
        !first || !last || !count || !current || *first > *last || *current > *last ||
        *count > *maximum || (!empty && (*first == 0 || *count != *last - *first + 1)) ||
        (*first > 1 && *current < *first)) {
      result["reason"] = "unrecognized-recording-state";
      error = {"READ_FAILED", "GDB returned an unrecognized record-full status", false};
      return false;
    }
    result = {{"profile", recordingProfile}, {"available", true},
        {"mode", replay ? "replay" : "record"}, {"currentInstruction", std::to_string(*current)},
        {"firstInstruction", std::to_string(*first)}, {"lastInstruction", std::to_string(*last)},
        {"earliestSeekableInstruction", std::to_string(*first > 1 ? *first : 0)},
        {"recordedInstructions", *count}, {"maxRecordedInstructions", *maximum},
        {"evicted", *first > 1},
        {"coverage", {{"registers", "gdb-record-full"}, {"memory", "gdb-record-full"},
                      {"externalEffects", "not-restored"}, {"instructionSupport", "target-dependent"},
                      {"osState", "current-process"}, {"inputTransport", "not-restored"}}}};
    return true;
  }

  // Console `record goto` emits no *stopped MI event. Independently verify
  // that every live thread is stopped, then obtain its actual current frame.
  // This also recovers record-full failures after an instruction unsupported
  // by GDB, which may return ^error without any subsequent *stopped event.
  bool verifiedStoppedRecord(MiRecord& stopped, std::string_view reason, GdbError& error) {
    MiRecord threads;
    if (!command("-thread-info", false, threads, error)) return false;
    const auto* entries = field(threads.fields, "threads");
    const auto thread = valText(field(threads.fields, "current-thread-id"));
    if (!entries || entries->values.empty() || thread.empty()) {
      error = {"READ_FAILED", "record operation did not leave a live stopped thread", true};
      return false;
    }
    for (const auto& entry : entries->values) {
      if (valText(field(*entry, "state")) != "stopped") {
        failClosed(error, "READ_FAILED", "record operation left an unconfirmed running thread");
        return false;
      }
    }
    MiRecord frame;
    if (!command("-stack-select-frame 0", false, frame, error) ||
        !command("-stack-info-frame", false, frame, error)) return false;
    const auto* value = field(frame.fields, "frame");
    if (!value) {
      error = {"READ_FAILED", "record operation returned no stopped frame", true};
      return false;
    }
    stopped = {};
    stopped.type = '*';
    stopped.klass = "stopped";
    stopped.fields = {{"reason", std::make_shared<MiValue>(MiValue::string_value(std::string(reason)))},
                      {"thread-id", std::make_shared<MiValue>(MiValue::string_value(thread))},
                      {"frame", std::make_shared<MiValue>(*value)}};
    return true;
  }

  bool makeStop(const MiRecord& stop, GdbStop& result, GdbError& e) {
    latestStop = stop;
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
    if (result.exited) {
      result.memoryMap = {{"available", false}, {"source", "linux-proc-maps"},
                          {"coverage", "none"}, {"regions", nlohmann::json::array()},
                          {"reason", "process-exited"}};
    } else {
      int pid = 0;
      const auto parsed = std::from_chars(inferiorPid.data(), inferiorPid.data() + inferiorPid.size(), pid);
      result.memoryMap = readLinuxMemoryMap(parsed.ec == std::errc{} &&
          parsed.ptr == inferiorPid.data() + inferiorPid.size() ? pid : 0);
    }
    // At an inferior stop its completed writes are already queued in the
    // kernel. Capture that backlog without a sleep or EOF heuristic.
    captureIo(result);
    if (recordingProfile != "native") {
      if (result.exited) {
        recordingActive = false;
        result.recording = {{"profile", recordingProfile}, {"available", false}, {"reason", "process-exited"}};
      } else {
        GdbError recordingError;
        (void)recordingSnapshot(result.recording, recordingError);
        if (!live.load()) { e = std::move(recordingError); return false; }
      }
    }
    result.raw = {{"reason", result.reason}, {"stack", result.stack}, {"location", result.location}};
    result.raw["exited"] = result.exited;
    if (result.exitCode) result.raw["exitCode"] = *result.exitCode;
    return true;
  }

  bool settleInputInterrupt(MiRecord& stopped, GdbError& error) {
    if ((error.code != "INPUT_CHECK" && error.code != "STEP_TIMEOUT") ||
        valText(field(stopped.fields, "reason")) != "end-stepping-range" || !interruptedInputRead()) return true;
    // Linux can report the syscall-exit single-step trap before the SIGINT
    // that interrupted this read. The pending signal must reach its ptrace
    // delivery stop before returning the wait to our caller; otherwise the
    // next Continue unexpectedly stops a second time. At this verified
    // restart boundary, signal delivery precedes another user instruction.
    // Still honor every actual returned breakpoint/signal instead of hiding
    // it if the target behaves differently.
    const auto interrupted = error;
    MiRecord signalStop;
    if (!command("-exec-step-instruction", true, signalStop, error)) return false;
    stopped = std::move(signalStop);
    if (valText(field(stopped.fields, "signal-name")) == "SIGINT") error = interrupted;
    else if (error.code.empty())
      error = {"READ_FAILED", "interrupted syscall did not reach the expected signal-delivery stop", true};
    return true;
  }

  bool finishExecutionStop(const MiRecord& stopped, GdbStop& result, GdbError& error) {
    // GDB may reject an instruction or a memory-recording operation using
    // diagnostics followed by *stopped,signal-name="0" rather than ^error.
    // Signal zero is not an inferior signal. Preserve its verified stop but
    // do not report a successfully completed source/instruction operation.
    if (recordingActive && error.code.empty() &&
        valText(field(stopped.fields, "reason")) == "signal-received" &&
        valText(field(stopped.fields, "signal-name")) == "0") {
      const bool unsupported = recordingDiagnostics.find("does not support") != std::string::npos ||
                               recordingDiagnostics.find("not supported") != std::string::npos;
      error = {unsupported ? "UNSUPPORTED" : "READ_FAILED",
               "record-full could not record the next instruction" +
                   (recordingDiagnostics.empty() ? std::string{} : ": " + displayUtf8(recordingDiagnostics)), false};
    }
    const bool incompleteStep = error.code == "STEP_TIMEOUT";
    const bool inputCandidate = error.code == "INPUT_CHECK" || incompleteStep;
    // Single-stepping a blocking syscall may acknowledge our interrupt as an
    // end-stepping-range rather than a SIGINT stop. Both still need the same
    // kernel restart-register and owned-stdin-FIFO evidence.
    const auto stopReason = valText(field(stopped.fields, "reason"));
    const bool inputWait = inputCandidate &&
        (valText(field(stopped.fields, "signal-name")) == "SIGINT" ||
         (error.code == "INPUT_CHECK" && stopReason == "end-stepping-range")) && interruptedInputRead();
    if (error.code == "INPUT_CHECK" && !inputWait) error = {};
    GdbError snapshotError;
    if (!makeStop(stopped, result, snapshotError)) { error = std::move(snapshotError); return false; }
    if (process) result.processInstanceId = inferiorPid.empty() ? std::to_string(process->pid()) : inferiorPid;
    if (inputWait && result.stopped && !result.exited) {
      inputWaitActive = true;
      inputWaitFrame = -1;
      inputWaitLocation = nullptr;
      result.reason = "input-wait";
      result.signalName.clear();
      for (const auto& frame : result.stack) {
        const auto location = frame.value("location", nlohmann::json(nullptr));
        if (location.is_null()) continue;
        const auto id = frame.value("id", std::string{});
        const auto colon = id.find(':');
        if (colon == std::string::npos) continue;
        try { inputWaitFrame = std::stoi(id.substr(colon + 1)); } catch (...) { continue; }
        inputWaitLocation = location;
        if (result.location.is_null()) result.location = location;
        break;
      }
      error = {"INPUT_WAIT", "program is waiting for stdin; provide input to continue", true};
      return false;
    }
    return !incompleteStep && error.code.empty();
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
    if (request.recordingProfile == "gdb-record-full") po.environment.emplace_back("LC_ALL", "C");
    // MI belongs to an unbounded-duration conversation. Retaining already
    // consumed replies would eventually kill a healthy debugging session.
    // Process bounds each poll; command() bounds individual MI records.
    po.capture_output = false;
    try { std::lock_guard lock(processMutex); process = std::make_unique<Process>(Process::spawn(po)); }
    catch (const std::exception& ex) { setError(e, "LAUNCH_FAILED", ex.what()); return false; }
    live = true;
    auto setup = [&](std::string_view c) { MiRecord ignored; return command(c, false, ignored, e); };
    if (!setup("-gdb-set pagination off") || !setup("-gdb-set confirm off") ||
        !setup(request.disableRandomization ? "-gdb-set disable-randomization on" :
                                             "-gdb-set disable-randomization off") ||
        // Address/sizeof probes are intentionally non-evaluating.  Refuse
        // any fallback that would invoke a user function or overloaded call.
        !setup("-gdb-set may-call-functions off") || !setup("-gdb-set overload-resolution off") ||
        !setup("-gdb-set startup-with-shell on") || !setup("-gdb-set print pretty off") ||
        !setup("-gdb-set print elements 128") ||
        !setup("-interpreter-exec console " + miQuote("set inferior-tty " + ptyPath.string()))) return false;
    if (request.recordingProfile == "gdb-record-full" &&
        (!setup("-interpreter-exec console \"unset environment LC_ALL\"") ||
         !setup("-gdb-set mi-async off") || !setup("-gdb-set non-stop off") ||
         !setup("-interpreter-exec console \"set record full stop-at-limit off\"") ||
         !setup("-interpreter-exec console \"set record full memory-query on\"") ||
         !setup("-interpreter-exec console " + miQuote("set record full insn-number-max " +
              std::to_string(request.maxRecordedInstructions))))) return false;
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
  result = {};
  error = {};
  if (request.recordingProfile != "native" && request.recordingProfile != "gdb-record-full") {
    error = {"UNSUPPORTED", "unknown recording profile", false}; return false;
  }
  if (request.recordingProfile == "gdb-record-full" &&
      (!request.stopAtEntry || !request.closeInputAfterWrite ||
       request.maxRecordedInstructions == 0 || request.maxRecordedInstructions > 1000000)) {
    error = {"INVALID_REQUEST", "record-full requires entry stop, finite initial stdin and a 1..1000000 instruction limit", false};
    return false;
  }
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
  impl_->latestStop = {};
  impl_->registerNames.clear();
  impl_->traceActive = false;
  impl_->recordingProfile = request.recordingProfile;
  impl_->maxRecordedInstructions = request.maxRecordedInstructions;
  impl_->recordingActive = false;
  impl_->sourceBundle = request.sourceBundle;
  if (!impl_->prepareTemp(request, error)) return false;
  if (!impl_->startGdb(request, error)) { stop(); return false; }
  if (request.stopAtEntry) {
    MiRecord entryBreakpoint;
    if (!impl_->command("-break-insert -t -f main", false, entryBreakpoint, error)) { stop(); return false; }
  }
  MiRecord stopped;
  if (!impl_->command("-exec-run", true, stopped, error)) { stop(); return false; }
  if (request.recordingProfile == "gdb-record-full") {
    if (impl_->inferiorPidFd < 0) {
      error = {"LAUNCH_FAILED", "record-full requires pidfd support for reliable inferior interruption", false};
      stop(); return false;
    }
    MiRecord started;
    if (!impl_->command("-interpreter-exec console \"record full\"", false, started, error)) {
      error.code = "LAUNCH_FAILED";
      stop(); return false;
    }
    impl_->recordingActive = true;
    nlohmann::json status;
    if (!impl_->recordingSnapshot(status, error) || !status.value("available", false)) {
      if (error.code.empty()) error = {"LAUNCH_FAILED", "record-full did not become active", false};
      stop(); return false;
    }
  }
  if (!impl_->makeStop(stopped, result, error)) { stop(); return false; }
  result.processInstanceId = impl_->inferiorPid.empty() ? std::to_string(impl_->process->pid()) : impl_->inferiorPid;
  return true;
}

bool GdbEngine::appendInput(std::string_view id, std::string_view text,
                            nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  if (impl_->recordingProfile != "native") {
    error = {"UNSUPPORTED", "record-full uses immutable finite initial stdin", false}; return false;
  }
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
  if (impl_->recordingProfile != "native") {
    error = {"UNSUPPORTED", "record-full uses immutable finite initial stdin", false}; return false;
  }
  std::lock_guard inputLock(impl_->inputMutex);
  if (!impl_->live.load() || impl_->control.load() >= 2) { error = {"STALE_CONTEXT", "no live inferior", false}; return false; }
  impl_->closeInputAfterWrite = true;
  impl_->feedInputLocked();
  result = impl_->inputSnapshotLocked();
  return true;
}

bool GdbEngine::resume(std::string_view stepKind, GdbStop& result, GdbError& error) {
  result = {};
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
    if (impl_->recordingActive && live()) {
      const auto executionError = error;
      GdbError recoveryError;
      if (impl_->verifiedStoppedRecord(stopped, "recording-error", recoveryError) &&
          impl_->makeStop(stopped, result, recoveryError)) {
        result.processInstanceId = impl_->inferiorPid;
        error = executionError;
      } else if (!live()) error = recoveryError;
    }
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
  if (!impl_->settleInputInterrupt(stopped, error)) return false;
  return impl_->finishExecutionStop(stopped, result, error);
}

bool GdbEngine::readRecording(nlohmann::json& result, GdbError& error) {
  if (!live()) { error = {"STALE_CONTEXT", "no live debugger", false}; return false; }
  error = {};
  return impl_->recordingSnapshot(result, error);
}

bool GdbEngine::reverseInstruction(GdbStop& result, GdbError& error) {
  result = {};
  impl_->traceActive = true;
  struct Reset { bool& flag; ~Reset() { flag = false; } } reset{impl_->traceActive};
  nlohmann::json status;
  if (!readRecording(status, error)) return false;
  if (!status.value("available", false)) {
    error = {"UNSUPPORTED", "reverse instruction requires an active record-full profile", false}; return false;
  }
  const auto current = parseUnsigned(status.at("currentInstruction").get<std::string>());
  const auto earliest = parseUnsigned(status.at("earliestSeekableInstruction").get<std::string>());
  if (*current <= *earliest) {
    error = {"INVALID_REQUEST", "already at the earliest retained instruction boundary", false}; return false;
  }
  const int control = impl_->control.exchange(0);
  if (control >= 2) {
    impl_->traceActive = false;
    result = stopAndSnapshot();
    error = {"CANCELLED", "reverse instruction stopped", true}; return false;
  }
  MiRecord stopped;
  if (control == 1) {
    if (impl_->verifiedStoppedRecord(stopped, "interrupted", error) && impl_->makeStop(stopped, result, error))
      result.processInstanceId = impl_->inferiorPid;
    if (error.code.empty()) error = {"CANCELLED", "reverse instruction interrupted before execution", true};
    return false;
  }
  const bool executed = impl_->command("-exec-step-instruction --reverse", true, stopped, error);
  if (!executed) {
    if (!live()) return false;
    const auto executionError = error;
    GdbError recoveryError;
    if (impl_->verifiedStoppedRecord(stopped, "recording-error", recoveryError) &&
        impl_->makeStop(stopped, result, recoveryError)) result.processInstanceId = impl_->inferiorPid;
    error = !live() ? recoveryError : executionError;
    return false;
  }
  impl_->inputWaitActive = false;
  return impl_->finishExecutionStop(stopped, result, error);
}

bool GdbEngine::seekRecording(std::uint64_t instruction, GdbStop& result, GdbError& error) {
  result = {};
  impl_->traceActive = true;
  struct Reset { bool& flag; ~Reset() { flag = false; } } reset{impl_->traceActive};
  nlohmann::json status;
  if (!readRecording(status, error)) return false;
  if (!status.value("available", false)) {
    error = {"UNSUPPORTED", "record seek requires an active record-full profile", false}; return false;
  }
  const auto earliest = parseUnsigned(status.at("earliestSeekableInstruction").get<std::string>());
  const auto last = parseUnsigned(status.at("lastInstruction").get<std::string>());
  if (instruction < *earliest || instruction > *last) {
    error = {"INVALID_REQUEST", "instruction boundary is outside the retained recording", false}; return false;
  }
  const int control = impl_->control.exchange(0);
  if (control >= 2) {
    impl_->traceActive = false;
    result = stopAndSnapshot();
    error = {"CANCELLED", "record seek stopped", true}; return false;
  }
  MiRecord response;
  if (control == 1) {
    if (impl_->verifiedStoppedRecord(response, "interrupted", error) && impl_->makeStop(response, result, error))
      result.processInstanceId = impl_->inferiorPid;
    if (error.code.empty()) error = {"CANCELLED", "record seek interrupted before execution", true};
    return false;
  }
  // GDB rejects `record goto` at the existing cursor as "Already at target
  // insn", including an empty log. Treat the verified no-op as successful.
  const bool unchanged = status.at("currentInstruction") == std::to_string(instruction);
  const bool moved = unchanged || impl_->command("-interpreter-exec console " +
      miQuote("record goto " + std::to_string(instruction)), false, response, error);
  if (!live()) return false;
  const auto executionError = error;
  GdbError recoveryError;
  MiRecord stopped;
  if (!impl_->verifiedStoppedRecord(stopped, moved ? "recording-seek" : "recording-error", recoveryError) ||
      !impl_->makeStop(stopped, result, recoveryError)) {
    error = recoveryError;
    return false;
  }
  result.processInstanceId = impl_->inferiorPid;
  impl_->inputWaitActive = false;
  if (!moved) { error = executionError; return false; }
  if (!result.recording.value("available", false) ||
      result.recording.value("currentInstruction", "") != std::to_string(instruction)) {
    error = {"READ_FAILED", "record seek did not reach the requested instruction boundary", true}; return false;
  }
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
std::optional<int> GdbEngine::inferiorPid() const noexcept {
  if (!live()) return std::nullopt;
  const auto reason = valText(field(impl_->latestStop.fields, "reason"));
  if (reason.rfind("exited", 0) == 0 || impl_->latestStop.klass.rfind("exited", 0) == 0)
    return std::nullopt;
  int pid = 0;
  const auto& text = impl_->inferiorPid;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), pid);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && pid > 0 ?
      std::optional<int>(pid) : std::nullopt;
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
  const auto address = parseAddress(addressHex);
  if (!address || *address > std::numeric_limits<std::uint64_t>::max() - byteCount) {
    error = {"INVALID_REQUEST", "invalid or overflowing memory address", false}; return false;
  }
  // Canonicalize parsed addresses: a bare hexadecimal input must never become
  // a GDB identifier/expression merely because it omits the 0x prefix.
  std::ostringstream canonical;
  canonical << "0x" << std::hex << *address;
  std::string bytes;
  const long nativePageSize = ::sysconf(_SC_PAGESIZE);
  if (nativePageSize <= 0) { error = {"READ_FAILED", "cannot determine OS page size", true}; return false; }
  const auto pageSize = static_cast<std::size_t>(nativePageSize);
  while (bytes.size() < byteCount) {
    const auto chunkAddress = *address + bytes.size();
    const auto chunkSize = std::min(byteCount - bytes.size(), pageSize - static_cast<std::size_t>(chunkAddress % pageSize));
    std::ostringstream chunkHex;
    chunkHex << "0x" << std::hex << chunkAddress;
    MiRecord rec;
    if (!impl_->command("-data-read-memory-bytes " + chunkHex.str() + " " + std::to_string(chunkSize), false, rec, error)) {
      if (bytes.empty() || !live() || error.code != "READ_FAILED") return false;
      error = {};
      break;
    }
    std::map<std::uint64_t, std::string> blocks;
    if (const MiValue* memory = field(rec.fields, "memory")) {
      const auto appendCell = [&](const MiValue* cell) {
        if (!cell) return false;
        const auto begin = parseAddress(valText(field(*cell, "begin")));
        const auto end = parseAddress(valText(field(*cell, "end")));
        std::string contents;
        if (!begin || !end || *begin < chunkAddress || *end < *begin || *end > chunkAddress + chunkSize ||
            !appendHexBytes(valText(field(*cell, "contents")), contents) || *end - *begin != contents.size()) return false;
        if (const auto* offset = field(*cell, "offset")) {
          const auto parsed = parseUnsigned(offset->text);
          if (!parsed || *parsed != *begin - chunkAddress) return false;
        }
        return blocks.emplace(*begin, std::move(contents)).second;
      };
      for (const auto& cell : memory->values) if (!appendCell(cell.get())) {
        error = {"READ_FAILED", "GDB returned malformed memory block bounds or bytes", true}; return false;
      }
      for (const auto& [key, cell] : memory->fields) if (!appendCell(cell.get())) {
        error = {"READ_FAILED", "GDB returned malformed memory block bounds or bytes", true}; return false;
      }
    }
    // Some GDB versions report a stray byte beyond the readable prefix when
    // one MI request straddles an unmapped page. Query each OS page separately
    // and retain only a verified contiguous prefix, never joining islands.
    std::uint64_t next = chunkAddress;
    for (const auto& [begin, contents] : blocks) {
      if (begin > next) break;
      if (begin < next) { error = {"READ_FAILED", "GDB returned overlapping memory blocks", true}; return false; }
      bytes += contents;
      next += contents.size();
    }
    if (next != chunkAddress + chunkSize) break;
  }
  result = {{"addressHex", canonical.str()}, {"bytesBase64", base64(bytes)},
            {"unreadableBytes", byteCount - bytes.size()}};
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

bool GdbEngine::readRegisters(const std::vector<std::string>& names,
                              nlohmann::json& result, GdbError& error) {
  error = {};
  if (!inferiorPid()) { error = {"INVALID_REQUEST", "no stopped inferior", false}; return false; }
  std::vector<std::pair<std::size_t, std::string>> selection;
  if (!impl_->resolveRegisters(names, selection, error)) return false;
  MiRecord selected;
  if (!impl_->command("-stack-select-frame 0", false, selected, error)) return false;
  impl_->selectedFrame = 0;
  nlohmann::json registers;
  if (!impl_->captureRegisters(selection, registers, error)) return false;
  result = {{"architecture", "x86_64"}, {"registers", std::move(registers)}};
  return true;
}

bool GdbEngine::traceInstructions(std::size_t count,
                                  const std::vector<std::string>& registerNames,
                                  const nlohmann::json& memoryRanges,
                                  GdbStop& finalStop, nlohmann::json& trace,
                                  GdbError& error) {
  error = {};
  finalStop = {};
  trace = {{"requestedInstructions", count}, {"executedInstructions", 0}, {"attemptedInstructions", 0},
           {"status", "failed"}, {"terminationReason", "not-started"},
           {"coverage", {{"registers", "selected-instruction-boundaries"},
                         {"memory", "selected-instruction-boundaries"},
                         {"sameValueWrites", false}, {"otherThreads", "not-recorded"}}},
           {"initialRegisters", nlohmann::json::array()}, {"initialMemory", nlohmann::json::array()},
           {"entries", nlohmann::json::array()}};
  if (!inferiorPid()) { error = {"INVALID_REQUEST", "no stopped inferior", false}; return false; }
  if (count == 0 || count > std::min<std::size_t>(256, impl_->options.maxInstructions)) {
    error = {"LIMIT_EXCEEDED", "instruction trace count must be between 1 and the configured limit (at most 256)", false};
    return false;
  }
  if (!memoryRanges.is_array() || memoryRanges.size() > 8) {
    error = {"INVALID_REQUEST", "trace memory ranges must be an array of at most eight ranges", false}; return false;
  }
  std::vector<std::pair<std::string, std::size_t>> ranges;
  std::size_t bytes = 0;
  for (const auto& range : memoryRanges) {
    if (!range.is_object() || !range.contains("addressHex") || !range["addressHex"].is_string() ||
        !range.contains("byteCount") || !range["byteCount"].is_number_integer() ||
        range["byteCount"] <= 0 || range["byteCount"] > 4096) {
      error = {"INVALID_REQUEST", "trace ranges require a hexadecimal address and positive bounded byte count", false};
      return false;
    }
    const auto address = parseAddress(range["addressHex"].get<std::string>());
    const auto size = range["byteCount"].get<std::size_t>();
    if (!address || *address > std::numeric_limits<std::uint64_t>::max() - size) {
      error = {"INVALID_REQUEST", "invalid or overflowing trace memory range", false}; return false;
    }
    bytes += size;
    if (bytes > 4096 || size > impl_->options.maxMemoryReadBytes) {
      error = {"LIMIT_EXCEEDED", "trace memory ranges exceed the 4096-byte observation budget", false}; return false;
    }
    std::ostringstream hex;
    hex << "0x" << std::hex << *address;
    ranges.emplace_back(hex.str(), size);
  }
  impl_->traceActive = true;
  struct ResetTrace { bool& active; ~ResetTrace() { active = false; } } reset{impl_->traceActive};
  std::vector<std::pair<std::size_t, std::string>> selection;
  if (!impl_->resolveRegisters(registerNames, selection, error, true)) return false;
  MiRecord selected;
  if (!impl_->command("-stack-select-frame 0", false, selected, error)) return false;
  impl_->selectedFrame = 0;
  nlohmann::json beforeRegisters;
  if (!impl_->captureRegisters(selection, beforeRegisters, error)) return false;
  GdbError rangeCaptureError;
  const auto readRanges = [&](bool exited) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [address, size] : ranges) {
      nlohmann::json captured;
      GdbError localError;
      if (!exited && readMemory(address, size, captured, localError)) {
        captured["available"] = captured.value("unreadableBytes", size) == 0;
        if (!captured["available"].get<bool>()) captured["reason"] = "partial-read";
      } else {
        if (!exited && !live() && rangeCaptureError.code.empty()) rangeCaptureError = localError;
        captured = {{"addressHex", address}, {"available", false},
                    {"unreadableBytes", size}, {"reason", exited ? "process-exited" : "read-failed"}};
      }
      captured["byteCount"] = size;
      result.push_back(std::move(captured));
    }
    return result;
  };
  auto beforeMemory = readRanges(false);
  if (!live()) {
    error = rangeCaptureError.code.empty() ? GdbError{"READ_FAILED", "debugger failed during initial trace capture", true} : rangeCaptureError;
    return false;
  }
  trace["initialRegisters"] = beforeRegisters;
  trace["initialMemory"] = beforeMemory;
  const auto pc = [](const nlohmann::json& registers) -> nlohmann::json {
    for (const auto& reg : registers)
      if (reg.value("name", "") == "rip" && reg.value("available", false)) return reg.at("valueHex");
    return nullptr;
  };
  MiRecord lastStop = impl_->latestStop;
  GdbError executionError;
  const auto deadline = std::chrono::steady_clock::now() + impl_->options.commandTimeout;
  trace["status"] = "complete";
  trace["terminationReason"] = "count-reached";
  for (std::size_t instruction = 0; instruction < count; ++instruction) {
    const int control = impl_->control.exchange(0);
    if (control >= 2) {
      impl_->traceActive = false;
      finalStop = stopAndSnapshot();
      trace["status"] = "terminated";
      trace["terminationReason"] = "cancelled";
      error = {"CANCELLED", "instruction trace stopped", true};
      return false;
    }
    if (control == 1) {
      trace["status"] = "terminated";
      trace["terminationReason"] = "interrupted";
      break;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      trace["status"] = "terminated";
      trace["terminationReason"] = "timeout";
      executionError = {"TIMEOUT", "instruction trace reached its command budget at a stopped boundary", true};
      break;
    }
    MiRecord stopped;
    impl_->inputWaitActive = false;
    trace["attemptedInstructions"] = instruction + 1;
    if (!impl_->command("-exec-step-instruction", true, stopped, executionError)) {
      trace["status"] = "failed";
      trace["terminationReason"] = executionError.code;
      if (impl_->recordingActive && live()) {
        GdbError recoveryError;
        if (impl_->verifiedStoppedRecord(stopped, "recording-error", recoveryError)) lastStop = stopped;
        else if (!live()) executionError = recoveryError;
      }
      break;
    }
    const bool externallyInterrupted = impl_->lastExecutionInterrupted;
    if (externallyInterrupted && executionError.code.empty() &&
        valText(field(stopped.fields, "reason")) == "end-stepping-range" && impl_->interruptedInputRead())
      executionError = {"INPUT_CHECK", "interrupted a pending stdin read", true};
    if (!impl_->settleInputInterrupt(stopped, executionError)) {
      trace["status"] = "failed";
      trace["terminationReason"] = executionError.code;
      break;
    }
    lastStop = stopped;
    const auto reason = valText(field(stopped.fields, "reason"));
    const bool exited = reason.rfind("exited", 0) == 0 || stopped.klass.rfind("exited", 0) == 0;
    const bool completed = reason == "end-stepping-range" && executionError.code.empty() && !externallyInterrupted;
    if (completed) trace["executedInstructions"] = trace["executedInstructions"].get<std::size_t>() + 1;
    nlohmann::json afterRegisters = beforeRegisters;
    GdbError captureError;
    if (exited || !impl_->captureRegisters(selection, afterRegisters, captureError)) {
      afterRegisters = nlohmann::json::array();
      for (const auto& [number, name] : selection)
        afterRegisters.push_back({{"number", number}, {"name", name}, {"available", false},
                                  {"reason", exited ? "process-exited" : "read-failed"}});
    }
    auto afterMemory = readRanges(exited || !live());
    nlohmann::json registerChanges = nlohmann::json::array();
    for (std::size_t i = 0; i < beforeRegisters.size(); ++i)
      if (beforeRegisters[i] != afterRegisters[i])
        registerChanges.push_back({{"name", beforeRegisters[i]["name"]},
                                   {"before", beforeRegisters[i]}, {"after", afterRegisters[i]}});
    nlohmann::json memoryChanges = nlohmann::json::array();
    for (std::size_t i = 0; i < beforeMemory.size(); ++i)
      if (beforeMemory[i] != afterMemory[i])
        memoryChanges.push_back({{"addressHex", ranges[i].first}, {"byteCount", ranges[i].second},
                                 {"before", beforeMemory[i]}, {"after", afterMemory[i]}});
    trace["entries"].push_back({{"ordinal", instruction + 1}, {"pcBeforeHex", pc(beforeRegisters)},
                               {"pcAfterHex", pc(afterRegisters)}, {"registerChanges", std::move(registerChanges)},
                               {"memoryChanges", std::move(memoryChanges)}, {"reason", reason},
                               {"instructionCompleted", completed}});
    beforeRegisters = std::move(afterRegisters);
    beforeMemory = std::move(afterMemory);
    if (!completed || !captureError.code.empty() || !live()) {
      trace["status"] = "terminated";
      trace["terminationReason"] = !executionError.code.empty() ? executionError.code :
          externallyInterrupted ? "interrupted" :
          exited ? "exit" : !captureError.code.empty() ? "capture-failed" : reason;
      if (!captureError.code.empty() && executionError.code.empty()) executionError = captureError;
      if (!rangeCaptureError.code.empty() && executionError.code.empty()) executionError = rangeCaptureError;
      break;
    }
  }
  impl_->traceActive = false;
  error = executionError;
  if (!live()) return false;
  const bool finished = impl_->finishExecutionStop(lastStop, finalStop, error);
  if (error.code == "INPUT_WAIT") trace["terminationReason"] = "input-wait";
  else if (error.code == "STEP_TIMEOUT") trace["terminationReason"] = "timeout";
  else if (impl_->recordingActive && !finished && !error.code.empty()) {
    trace["status"] = "failed";
    trace["terminationReason"] = error.code;
  }
  if (!finished && trace["status"] == "complete") {
    trace["status"] = "failed";
    trace["terminationReason"] = error.code;
  }
  return finished;
}

bool GdbEngine::writeVariable(std::string_view, const nlohmann::json&,
                              nlohmann::json&, GdbError& error) {
  error = {"UNSUPPORTED", "writing variables is disabled: evaluating a C++ assignment can execute user code", false};
  return false;
}

}  // namespace phantom
