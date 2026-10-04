#include <cstring>
#include <cstdio>
#include <csignal>
#include <iostream>
#include <sstream>
#include <ext/stdio_filebuf.h>
#include <unistd.h>

struct StorageFixture {
  int x;
  unsigned int u;
};

class DoublingCodecvt final : public std::codecvt<char, char, std::mbstate_t> {
 protected:
  bool do_always_noconv() const noexcept override { return false; }
  int do_encoding() const noexcept override { return 2; }
  int do_max_length() const noexcept override { return 2; }
  result do_out(state_type&, const char* from, const char* fromEnd, const char*& fromNext,
                char* to, char* toEnd, char*& toNext) const override {
    fromNext = from;
    toNext = to;
    while (fromNext != fromEnd && toEnd - toNext >= 2) {
      *toNext++ = *fromNext;
      *toNext++ = *fromNext++;
    }
    return fromNext == fromEnd ? ok : partial;
  }
  result do_unshift(state_type&, char* to, char*, char*& toNext) const override {
    toNext = to;
    return ok;
  }
};

__attribute__((noinline)) void streambufCheckpoint(int phase) {
  asm volatile("" : : "r"(phase) : "memory");  // GDB_TEST_STREAMBUF_CHECKPOINT
}

void streambufOutput(const char* mode) {
  const bool synchronized = std::strcmp(mode, "streambuf-sync") == 0 ||
      std::strcmp(mode, "streambuf-sync-unitbuf") == 0 ||
      std::strcmp(mode, "streambuf-sink-sync") == 0;
  if (!synchronized) std::ios::sync_with_stdio(false);
  // libstdc++ does not switch an already independent buffer back to C stdio.
  if (std::strcmp(mode, "streambuf-resync") == 0) std::ios::sync_with_stdio(true);
  if (std::strcmp(mode, "streambuf-library-stop") == 0) {
    std::cout << "pending-cout";
    std::printf("pending-C");
    std::raise(SIGSTOP);
    streambufCheckpoint(1);
    std::cout.flush();
    std::fflush(stdout);
    return;
  }
  if (std::strcmp(mode, "streambuf-codecvt") == 0) {
    std::cout.imbue(std::locale(std::locale::classic(), new DoublingCodecvt));
    std::cout << "ab";
    std::printf("C-only");
    streambufCheckpoint(1);
    std::cout.flush();
    streambufCheckpoint(2);
    std::cout.imbue(std::locale::classic());
    streambufCheckpoint(3);
    std::fflush(stdout);
    return;
  }
  if (std::strncmp(mode, "streambuf-sink-", 15) == 0) {
    const int original = ::dup(STDOUT_FILENO);
    FILE* file = std::tmpfile();
    if (original < 0 || !file || ::dup2(::fileno(file), STDOUT_FILENO) < 0) std::abort();
    std::cout << "private-cout";
    std::printf("private-C");
    streambufCheckpoint(1);
    std::cout.flush();
    std::fflush(stdout);
    if (::dup2(original, STDOUT_FILENO) < 0) std::abort();
    ::close(original);
    std::fclose(file);
    streambufCheckpoint(2);
    std::cout << "restored" << std::flush;
    streambufCheckpoint(3);
    return;
  }
  if (std::strcmp(mode, "streambuf-custom") == 0) {
    std::ostringstream capture;
    auto* original = std::cout.rdbuf(capture.rdbuf());
    std::cout << "private-capture";
    std::printf("C-only");
    streambufCheckpoint(1);
    std::cout.rdbuf(original);
    return;
  }
  if (std::strcmp(mode, "streambuf-null") == 0) {
    auto* original = std::cout.rdbuf(nullptr);
    streambufCheckpoint(1);
    std::cout.rdbuf(original);
    return;
  }
  if (std::strcmp(mode, "streambuf-redirected") == 0) {
    FILE* file = std::tmpfile();
    if (!file) std::abort();
    {
      __gnu_cxx::stdio_filebuf<char> redirected(file, std::ios::out);
      auto* original = std::cout.rdbuf(&redirected);
      std::cout << "private-file";
      streambufCheckpoint(1);
      std::cout.rdbuf(original);
    }
    std::fclose(file);
    return;
  }
  if (std::strcmp(mode, "streambuf-empty") == 0) {
    streambufCheckpoint(1);
    return;
  }
  if (std::strcmp(mode, "streambuf-unitbuf") == 0 ||
      std::strcmp(mode, "streambuf-sync-unitbuf") == 0) std::cout << std::unitbuf;
  if (std::strcmp(mode, "streambuf-large") == 0) {
    for (int i = 0; i < 7000; ++i) std::cout.put('x');
  } else {
    std::cout << "C++\xf0\x9f\x98\x80\xd0\x96\n";
  }
  std::printf("C-only");
  streambufCheckpoint(1);
  std::cout << std::flush;
  streambufCheckpoint(2);
  std::fflush(stdout);
  streambufCheckpoint(3);
}

// Keep this function out of main so the regression can select a nonzero
// stack frame before reusing the same engine for another launch.
__attribute__((noinline)) void waitForever(int marker) {
  StorageFixture aggregate{7, 0xa5a5a5a5u};
  (void)::write(STDOUT_FILENO, "loop-out\n", 9);
  (void)::write(STDERR_FILENO, "loop-err\n", 9);
  for (;;) {  // GDB_TEST_LOOP_BREAKPOINT
    asm volatile("" : : "r"(marker), "r"(aggregate.x), "r"(aggregate.u) : "memory");
    ::usleep(10000);
  }
}

__attribute__((noinline)) void pendingOutput(const char* mode) {
  if (std::strcmp(mode, "cout-line") == 0) {
    (void)::setvbuf(stdout, nullptr, _IOLBF, BUFSIZ);
    std::cout << "line";
  } else if (std::strcmp(mode, "cout-unbuffered") == 0) {
    (void)::setvbuf(stdout, nullptr, _IONBF, 0);
    std::cout << "direct";
  } else if (std::strcmp(mode, "cout-full") == 0) {
    // Linux/glibc allocates a 4096-byte stdout window for this FIFO. Keep
    // the fixture independent of the BUFSIZ macro (which is 8192 here).
    for (int i = 0; i < 4097; ++i) std::cout << 'x';
  } else if (std::strcmp(mode, "cout-boundary") == 0) {
    for (int i = 0; i < 4095; ++i) std::cout << 'x';
  } else if (std::strcmp(mode, "cout-empty") != 0) {
    std::cout << "pending\n";
  }
  volatile unsigned long pendingCounter = 0;
  for (;;) {  // GDB_TEST_PENDING_LOOP
    ++pendingCounter;
    asm volatile("" : : "r"(pendingCounter) : "memory");
  }
}

int main(int argc, char** argv) {
  if (argc > 1 && std::strncmp(argv[1], "streambuf-", 10) == 0) {
    streambufOutput(argv[1]);
    return 0;
  }
  if (argc > 1 && (std::strncmp(argv[1], "cout-", 5) == 0)) {
    pendingOutput(argv[1]);
    return 0;
  }
  if (argc > 1 && std::strcmp(argv[1], "utf8") == 0) {
    const char out[] = "ab\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80"
                       "\xf0\x9f\x98\x80\xf0\x9f\x98\x80";
    const char err[] = "123456789\xff\xfe\xf0\x9f\x98\x80";
    (void)::write(STDOUT_FILENO, out, sizeof(out) - 1);
    (void)::write(STDERR_FILENO, err, sizeof(err) - 1);
    return 0;
  }
  waitForever(42);
}
