#include <cstring>
#include <cstdio>
#include <iostream>
#include <unistd.h>

struct StorageFixture {
  int x;
  unsigned int u;
};

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
