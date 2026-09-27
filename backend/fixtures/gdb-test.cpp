#include <cstring>
#include <iostream>
#include <unistd.h>

// Keep this function out of main so the regression can select a nonzero
// stack frame before reusing the same engine for another launch.
__attribute__((noinline)) void waitForever(int marker) {
  (void)::write(STDOUT_FILENO, "loop-out\n", 9);
  (void)::write(STDERR_FILENO, "loop-err\n", 9);
  for (;;) {  // GDB_TEST_LOOP_BREAKPOINT
    asm volatile("" : : "r"(marker) : "memory");
    ::usleep(10000);
  }
}

__attribute__((noinline)) void pendingOutput() {
  std::cout << "pending\n";
  volatile unsigned long pendingCounter = 0;
  for (;;) {  // GDB_TEST_PENDING_LOOP
    ++pendingCounter;
    asm volatile("" : : "r"(pendingCounter) : "memory");
  }
}

int main(int argc, char** argv) {
  if (argc > 1 && std::strcmp(argv[1], "cout-pending") == 0) {
    pendingOutput();
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
