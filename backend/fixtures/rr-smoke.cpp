#include <cstdio>

int phantom_rr_total = 0;

// Two stable breakpoint locations let the Linux agent check real reverse travel.
// Build at -O0; this fixture has no dependency on the phantom backend executable.
#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline))
#endif
void phantom_checkpoint() {}

int main() {
  phantom_rr_total = 5;
  phantom_checkpoint();
  phantom_rr_total += 7;
  phantom_checkpoint();
  std::printf("total=%d\n", phantom_rr_total);
  return phantom_rr_total == 12 ? 0 : 1;
}
