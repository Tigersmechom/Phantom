#include <cstdio>

extern "C" {
volatile unsigned int phantom_recorder_probe_value = 0;

#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline))
#endif
void phantom_recorder_probe_checkpoint() {
#if defined(__clang__) || defined(__GNUC__)
  asm volatile("" ::: "memory");
#endif
}

#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline))
#endif
void phantom_recorder_probe_final_checkpoint() {
#if defined(__clang__) || defined(__GNUC__)
  asm volatile("" ::: "memory");
#endif
}
}

int main() {
  phantom_recorder_probe_checkpoint();
  phantom_recorder_probe_value = 17;
  phantom_recorder_probe_checkpoint();
  phantom_recorder_probe_value = 29;
  phantom_recorder_probe_final_checkpoint();
  std::puts("phantom-recorder-probe-ok");
  return phantom_recorder_probe_value == 29 ? 0 : 1;
}
