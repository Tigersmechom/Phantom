#include <cstring>

// Deliberately simple x86_64 instructions: GDB's software recorder has a
// target-dependent instruction set, independently of this compiler's ISA.
int main(int argc, char** argv) {
  volatile int value = 0;
  const char mode = argc > 1 ? argv[1][0] : 's';
  if (mode == 'e') return value;
  if (mode == 't') {
    while (true) { value = value + 1; }  // RECORD_SOURCE_TIMEOUT
  }
  if (mode == 'a') {
    value = static_cast<int>(std::strlen(argv[0]));  // RECORD_AVX_RUNTIME
    asm volatile("nop" : : : "memory");  // RECORD_AVX_AFTER
  }
  if (mode == 'm') {
    register long flags asm("r10") = 34;
    register long fd asm("r8") = -1;
    register long offset asm("r9") = 0;
    long address;
    asm volatile("syscall" : "=a"(address) : "0"(9L), "D"(0L), "S"(4096L), "d"(3L),
                 "r"(flags), "r"(fd), "r"(offset) : "rcx", "r11", "memory");
    if (address < 0 && address > -4096) return 92;
    auto* memory = reinterpret_cast<volatile unsigned char*>(address);
    *memory = 11;
    *memory = 22;
    asm volatile("nop" : : : "memory");  // RECORD_MUNMAP_BEFORE
    long result;
    asm volatile("syscall" : "=a"(result) : "0"(11L), "D"(address), "S"(4096L)
                 : "rcx", "r11", "memory");
    asm volatile("nop" : : : "memory");  // RECORD_MUNMAP_AFTER
  }
  if (mode == 'u') {
    // AVX is not required: UD2 is recognized by every x86 CPU, and GDB's
    // record-full decoder currently refuses to record it before execution.
    asm volatile("ud2");  // RECORD_UNSUPPORTED
  }
  if (mode == 'o') {
    static const char bytes[] = {'o', '\0', static_cast<char>(0xff), '\n'};
    long result;
    asm volatile("syscall" : "=a"(result) : "0"(1L), "D"(1L), "S"(bytes), "d"(4L)  // RECORD_OUTPUT_BEGIN
                 : "rcx", "r11", "memory");  // RECORD_OUTPUT
    value = static_cast<int>(result);  // RECORD_OUTPUT_DONE
  }
  value = 1;  // RECORD_SEQUENCE
  value = 2;
  value = 0;
  while (true) {  // RECORD_LOOP
    value = value + 1;
  }
}
