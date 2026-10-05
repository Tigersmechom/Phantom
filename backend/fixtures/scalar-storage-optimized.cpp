extern volatile int scalarSink;

__attribute__((noinline)) void scalarRegister(int seed) {
  register long registerOnly asm("r12") = seed + 7;
  asm volatile("" : "+r"(registerOnly) : : "memory");
  scalarSink = 7;  // SCALAR_REGISTER
  asm volatile("" : : "r"(registerOnly) : "memory");
}

__attribute__((noinline)) void scalarUnavailable(int seed) {
  asm volatile("" : "+r"(seed) : : "memory");
  seed *= seed;
  asm volatile("" : : "r"(seed) : "memory");
  asm volatile("xor %%eax, %%eax\n\txor %%edi, %%edi" : : : "rax", "rdi", "memory");
  scalarSink = 5;  // SCALAR_OPTIMIZED
  asm volatile("" : : : "memory");
}
