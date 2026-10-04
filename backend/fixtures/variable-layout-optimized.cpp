extern volatile int sink;

// Built separately with -O2. The opaque computation and clobber invalidate
// the parameter's register location without evaluating undefined C++ values.
// Both GCC and Clang emit seed as an actual optimized-out MI argument here.
__attribute__((noinline)) void layoutOptimized(int seed) {
  asm volatile("" : "+r"(seed) : : "memory");
  seed *= seed;
  asm volatile("" : : "r"(seed) : "memory");
  asm volatile("xor %%eax, %%eax\n\txor %%edi, %%edi" : : : "rax", "rdi", "memory");
  sink = 5;  // LAYOUT_OPTIMIZED
  asm volatile("" ::: "memory");
}
