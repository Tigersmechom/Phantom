#include <atomic>
#include <cstdint>

using SignedAlias = std::int32_t;
using ConstAlias = const SignedAlias;
using VolatileAlias = volatile SignedAlias;
enum class EnumValue : unsigned short { first = 3 };
struct HostileScalar {
  static int calls;
  int value;
  operator int() { ++calls; return value; }
};
int HostileScalar::calls = 0;
volatile int scalarSink;
void scalarRegister(int seed);
void scalarUnavailable(int seed);

__attribute__((noinline)) void scalarInner(int argument) {
  int inner = argument + 1;
  scalarSink = inner;  // SCALAR_INNER
}

int main() {
  std::int8_t s8 = -12;
  std::uint8_t u8 = 250;
  std::int16_t s16 = -1234;
  std::uint16_t u16 = 65500;
  SignedAlias s32 = -123456;
  std::uint32_t u32 = 4294967290U;
  std::int64_t s64 = -9223372036854775807LL;
  std::uint64_t u64 = 18446744073709551615ULL;
  bool flag = true;
  char character = 'z';
  ConstAlias constant = 2;
  VolatileAlias changing = 3;
  const volatile int both = 4;
  std::atomic<int> atomicValue{5};
#ifdef __clang__
  _Atomic(int) cAtomic = 6;
#endif
  int& reference = s32;
  int&& rvalueReference = static_cast<int&&>(s32);
  int* pointer = &s32;
  int array[2] = {1, 2};
  double floating = 1.5;
  EnumValue enumeration = EnumValue::first;
  __int128 wide = 1;
  HostileScalar hostile{13};
  scalarSink = s32;  // SCALAR_READY
  scalarInner(s32);
  {
    int s32 = 88;
    scalarSink = s32;  // SCALAR_SHADOW
  }
  scalarRegister(s32);
  scalarUnavailable(s32);
  scalarSink = s8 + u8 + s16 + u16 + reference + rvalueReference + *pointer +
      array[0] + constant + changing + both + hostile.value + character + flag +
      static_cast<int>(floating) + static_cast<int>(enumeration) + static_cast<int>(wide) +
      static_cast<int>(s64 == 0) + static_cast<int>(u64 == 0) + static_cast<int>(u32 == 0);
  return HostileScalar::calls;
}
