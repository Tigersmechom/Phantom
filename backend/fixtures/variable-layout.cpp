#include <cstddef>

struct Left { int left = 11; };
struct Right { int right = 22; };
struct Virtual { int shared = 33; };
struct Derived : Left, Right, virtual Virtual {
  virtual int method() { return tail; }
  int tail = 44;
};
struct Plain {
  int first;
  unsigned low : 3;
  unsigned high : 5;
  int matrix[2][3];
  int* pointer;
  union { int integer; unsigned char bytes[4]; } overlap;
  static int global;
};
int Plain::global = 99;
template<int Depth> struct Nested { Nested<Depth - 1> child; };
template<> struct Nested<0> { int leaf; };
#define LAYOUT_ROW(prefix) int prefix##0, prefix##1, prefix##2, prefix##3, prefix##4, prefix##5, prefix##6, prefix##7;
struct Wide {
  LAYOUT_ROW(a) LAYOUT_ROW(b) LAYOUT_ROW(c) LAYOUT_ROW(d) LAYOUT_ROW(e)
  LAYOUT_ROW(f) LAYOUT_ROW(g) LAYOUT_ROW(h) LAYOUT_ROW(i) LAYOUT_ROW(j)
  LAYOUT_ROW(k) LAYOUT_ROW(l) LAYOUT_ROW(m) LAYOUT_ROW(n) LAYOUT_ROW(o)
  LAYOUT_ROW(p) LAYOUT_ROW(q) LAYOUT_ROW(r) LAYOUT_ROW(s) LAYOUT_ROW(t)
};
#undef LAYOUT_ROW
struct Hostile {
  static int calls;
  int stored;
  int operator*() { ++calls; return stored; }
  operator int() { ++calls; return stored; }
};
int Hostile::calls = 0;
volatile int sink;

void layoutOptimized(int seed);

__attribute__((noinline)) static void nestedCall(int arg) {
  int local = arg;
  sink = local;  // LAYOUT_INNER
}

int main() {
  int scalar = 17;
  int& reference = scalar;
  Plain plain{7, 5, 17, {{1, 2, 3}, {4, 5, 6}}, &scalar, {123}};
  Derived derived;
  Nested<12> deep;
  Wide wide;
  Hostile hostile{41};
  int* invalidPointer = reinterpret_cast<int*>(1);
  int array[10000] = {};
  const int constant = 63;
  sink = scalar;  // LAYOUT_READY
  nestedCall(scalar);
  {
    int scalar = 88;
    sink = scalar;  // LAYOUT_SHADOW
  }
  layoutOptimized(scalar);
  sink = plain.first + derived.tail + hostile.stored + constant + reference + array[0];
  return Hostile::calls;
}
