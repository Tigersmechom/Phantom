#include <cstddef>
#include <cstdint>
#include <cstring>
#include <csignal>
#include <sys/mman.h>
#include <unistd.h>

// The test reads these through ELF symbols + debugger memory in a stripped
// build. In a debug build the same facts are ordinary checkpoint arguments.
// These addresses are fixture ground truth, never inferred by the inspector.
extern "C" {
std::uintptr_t phantom_vptr_slots[64] = {};
std::uintptr_t phantom_vptr_expected_tops[64] = {};
unsigned phantom_vtable_phase = 0;
int phantom_vtable_function() { return 73; }
}
static bool trapCheckpoints = false;

extern "C" __attribute__((noinline)) void phantom_vtable_checkpoint(
    unsigned phase, void* vptrSlot, void* expectedTop) {
  phantom_vptr_slots[phase] = reinterpret_cast<std::uintptr_t>(vptrSlot);
  phantom_vptr_expected_tops[phase] = reinterpret_cast<std::uintptr_t>(expectedTop);
  phantom_vtable_phase = phase;
  asm volatile("" : : "r"(vptrSlot), "r"(expectedTop) : "memory");  // VTABLE_CHECKPOINT
  if (trapCheckpoints) ::raise(SIGTRAP);
}

struct SingleBase {
  int base = 11;
  SingleBase() { phantom_vtable_checkpoint(1, this, this); }
  virtual ~SingleBase() { phantom_vtable_checkpoint(5, this, this); }
  virtual int value() const { return base; }
};
struct SingleDerived : SingleBase {
  int derived = 22;
  SingleDerived() { phantom_vtable_checkpoint(2, this, this); }
  ~SingleDerived() override { phantom_vtable_checkpoint(4, this, this); }
  int value() const override { return derived; }
};

struct MultiLeft {
  int left = 31;
  virtual ~MultiLeft() { phantom_vtable_checkpoint(17, this, this); }
  virtual int leftValue() const { return left; }
};
struct MultiRight {
  int right = 32;
  virtual ~MultiRight() { phantom_vtable_checkpoint(16, this, this); }
  virtual int rightValue() const { return right; }
};
struct Multiple : MultiLeft, MultiRight {
  Multiple() {
    phantom_vtable_checkpoint(10, static_cast<MultiLeft*>(this), this);
    phantom_vtable_checkpoint(11, static_cast<MultiRight*>(this), this);
  }
  ~Multiple() override {
    phantom_vtable_checkpoint(14, static_cast<MultiLeft*>(this), this);
    phantom_vtable_checkpoint(15, static_cast<MultiRight*>(this), this);
  }
  int leftValue() const override { return 41; }
  int rightValue() const override { return 42; }
};

struct Common {
  int shared = 51;
  Common() { phantom_vtable_checkpoint(20, this, this); }
  virtual ~Common() { phantom_vtable_checkpoint(38, this, this); }
  virtual int commonValue() const { return shared; }
};
struct DiamondLeft : virtual Common {
  int left = 52;
  DiamondLeft() {
    phantom_vtable_checkpoint(21, this, this);
    phantom_vtable_checkpoint(22, static_cast<Common*>(this), this);
  }
  ~DiamondLeft() override {
    phantom_vtable_checkpoint(36, this, this);
    phantom_vtable_checkpoint(37, static_cast<Common*>(this), this);
  }
  virtual int leftValue() const { return left; }
};
struct DiamondRight : virtual Common {
  int right = 53;
  DiamondRight() {
    phantom_vtable_checkpoint(23, this, this);
    phantom_vtable_checkpoint(24, static_cast<Common*>(this), this);
  }
  ~DiamondRight() override {
    phantom_vtable_checkpoint(34, this, this);
    phantom_vtable_checkpoint(35, static_cast<Common*>(this), this);
  }
  virtual int rightValue() const { return right; }
};
struct Diamond : DiamondLeft, DiamondRight {
  Diamond() {
    phantom_vtable_checkpoint(25, static_cast<DiamondLeft*>(this), this);
    phantom_vtable_checkpoint(26, static_cast<DiamondRight*>(this), this);
    phantom_vtable_checkpoint(27, static_cast<Common*>(this), this);
  }
  ~Diamond() override {
    phantom_vtable_checkpoint(31, static_cast<DiamondLeft*>(this), this);
    phantom_vtable_checkpoint(32, static_cast<DiamondRight*>(this), this);
    phantom_vtable_checkpoint(33, static_cast<Common*>(this), this);
  }
  int commonValue() const override { return 61; }
  int leftValue() const override { return 62; }
  int rightValue() const override { return 63; }
};

// A vptr is needed for virtual-base offsets despite having NO virtual
// functions. Its address point can be exactly the end of its ELF symbol.
struct PlainVirtualBase { int value = 71; };
struct VirtualOnly : virtual PlainVirtualBase { int local = 72; };

// In this hierarchy the shared, nearly empty virtual base precedes the
// PositiveC subobject. C's construction/destruction table therefore has a
// genuinely POSITIVE offset-to-top for PositiveA, not a corrupt header.
struct PositiveA { virtual ~PositiveA() = default; virtual int value() { return 81; } };
struct PositiveB : virtual PositiveA {};
struct PositiveC : virtual PositiveB {
  PositiveC() { phantom_vtable_checkpoint(51, static_cast<PositiveA*>(this), this); }
  ~PositiveC() override { phantom_vtable_checkpoint(54, static_cast<PositiveA*>(this), this); }
};
struct PositiveBranch : PositiveB {};
struct PositiveD : PositiveBranch, virtual PositiveC {};

int main(int argc, char** argv) {
  trapCheckpoints = argc > 1 && argv[1][0] == 't';
  std::uintptr_t copiedVptr = 0;
  {
    SingleDerived single;
    std::memcpy(&copiedVptr, static_cast<const void*>(&single), sizeof(copiedVptr));
    phantom_vtable_checkpoint(3, &single, &single);
  }
  {
    Multiple multiple;
    phantom_vtable_checkpoint(12, static_cast<MultiLeft*>(&multiple), &multiple);
    phantom_vtable_checkpoint(13, static_cast<MultiRight*>(&multiple), &multiple);
  }
  {
    Diamond diamond;
    phantom_vtable_checkpoint(28, static_cast<DiamondLeft*>(&diamond), &diamond);
    phantom_vtable_checkpoint(29, static_cast<DiamondRight*>(&diamond), &diamond);
    phantom_vtable_checkpoint(30, static_cast<Common*>(&diamond), &diamond);
  }
  VirtualOnly virtualOnly;
  phantom_vtable_checkpoint(39, &virtualOnly, &virtualOnly);
  {
    PositiveD positive;
    phantom_vtable_checkpoint(52, static_cast<PositiveA*>(&positive), &positive);
    phantom_vtable_checkpoint(53, static_cast<PositiveC*>(&positive), &positive);
  }

  // Raw integer slots do not represent C++ polymorphic objects. Even a
  // copied, real vtable pointer cannot prove object type or lifetime.
  phantom_vtable_checkpoint(50, &copiedVptr, nullptr);
  std::uintptr_t nullVptr = 0;
  phantom_vtable_checkpoint(40, &nullVptr, nullptr);
  std::uintptr_t underflowVptr = 8;
  phantom_vtable_checkpoint(41, &underflowVptr, nullptr);
  std::uintptr_t forgedTable[] = {0, 0, reinterpret_cast<std::uintptr_t>(&phantom_vtable_function)};
  std::uintptr_t forgedVptr = reinterpret_cast<std::uintptr_t>(&forgedTable[2]);
  phantom_vtable_checkpoint(43, &forgedVptr, nullptr);
  std::uintptr_t misalignedVptr = copiedVptr + 1;
  phantom_vtable_checkpoint(48, &misalignedVptr, nullptr);

  const long pageSize = ::sysconf(_SC_PAGESIZE);
  if (pageSize <= 0) return 90;
  void* abandoned = ::mmap(nullptr, static_cast<std::size_t>(pageSize), PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (abandoned == MAP_FAILED) return 91;
  const auto abandonedAddress = reinterpret_cast<std::uintptr_t>(abandoned);
  if (::munmap(abandoned, static_cast<std::size_t>(pageSize)) != 0) return 92;
  std::uintptr_t unmappedVptr = abandonedAddress;
  phantom_vtable_checkpoint(42, &unmappedVptr, nullptr);
  phantom_vtable_checkpoint(44, reinterpret_cast<void*>(abandonedAddress), nullptr);

  auto* pages = static_cast<unsigned char*>(::mmap(nullptr, static_cast<std::size_t>(pageSize) * 2,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (pages == MAP_FAILED) return 93;
  auto* partialSlot = pages + pageSize - sizeof(std::uintptr_t) / 2;
  std::memcpy(partialSlot, &copiedVptr, sizeof(copiedVptr));
  if (::munmap(pages + pageSize, static_cast<std::size_t>(pageSize)) != 0) return 94;
  phantom_vtable_checkpoint(45, partialSlot, nullptr);
  std::memcpy(pages, &copiedVptr, sizeof(copiedVptr));
  if (::mprotect(pages, static_cast<std::size_t>(pageSize), PROT_NONE) != 0) return 95;
  // PROT_NONE is not necessarily unreadable to ptrace. The report must obey
  // its documented map policy and actual captured bytes, never assume both
  // are equivalent to an unmapped page.
  phantom_vtable_checkpoint(46, pages, nullptr);
  if (::mprotect(pages, static_cast<std::size_t>(pageSize), PROT_READ) != 0) return 96;
  phantom_vtable_checkpoint(47, pages, nullptr);
  if (::munmap(pages, static_cast<std::size_t>(pageSize)) != 0) return 97;
  return 0;
}
