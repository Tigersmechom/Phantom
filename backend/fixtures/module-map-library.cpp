// A small real dlopen/dlclose fixture with initialized data, a BSS tail and
// read-only compiler metadata. It intentionally has no runtime dependencies.
namespace {
volatile unsigned char tail[32768];
int value = 41;
}

extern "C" int phantomModuleFixture() {
  tail[sizeof(tail) - 1] = 1;
  return value + tail[sizeof(tail) - 1];
}
