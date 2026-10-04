// A small real GNU ELF image for section/symbol and stripping tests. No calls
// into this image are necessary: the test reads metadata from its descriptor.
struct ElfSymbolBase {
  virtual ~ElfSymbolBase();
  virtual int value() const;
};
struct ElfSymbolDerived : virtual ElfSymbolBase {
  ~ElfSymbolDerived() override;
  int value() const override;
};
ElfSymbolBase::~ElfSymbolBase() = default;
int ElfSymbolBase::value() const { return 17; }
ElfSymbolDerived::~ElfSymbolDerived() = default;
int ElfSymbolDerived::value() const { return 29; }
ElfSymbolDerived elf_symbol_object;
thread_local int elf_symbol_tls = 31;
int elf_symbol_bss[4096];
static int elf_symbol_private = 37;

extern "C" int elf_symbol_function() { return elf_symbol_private; }
extern "C" int elf_symbol_weak() __attribute__((weak));
extern "C" int elf_symbol_weak() { return 41; }
extern "C" int (*elf_symbol_resolve())() { return elf_symbol_function; }
extern "C" int elf_symbol_indirect() __attribute__((ifunc("elf_symbol_resolve")));
