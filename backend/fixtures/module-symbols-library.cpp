// Real compiler metadata for section/symbol overlays. Tests never invoke the
// inferior to discover symbols; these exports merely supply independent facts.
struct PhantomSymbolFixture {
  virtual ~PhantomSymbolFixture();
  virtual int value() const;
};
PhantomSymbolFixture::~PhantomSymbolFixture() = default;
int PhantomSymbolFixture::value() const { return 73; }

extern "C" {
int phantomSymbolData = 73;
thread_local int phantomSymbolTls = 17;
PhantomSymbolFixture phantomSymbolObject;
int phantomSymbolFunction() { return phantomSymbolObject.value(); }
void* phantomSymbolVptr() { return *reinterpret_cast<void**>(&phantomSymbolObject); }
void* phantomSymbolTlsAddress() { return &phantomSymbolTls; }
}
