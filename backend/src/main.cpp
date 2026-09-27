#include <iostream>
#include <string_view>

static_assert(__cplusplus >= 202002L, "phantom-backend requires C++20");

namespace {
constexpr std::string_view platform() {
#if defined(__linux__)
  return "linux";
#elif defined(__APPLE__)
  return "macos";
#else
  return "other";
#endif
}

constexpr std::string_view architecture() {
#if defined(__aarch64__) || defined(__arm64__)
  return "arm64";
#elif defined(__x86_64__) || defined(_M_X64)
  return "x86_64";
#else
  return "other";
#endif
}

void help() {
  std::cout << "phantom-backend " << PHANTOM_BACKEND_VERSION << " (scaffold only)\n"
            << "Usage: phantom-backend [--help | --version | --self-check]\n"
            << "No debugger, transport, recording or replay engine is implemented.\n";
}

void self_check() {
  // This is a build report, not a Protocol v1 hello/capability negotiation.
  // A zero exit status proves only that this standalone executable can run.
  std::cout << "{\n"
            << "  \"kind\": \"phantom.backend.scaffold-check\",\n"
            << "  \"version\": \"" << PHANTOM_BACKEND_VERSION << "\",\n"
            << "  \"status\": \"scaffold-only\",\n"
            << "  \"platform\": \"" << platform() << "\",\n"
            << "  \"architecture\": \"" << architecture() << "\",\n"
            << "  \"cxxStandard\": " << __cplusplus << ",\n"
            << "  \"protocol\": \"not-implemented\",\n"
            << "  \"capabilities\": {\n"
            << "    \"debugger\": false,\n"
            << "    \"recordReplay\": false,\n"
            << "    \"expressionTrace\": false,\n"
            << "    \"historyQueries\": false,\n"
            << "    \"interventions\": false\n"
            << "  }\n"
            << "}\n";
}
} // namespace

int main(int argc, char** argv) {
  if (argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--help")) {
    help();
    return 0;
  }
  if (argc != 2) {
    std::cerr << "Expected exactly one option. Use --help.\n";
    return 2;
  }
  const std::string_view option(argv[1]);
  if (option == "--version") {
    std::cout << "phantom-backend " << PHANTOM_BACKEND_VERSION << "\n";
    return 0;
  }
  if (option == "--self-check") {
    self_check();
    return 0;
  }
  std::cerr << "Unsupported option. Use --help.\n";
  return 2;
}
