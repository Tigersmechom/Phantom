#include "phantom/process_inspection.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <signal.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

std::string statRecord(const std::string& command = "a command", std::size_t lastField = 52,
                       std::size_t changedField = 0, const std::string& changedValue = "") {
  std::string result = "123 (" + command + ") R";
  for (std::size_t field = 4; field <= lastField; ++field) {
    result += ' ';
    if (field == changedField) result += changedValue;
    else if (field == 22) result += "9007199254740993";
    else if (field == 28) result += "18446744073709551615";
    else result += std::to_string(field);
  }
  return result + '\n';
}

void malformed(const std::string& text) {
  const auto result = phantom::parseLinuxProcessStat(text);
  assert(result["available"] == false && result["coverage"] == "none");
  assert(result["reason"] == "malformed");
  assert(!result.contains("addresses"));
}

void parserTests() {
  const auto record = phantom::parseLinuxProcessStat(statRecord());
  assert(record["available"] == true && record["coverage"] == "complete");
  assert(record["pid"] == "123" && record["command"] == "a command");
  assert(record["state"] == "R" && record["startTimeTicks"] == "9007199254740993");
  const auto& addresses = record["addresses"];
  assert(addresses["startCodeHex"] == "0x1a" && addresses["endCodeHex"] == "0x1b");
  assert(addresses["startStackHex"] == "0xffffffffffffffff");
  assert(addresses["startDataHex"] == "0x2d" && addresses["endDataHex"] == "0x2e");
  assert(addresses["startBrkHex"] == "0x2f");
  assert(addresses["argStartHex"] == "0x30" && addresses["argEndHex"] == "0x31");
  assert(addresses["envStartHex"] == "0x32" && addresses["envEndHex"] == "0x33");
  assert(record["addressEvidence"] == "kernel-reported-may-be-redacted");

  // A scanner which splits whitespace first or uses the FIRST ')' is wrong.
  for (const auto& name : {std::string("a ) R ( 99) ("), std::string("))) ((("),
                           std::string("\n\tЖ 😀\n"), std::string("")}) {
    const auto result = phantom::parseLinuxProcessStat(statRecord(name));
    assert(result["available"] == true && result["command"] == name);
    assert(result["startTimeTicks"] == "9007199254740993");
  }
  for (const auto& name : {std::string("\xff"), std::string("\xc0\xaf"),
                           std::string("\xed\xa0\x80"), std::string("\xf4\x90\x80\x80"),
                           std::string("\xe2\x82")}) {
    const auto result = phantom::parseLinuxProcessStat(statRecord(name));
    assert(result["available"] == true && result["command"].is_null());
    assert(!result["commandBytesHex"].get<std::string>().empty());
    assert(!result.dump().empty());
  }
  const auto oldKernel = phantom::parseLinuxProcessStat(statRecord("old", 28));
  assert(oldKernel["available"] == true && oldKernel["coverage"] == "partial");
  assert(oldKernel["addresses"]["startBrkHex"].is_null());
  const auto future = phantom::parseLinuxProcessStat(statRecord("future", 80));
  assert(future["available"] == true && future["coverage"] == "complete");
  const auto masked = phantom::parseLinuxProcessStat(statRecord("protected", 52, 28, "0"));
  assert(masked["addresses"]["startStackHex"] == "0x0");
  assert(masked["addressEvidence"] == "kernel-reported-may-be-redacted");

  malformed("");
  malformed("123 no brackets R 0 0 0\n");
  malformed("123 (name)R 0 0 0\n");
  malformed("123(name) R 0 0 0\n");
  malformed("0 (name) R 0 0 0\n");
  malformed("999999999999999999999 (name) R 0 0 0\n");
  malformed(statRecord("short", 21));
  malformed(statRecord("bad", 52, 22, "-1"));
  malformed(statRecord("bad", 52, 22, "18446744073709551616"));
  malformed(statRecord("bad", 52, 28, "0x123"));
  malformed(statRecord("bad", 52, 47, "123junk"));
  malformed(statRecord("bad", 52, 51, "-1"));
  malformed(statRecord(std::string("a\0b", 3)));
  auto badState = statRecord();
  badState[badState.find(") R") + 2] = '?';
  malformed(badState);
  const auto oversized = phantom::parseLinuxProcessStat(std::string(64 * 1024 + 1, 'x'));
  assert(oversized["available"] == false && oversized["reason"] == "byte-limit");
}

#ifdef __linux__
void liveTests() {
  const auto snapshot = phantom::inspectOwnedProcess(::getpid());
  assert(snapshot["available"] == true && snapshot["identityVerified"] == true);
  assert(snapshot["source"] == "linux-procfs" && snapshot["pid"] == std::to_string(::getpid()));
  assert(snapshot["stat"]["available"] == true);
  assert(snapshot["status"]["available"] == true && snapshot["status"]["threads"].get<int>() > 0);
  assert(snapshot["status"]["uid"]["effective"] == std::to_string(::geteuid()));
  assert(snapshot["status"]["gid"]["effective"] == std::to_string(::getegid()));
  assert(snapshot["executable"]["available"] == true && snapshot["executable"]["path"].is_string());
  assert(!snapshot.contains("environ") && !snapshot.contains("cmdline"));
  assert(snapshot["memory"]["available"] == true);
  for (const auto& [key, value] : snapshot["memory"]["countersBytes"].items()) {
    (void)key;
    assert(value.is_string() && std::stoull(value.get<std::string>()) % 1024 == 0);
  }
  utsname system{};
  assert(::uname(&system) == 0);
  assert(snapshot["system"]["kernelRelease"] == system.release);
  assert(snapshot["system"]["machine"] == system.machine);
  assert(snapshot["system"]["pageSizeBytes"] == std::to_string(::sysconf(_SC_PAGESIZE)));
  // Reading personality can be prohibited even when status/maps are readable.
  const int mask = ::personality(0xffffffffUL);
  if (snapshot["personality"]["available"] == true && mask >= 0) {
    assert(snapshot["personality"]["addrNoRandomize"] == ((mask & ADDR_NO_RANDOMIZE) != 0));
  } else if (snapshot["personality"]["available"] == false) {
    assert(snapshot["personality"]["reason"] == "read-denied");
    assert(!snapshot["personality"].contains("addrNoRandomize"));
  }

  // Real kernel comm fields with ')', newline and raw bytes remain parseable.
  std::array<char, 16> oldName{};
  assert(::prctl(PR_GET_NAME, oldName.data()) == 0);
  const std::string unusualName = "a) R (\n\xff";
  assert(::prctl(PR_SET_NAME, unusualName.c_str()) == 0);
  const auto named = phantom::inspectOwnedProcess(::getpid());
  assert(::prctl(PR_SET_NAME, oldName.data()) == 0);
  assert(named["available"] == true && named["stat"]["command"].is_null());
  assert(named["stat"]["commandBytesHex"] == "6129205220280aff");
  assert(!named.dump().empty());

  const auto tiny = phantom::inspectOwnedProcess(::getpid(), {1, 128, 4096});
  assert(tiny["available"] == false && tiny["reason"] == "byte-limit");
  assert(tiny["identityVerified"] == false && !tiny.contains("status"));
  const auto noFds = phantom::inspectOwnedProcess(::getpid(), {64 * 1024, 0, 4096});
  assert(noFds["available"] == true && noFds["coverage"] == "partial");
  assert(noFds["fileDescriptors"]["coverage"] == "truncated");
  assert(noFds["fileDescriptors"]["reason"] == "descriptor-limit");
  assert(noFds["fileDescriptors"]["entries"].empty());
  const auto noLinks = phantom::inspectOwnedProcess(::getpid(), {64 * 1024, 128, 0});
  assert(noLinks["available"] == true && noLinks["coverage"] == "partial");
  assert(noLinks["executable"]["available"] == false && noLinks["executable"]["reason"] == "byte-limit");
  const auto huge = phantom::inspectOwnedProcess(::getpid(),
    {std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::size_t>::max(),
     std::numeric_limits<std::size_t>::max()});
  assert(huge["available"] == true && huge["fileDescriptors"]["entries"].size() <= 128);
  assert(phantom::inspectOwnedProcess(0)["reason"] == "invalid-process");
  assert(phantom::inspectOwnedProcess(-1)["reason"] == "invalid-process");
}

void descriptorTests() {
  std::array<char, 64> directory{};
  const std::string pattern = "/tmp/phantom-process-inspection-XXXXXX";
  std::copy(pattern.begin(), pattern.end(), directory.begin());
  assert(::mkdtemp(directory.data()) != nullptr);
  const std::array<std::string, 4> names = {"with spaces", "Ж 😀", "deleted", std::string("byte\xff")};
  std::array<int, 4> fds{};
  for (std::size_t i = 0; i < names.size(); ++i) {
    const auto path = std::string(directory.data()) + '/' + names[i];
    fds[i] = ::open(path.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    assert(fds[i] >= 0);
    if (i == 2) assert(::unlink(path.c_str()) == 0);
  }
  const auto snapshot = phantom::inspectOwnedProcess(::getpid());
  assert(snapshot["fileDescriptors"]["available"] == true);
  std::array<bool, 4> found{};
  int previous = -1;
  for (const auto& entry : snapshot["fileDescriptors"]["entries"]) {
    const auto descriptor = entry["descriptor"].get<int>();
    assert(descriptor > previous);
    previous = descriptor;
    for (std::size_t i = 0; i < fds.size(); ++i) {
      if (descriptor != fds[i]) continue;
      found[i] = true;
      assert(entry["available"] == true);
      if (i == 3) {
        assert(entry["path"].is_null());
        assert(entry["pathBytesHex"].get<std::string>().ends_with("62797465ff"));
      } else {
        assert(entry["path"] == std::string(directory.data()) + '/' + names[i] + (i == 2 ? " (deleted)" : ""));
      }
    }
  }
  for (bool present : found) assert(present);
  assert(!snapshot.dump().empty());
  for (std::size_t i = 0; i < fds.size(); ++i) {
    assert(::close(fds[i]) == 0);
    if (i != 2) assert(::unlink((std::string(directory.data()) + '/' + names[i]).c_str()) == 0);
  }
  assert(::rmdir(directory.data()) == 0);

  // Descriptor and per-link hard caps apply even to SIZE_MAX requests. A large
  // process cannot make collection walk or serialize every descriptor.
  std::vector<int> many;
  for (int i = 0; i < 150; ++i) {
    const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    many.push_back(fd);
  }
  const auto bounded = phantom::inspectOwnedProcess(::getpid(),
    {std::numeric_limits<std::size_t>::max(), std::numeric_limits<std::size_t>::max(),
     std::numeric_limits<std::size_t>::max()});
  assert(bounded["available"] == true && bounded["fileDescriptors"]["coverage"] == "truncated");
  assert(bounded["fileDescriptors"]["entries"].size() == 128);
  assert(bounded["fileDescriptors"]["reason"] == "descriptor-limit");
  for (const int fd : many) assert(::close(fd) == 0);
}

void lifecycleTests() {
  const auto child = ::fork();
  assert(child >= 0);
  if (child == 0) {
    ::raise(SIGSTOP);
    ::_exit(0);
  }
  int status = 0;
  assert(::waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
  const auto stopped = phantom::inspectOwnedProcess(child);
  assert(stopped["available"] == true && stopped["identityVerified"] == true);
  assert(stopped["stat"]["state"] == "T");
  assert(::kill(child, SIGCONT) == 0);
  assert(::waitpid(child, &status, 0) == child && WIFEXITED(status));
  const auto reaped = phantom::inspectOwnedProcess(child);
  assert(reaped["available"] == false && reaped["identityVerified"] == false);
  assert(reaped["reason"] == "process-unavailable" || reaped["reason"] == "process-exited");
  assert(!reaped.contains("status") && !reaped.contains("stat"));

  // Permissions are checked per section; an undumpable process must not turn
  // a denied personality read into the false claim that ASLR is enabled.
  const auto protectedChild = ::fork();
  assert(protectedChild >= 0);
  if (protectedChild == 0) {
    if (::prctl(PR_SET_DUMPABLE, 0) != 0) ::_exit(1);
    ::raise(SIGSTOP);
    ::_exit(0);
  }
  assert(::waitpid(protectedChild, &status, WUNTRACED) == protectedChild && WIFSTOPPED(status));
  const auto protectedSnapshot = phantom::inspectOwnedProcess(protectedChild);
  if (protectedSnapshot["available"] == true) {
    assert(protectedSnapshot["stat"]["available"] == true);
    for (const auto* field : {"personality", "executable", "fileDescriptors", "memory"}) {
      const auto& section = protectedSnapshot[field];
      if (section["available"] == false) {
        assert(section["reason"] == "read-denied" || section["reason"] == "process-unavailable");
        assert(section["coverage"] == "none");
        assert(!section.contains("addrNoRandomize"));
      }
    }
  } else {
    assert(protectedSnapshot["reason"] == "read-denied" || protectedSnapshot["reason"] == "process-unavailable");
  }
  assert(::kill(protectedChild, SIGCONT) == 0);
  assert(::waitpid(protectedChild, &status, 0) == protectedChild && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#endif

}  // namespace

int main() {
  parserTests();
#ifdef __linux__
  liveTests();
  descriptorTests();
  lifecycleTests();
#endif
}
