#include "phantom/mi.hpp"
#include "phantom/process.hpp"

#include <cassert>
#include <chrono>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <future>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

using namespace phantom;
using namespace std::chrono_literals;

namespace {
void test_mi() {
  auto r = mi::parse_record(
      "42^done,bkpt={number=\"1\",times=\"0\"},stack=[frame={level=\"0\",args=[name=\"x\",value=\"1\"]},frame={level=\"1\"}]\n");
  assert(r.kind == mi::RecordKind::result && r.token && *r.token == "42" && r.klass == "done");
  assert(mi::find(r.fields, "bkpt") != nullptr);
  auto stack = mi::find(r.fields, "stack");
  assert(stack && stack->kind == mi::ValueKind::result_list && stack->fields.size() == 2);
  assert(stack->fields[0].second->kind == mi::ValueKind::tuple);
  auto args = mi::find(stack->fields[0].second->fields, "args");
  assert(args && args->kind == mi::ValueKind::result_list);
  assert(mi::find_all(args->fields, "name").size() == 1);

  auto stopped = mi::parse_record("*stopped,reason=\"breakpoint-hit\",reason=\"again\"\r\n");
  assert(stopped.kind == mi::RecordKind::exec && mi::find_all(stopped.fields, "reason").size() == 2);
  auto stream = mi::parse_record("~\"hello\\nworld\\x21\"\n");
  assert(stream.kind == mi::RecordKind::console && stream.stream == "hello\nworld!");
  assert(mi::quote("a\n\\\"") == "\"a\\n\\\\\\\"\"");

  mi::LineBuffer lines;
  auto one = lines.feed("1^done\r\n(gdb)\n");
  assert(one.size() == 2 && one[0] == "1^done" && one[1] == "(gdb)");
  auto cr = lines.feed("2^running\r");
  assert(cr.empty());
  auto tail = lines.finish();
  assert(tail.size() == 1 && tail[0] == "2^running");
  bool failed = false;
  try { (void)mi::parse_record("^done,x=\"bad\\q\"\n"); } catch (const mi::ParseError& e) { failed = e.code() == mi::ParseErrorCode::invalid_escape; }
  assert(failed);
  failed = false;
  try { (void)mi::parse_record("^future\n"); } catch (const mi::ParseError& e) { failed = e.code() == mi::ParseErrorCode::syntax; }
  assert(failed);
}

ProcessOptions shell(std::string command, std::size_t limit = 4096) {
  ProcessOptions o; o.argv = {"/bin/sh", "-c", std::move(command)}; o.max_output_bytes = limit; return o;
}

void test_process() {
  auto p = Process::spawn(shell("printf out; printf err >&2; exit 7"));
  auto result = p.wait(std::chrono::steady_clock::now() + 2s);
  assert(result.out == "out" && result.err == "err" && result.exit && result.exit->exit_code == 7);

  auto polled = Process::spawn(shell("printf chunk"));
  auto first = polled.poll(100ms);
  assert(first.out == "chunk");
  auto polled_result = polled.wait(std::chrono::steady_clock::now() + 2s);
  assert(polled_result.out == "chunk");  // wait retains bytes consumed by poll()

  auto io = Process::spawn(shell("read line; printf '<%s>' \"$line\""));
  io.write("input\n"); io.close_stdin();
  auto io_result = io.wait(std::chrono::steady_clock::now() + 2s);
  assert(io_result.out == "<input>");

  bool timeout = false;
  try { auto slow = Process::spawn(shell("sleep 2")); (void)slow.wait(std::chrono::steady_clock::now() + 30ms); }
  catch (const ProcessError& e) { timeout = e.code() == ProcessErrorCode::timeout; }
  assert(timeout);

  bool missing = false;
  try { ProcessOptions bad; bad.argv = {"/definitely/not/a/program"}; (void)Process::spawn(bad); }
  catch (const ProcessError& e) { missing = e.code() == ProcessErrorCode::spawn; }
  assert(missing);

  bool capped = false;
  try { auto noisy_options = shell("printf 123456789", 4); auto noisy = Process::spawn(noisy_options); (void)noisy.wait(std::chrono::steady_clock::now() + 2s); }
  catch (const ProcessError& e) { capped = e.code() == ProcessErrorCode::output_limit; }
  assert(capped);

  std::stop_source source;
  auto cancellable = Process::spawn(shell("sleep 2"));
  bool cancelled = false;
  std::thread waiter([&] {
    try { (void)cancellable.wait(Deadline::max(), source.get_token()); }
    catch (const ProcessError& e) { cancelled = e.code() == ProcessErrorCode::cancelled; }
  });
  std::this_thread::sleep_for(30ms); source.request_stop(); waiter.join();
  assert(cancelled);

  // A nonblocking stdin is required for deadlines to remain meaningful when
  // the child does not read. A blocking write of this size used to bypass the
  // deadline inside write(2).
  bool write_timeout = false;
  try {
    auto blocked = Process::spawn(shell("sleep 2"));
    std::string megabyte(1024 * 1024, 'x');
    blocked.write(megabyte, std::chrono::steady_clock::now() + 40ms);
  } catch (const ProcessError& e) {
    write_timeout = e.code() == ProcessErrorCode::timeout;
  }
  assert(write_timeout);

  // terminate() must be able to make progress while another thread is
  // waiting for stdin space. The write operation only holds the mutex around
  // short fd/state transitions, never around poll().
  auto concurrently_blocked = Process::spawn(shell("sleep 2"));
  std::promise<void> writer_done;
  auto writer_future = writer_done.get_future();
  std::thread writer([&] {
    try {
      concurrently_blocked.write(std::string(1024 * 1024, 'y'), Deadline::max());
    } catch (const ProcessError&) {
    }
    writer_done.set_value();
  });
  std::this_thread::sleep_for(30ms);
  auto terminate_start = std::chrono::steady_clock::now();
  concurrently_blocked.terminate(100ms);
  auto terminate_elapsed = std::chrono::steady_clock::now() - terminate_start;
  assert(terminate_elapsed < 1s);
  assert(writer_future.wait_for(1s) == std::future_status::ready);
  writer.join();

  // wait() also releases the object lock between bounded drain slices, so a
  // control thread can terminate a process that produces no output.
  auto concurrently_waiting = Process::spawn(shell("sleep 2"));
  std::promise<void> wait_done;
  auto wait_future = wait_done.get_future();
  std::thread waiter_thread([&] {
    try { (void)concurrently_waiting.wait(Deadline::max()); } catch (const ProcessError&) {}
    wait_done.set_value();
  });
  std::this_thread::sleep_for(30ms);
  concurrently_waiting.terminate(100ms);
  assert(wait_future.wait_for(1s) == std::future_status::ready);
  waiter_thread.join();

  // A child and a TERM-ignoring grandchild must be cleaned as one process
  // group; waiting only for the leader would leave the output pipes open.
  auto stubborn = Process::spawn(shell("trap '' TERM; (trap '' TERM; sleep 5)& wait"));
  auto group_start = std::chrono::steady_clock::now();
  stubborn.terminate(40ms);
  assert(std::chrono::steady_clock::now() - group_start < 1s);
  auto group_result = stubborn.wait(std::chrono::steady_clock::now() + 1s);
  assert(group_result.exit);

  bool bad_input = false;
  try {
    ProcessOptions bad; bad.argv = {"/bin/echo", std::string("a\0b", 3)};
    (void)Process::spawn(bad);
  } catch (const ProcessError& e) {
    bad_input = e.code() == ProcessErrorCode::spawn;
  }
  assert(bad_input);
  bad_input = false;
  try {
    ProcessOptions bad; bad.argv = {"/bin/true"}; bad.environment = {{"A=B", "x"}};
    (void)Process::spawn(bad);
  } catch (const ProcessError& e) {
    bad_input = e.code() == ProcessErrorCode::spawn;
  }
  assert(bad_input);

  // Empty PATH elements mean the child's current directory. Verify this with
  // an explicit cwd; resolving against the parent's cwd is incorrect.
  char temp_template[] = "/tmp/phantom-process-XXXXXX";
  char* temp_dir = ::mkdtemp(temp_template);
  assert(temp_dir != nullptr);
  std::string executable = std::string(temp_dir) + "/path_probe";
  int file = ::open(executable.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0700);
  assert(file >= 0);
  const char script[] = "#!/bin/sh\nprintf 'path-ok\\n'\n";
  assert(::write(file, script, sizeof(script) - 1) == static_cast<ssize_t>(sizeof(script) - 1));
  ::close(file);
  ProcessOptions path_probe;
  path_probe.argv = {"path_probe"}; path_probe.cwd = temp_dir;
  path_probe.environment = {{"PATH", ":"}};
  auto path_result = Process::spawn(path_probe).wait(std::chrono::steady_clock::now() + 2s);
  assert(path_result.out == "path-ok\n");
  ::unlink(executable.c_str());
  ::rmdir(temp_dir);

  // close_extra_fds must cover descriptors above the old 65536 ceiling. The
  // assertion is skipped only on systems whose RLIMIT_NOFILE cannot represent
  // that descriptor number.
  int base_fd = ::open("/dev/null", O_RDONLY);
  int high_fd = base_fd < 0 ? -1 : ::fcntl(base_fd, F_DUPFD, 70000);
  if (high_fd >= 0) {
    auto no_leak = Process::spawn(shell("test ! -e /proc/self/fd/70000"));
    auto no_leak_result = no_leak.wait(std::chrono::steady_clock::now() + 2s);
    assert(no_leak_result.exit && no_leak_result.exit->exit_code == 0);
    ::close(high_fd);
  }
  if (base_fd >= 0) ::close(base_fd);
}
}  // namespace

int main() {
  test_mi(); test_process();
  std::cout << "process/MI tests passed\n";
}
