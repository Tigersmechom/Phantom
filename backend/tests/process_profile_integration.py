"""Kernel-enforced single-process launch, startup ordering and native compatibility."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited
import runtime_helper_integration as runtime

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'single-process-v1'
SOURCE = r'''#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int constructor_denied = -1;
static volatile int worker_ran = 0;
static void reap(long child) {
  if (child == 0) _exit(0);
  if (child > 0) { int status; while (waitpid(static_cast<pid_t>(child), &status, 0) < 0 && errno == EINTR) {} }
}
__attribute__((constructor)) static void before_main() {
  errno = 0;
  const long child = syscall(SYS_fork);
  const int saved = errno;
  reap(child);
  constructor_denied = child == -1 && saved == EPERM;
  const char* text = constructor_denied ? "constructor:blocked\n" : "constructor:allowed\n";
  (void)write(1, text, constructor_denied ? 20 : 20);
}
static void* worker(void*) { worker_ran = 1; return nullptr; }
alignas(16) static char clone_stack[65536];
extern "C" long raw_clone_vm(void*);
asm(".text\n.global raw_clone_vm\n.type raw_clone_vm,@function\n"
    "raw_clone_vm:\nmov %rdi,%rsi\nmov $273,%rdi\nxor %rdx,%rdx\nxor %r10,%r10\nxor %r8,%r8\n"
    "mov $56,%rax\nsyscall\ntest %rax,%rax\njnz 1f\nxor %rdi,%rdi\nmov $60,%rax\nsyscall\nud2\n1: ret\n"
    ".size raw_clone_vm,.-raw_clone_vm\n");
static bool denied(long result, int error) { return result == -1 && error == EPERM; }
int main(int argc, char** argv) {
  const bool isolated = argc > 1 && argv[1][0] == 's';
  volatile int marker = 7;
  asm volatile("nop" : : : "memory"); // HOLD
  if (constructor_denied != static_cast<int>(isolated)) return 20;
  if (!std::getenv("PROFILE_TEXT") || std::string(std::getenv("PROFILE_TEXT")) != "sp ace\nv=42") return 21;
  errno = 123;
  if (getpid() <= 0 || errno != 123) return 22;
  int number = 0;
  std::string empty, text;
  std::cin >> number;
  std::getline(std::cin, empty);
  std::getline(std::cin, text);
  if (number != 42 || !empty.empty() || text != "hello world") return 23;
  if (std::cin.get() != std::char_traits<char>::eof()) return 24;
  errno = 0;
  long child = fork(); int saved = errno; reap(child);
  if (isolated ? !denied(child, saved) : child <= 0) return 25;
  errno = 0;
  child = vfork(); if (child == 0) _exit(0); saved = errno; reap(child);
  if (isolated ? !denied(child, saved) : child <= 0) return 26;
  if (isolated) {
    errno = 0; child = syscall(SYS_fork); saved = errno; reap(child);
    if (!denied(child, saved)) return 27;
    errno = 0; child = syscall(SYS_vfork); if (child == 0) _exit(0); saved = errno; reap(child);
    if (!denied(child, saved)) return 28;
    child = raw_clone_vm(clone_stack + sizeof(clone_stack)); reap(child);
    if (child != -EPERM) return 29;
    clone_args arguments{};
    arguments.exit_signal = SIGCHLD;
    errno = 0; child = syscall(SYS_clone3, &arguments, sizeof(arguments)); saved = errno; reap(child);
    if (!denied(child, saved)) return 30;
    long compat = 20; // i386 getpid: the entire foreign syscall ABI is denied.
    asm volatile("int $0x80" : "+a"(compat) : : "memory", "cc", "r8", "r9", "r10", "r11");
    if (static_cast<std::int32_t>(compat) != -EPERM) return 31;
    errno = 0;
    const long x32 = syscall(0x40000000L | SYS_getpid); saved = errno;
    if (!denied(x32, saved)) return 32;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) return 33;
    if (prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) != -1 || prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED, 0, 0, 0) != -1) return 34;
    sock_filter instruction = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    sock_fprog allow_all{1, &instruction};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &allow_all, 0, 0)) return 35;
    errno = 0; child = syscall(SYS_fork); saved = errno; reap(child);
    if (!denied(child, saved)) return 36; // A later filter cannot weaken the first one.
  }
  pthread_t thread;
  const int thread_result = pthread_create(&thread, nullptr, worker, nullptr);
  if (thread_result == 0) pthread_join(thread, nullptr);
  if (isolated ? thread_result != EPERM || worker_ran : thread_result != 0 || worker_ran != 1) return 37;
  marker = marker + 1;
  std::cout << "echo:" << number << ':' << text << ':' << std::getenv("PROFILE_TEXT") << '\n' << std::flush;
  std::cerr << "errors:0\n";
  asm volatile("nop" : : : "memory"); // AFTER
  return marker == 8 ? 0 : 38;
}
'''

PRELOAD = r'''#include <cerrno>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
__attribute__((constructor)) static void preload_constructor() {
  errno = 0;
  const long child = syscall(SYS_fork);
  const int saved = errno;
  if (child == 0) _exit(0);
  if (child > 0) { int status; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
  const bool blocked = child == -1 && saved == EPERM;
  const char* text = blocked ? "preload:blocked\n" : "preload:allowed\n";
  (void)write(1, text, 16);
}
'''


class Client(runtime.Client):
    def send(self, *frames):
        if self.record_requests:
            TRAFFIC.extend(('request', frame) for frame in frames)
        return LifecycleClient.send(self, *frames)

    def recv(self, timeout=25):
        frame = LifecycleClient.recv(self, timeout)
        TRAFFIC.append(('received', frame))
        return frame


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def command(artifact, profile, *, preload=None):
    environment = {'PROFILE_TEXT': 'sp ace\nv=42'}
    if preload is not None:
        environment['LD_PRELOAD'] = str(preload)
    result = {'kind': 'launch', 'buildId': artifact['id'], 'argv': ['single' if profile == PROFILE else 'native'],
        'input': {'id': 'profile-input', 'text': '42\nhello world\n', 'encoding': 'utf-8', 'closeAfterWrite': True},
        'environment': environment, 'stopAtEntry': True, 'recordingProfile': 'native'}
    if profile is not None:
        result['processProfile'] = profile
    return result


def isolation(observation, profile):
    isolated = profile == PROFILE
    result = observation['executionLayout']['processIsolation']
    assert result == {'requested': PROFILE if isolated else 'native', 'verified': isolated,
        'mechanism': 'linux-seccomp-bpf' if isolated else 'none',
        'noNewPrivileges': True if isolated else None, 'seccompMode': 2 if isolated else None}, result
    if isolated:
        status = dict(line.split(':', 1) for line in Path(f"/proc/{observation['processInstanceId']}/status").read_text().splitlines())
        assert int(status['NoNewPrivs']) == 1 and int(status['Seccomp']) == 2 and int(status['Threads']) == 1
    return result


def launch(client, artifact, profile, preload=None):
    client.execute(command(artifact, profile, preload=preload))
    isolation(client.observation, profile)
    expected = 'blocked' if profile == PROFILE else 'allowed'
    prefix = f'preload:{expected}\n' if preload is not None else ''
    assert client.observation['stdout']['text'] == prefix + f'constructor:{expected}\n', client.observation['stdout']
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1',
        'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True} for marker in ('HOLD', 'AFTER')]})
    assert all(item['verified'] for item in result['breakpoints']), result
    return client.observation['executionLayout']['runFingerprint']


def ordinary_execution(client, artifact, profile, preload=None):
    fingerprint = launch(client, artifact, profile, preload)
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('HOLD')['start']['line']
    if profile != PROFILE:
        before = client.checkpoint()
        client.reject(client.frame(runtime.COMMAND), ('UNSUPPORTED',))
        assert client.checkpoint() == before and runtime.ledger(client)['total'] == 0
    client.execute({'kind': 'step', 'stepKind': 'instruction'})
    isolation(client.observation, profile)
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('AFTER')['start']['line'], client.checkpoint()
    assert client.observation['stdout']['text'].endswith('echo:42:hello world:sp ace\nv=42\n')
    assert client.observation['stderr']['text'] == 'errors:0\n'
    marker = next(value for value in client.observation['stack'][0]['variables'] if value['name'] == 'marker')
    assert marker['value']['value']['decimal'] == '8', marker
    client.execute({'kind': 'continue'})
    assert client.checkpoint()['state']['phase'] == 'terminated'
    assert client.checkpoint()['state']['exit']['code'] == 0
    return fingerprint


def build_preload(workspace):
    source = workspace / 'preload.cpp'
    library = workspace / 'preload.so'
    source.write_text(PRELOAD)
    subprocess.run(['clang++', '-std=c++20', '-fPIC', '-shared', str(source), '-o', str(library)],
        check=True, capture_output=True)
    return library


def fake_wrapper(path):
    path.write_text(f'#!{sys.executable}\n' + r'''
import ctypes, os, pathlib, signal, sys
root = pathlib.Path(__file__).parent
mode = (root / 'mode').read_text()
directory = pathlib.Path(sys.argv[1])
assert sys.argv[2] == '--single-process-v1'
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0): sys.exit(126)
(root / 'inferior-pid').write_text(str(os.getpid()))
with (root / 'invocations').open('a') as output: output.write(mode + '\n')
for name, target, flags in [('stdin', 0, os.O_RDONLY), ('stdout', 1, os.O_WRONLY), ('stderr', 2, os.O_WRONLY)]:
    descriptor = os.open(str(directory / name), flags)
    os.dup2(descriptor, target)
    if descriptor != target: os.close(descriptor)
for item in (directory / 'environment').read_bytes().split(b'\0'):
    if item:
        name, value = item.split(b'=', 1)
        os.environb[name] = value
if mode != 'missing-marker':
    descriptor = os.open(str(directory / 'ready'), os.O_WRONLY)
    os.write(descriptor, b'\x01' if mode == 'wrong-marker' else b'\x02')
    os.close(descriptor)
os.execv(sys.argv[3], sys.argv[3:])
''')
    path.chmod(0o700)


def wrapper_proxy(path, real_gdb, replacement):
    path.write_text(f'#!{sys.executable}\nREAL = {real_gdb!r}\nWRAPPER = {str(replacement)!r}\n' + r'''
import json, os, pathlib, re, shlex, subprocess, sys, threading
if '--version' in sys.argv: os.execv(REAL, [REAL, *sys.argv[1:]])
root = pathlib.Path(__file__).parent
child = subprocess.Popen([REAL, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def forward():
    for line in child.stdout:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
reader = threading.Thread(target=forward, daemon=True); reader.start()
try:
    for line in sys.stdin.buffer:
        token, command = re.match(rb'(\d+)(.*)', line.rstrip(b'\n')).groups()
        prefix = b'-interpreter-exec console '
        if command.startswith(prefix) and (root / 'mode').read_text() != 'real':
            console = json.loads(command[len(prefix):])
            if console.startswith('set exec-wrapper '):
                pieces = shlex.split(console)
                pieces[2] = WRAPPER
                line = token + prefix + json.dumps(shlex.join(pieces)).encode() + b'\n'
        child.stdin.write(line); child.stdin.flush()
finally:
    if child.poll() is None: child.terminate()
    try: child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill(); child.wait()
    reader.join(timeout=.2)
''')
    path.chmod(0o700)


def handshake_failures(executable, real_gdb, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    fake_wrapper(tools / 'fake-wrapper')
    wrapper_proxy(tools / 'gdb', real_gdb, tools / 'fake-wrapper')
    (tools / 'mode').write_text('real')
    client = Client(executable, workspace, {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')})
    try:
        artifact = runtime.build(client, source='int main() { volatile int value = 7; return value - 7; }\n')
        host = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
        modes = ['wrong-marker', 'missing-marker']
        # A replacement wrapper deliberately lies about installing a filter.
        # Kernel metadata can independently disprove that only if the test
        # host has not already supplied both same-valued kernel properties.
        if int(host['NoNewPrivs']) != 1 or int(host['Seccomp']) != 2:
            modes.append('missing-filter')
        for mode in modes:
            (tools / 'mode').write_text(mode)
            (tools / 'inferior-pid').unlink(missing_ok=True)
            started = time.monotonic()
            response = client.reject(client.frame(command(artifact, PROFILE)), ('LAUNCH_FAILED', 'UNSUPPORTED'))
            assert time.monotonic() - started < 8, response
            assert (tools / 'inferior-pid').exists(), 'fault wrapper was not executed'
            require_inferior_exited((tools / 'inferior-pid').read_text())
            assert (tools / 'invocations').read_text().splitlines().count(mode) == 1, 'automatic launch fallback occurred'
            client.reject(client.frame({'kind': 'getState'}), ('STALE_CONTEXT',))
        (tools / 'mode').write_text('real')
        client.execute(command(artifact, PROFILE))
        isolation(client.observation, PROFILE)
        client.execute({'kind': 'continue'})
        assert client.checkpoint()['state']['exit']['code'] == 0
        client.execute(command(artifact, None))
        isolation(client.observation, None)
        client.execute({'kind': 'continue'})
        assert client.checkpoint()['state']['exit']['code'] == 0
    finally:
        client.close()


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='phantom-process-profile-') as directory:
        workspace = Path(directory)
        preload = build_preload(workspace)
        client = Client(executable, workspace, dict(os.environ))
        try:
            artifact = runtime.build(client, source=SOURCE)
            for invalid in ('auto', '', 'single-process-v2', 1, True, None, {}):
                client.reject(client.frame({**command(artifact, None), 'processProfile': invalid}), valid=False)
            default = ordinary_execution(client, artifact, None)
            isolated = ordinary_execution(client, artifact, PROFILE)
            native = ordinary_execution(client, artifact, 'native')
            assert default == native and isolated != native
            ordinary_execution(client, artifact, PROFILE, preload)
            ordinary_execution(client, artifact, None, preload)
            rejected = client.frame({**command(artifact, PROFILE), 'recordingProfile': 'gdb-record-full'})
            client.reject(rejected, ('INVALID_REQUEST', 'UNSUPPORTED'), valid=False)
            client.reject(client.frame({**command(artifact, PROFILE), 'stopAtEntry': False}), ('INVALID_REQUEST',), valid=False)
        finally:
            client.close()
    with tempfile.TemporaryDirectory(prefix='phantom-process-handshake-') as directory:
        handshake_failures(executable, str(Path(shutil.which('gdb')).resolve()), Path(directory))
    print('process profile: startup constructors, LD_PRELOAD, fork/vfork/clone/clone3/pthread, alternate syscall ABIs, immutable filter, ordinary I/O and native reset passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
