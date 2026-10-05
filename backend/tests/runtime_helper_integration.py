"""Opt-in live runtime scratch round-trips and once-only intervention evidence."""
from __future__ import annotations

import array
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import tempfile
import termios
import time

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited
from recorder_probe_integration import Client as ProbeClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'linux-x86_64-scratch-v1'
COMMAND = {'kind': 'runRuntimeHelper', 'profile': PROFILE}
EVIDENCE_FLAGS = {'getpid', 'allocated', 'writable', 'executable', 'payloadExecuted', 'released',
    'registersRestored', 'stackUnchanged', 'errnoUnchanged', 'signalMaskUnchanged',
    'signalPolicyRestored', 'codeUnchanged', 'mapsRestored'}
SOURCE = r'''#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <fcntl.h>
#include <iostream>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

volatile std::sig_atomic_t signal_count = 0;
static std::atomic<bool> worker_ready{false};
static void handler(int) {
  signal_count = 1;
  const char text[] = "handler\n";
  (void)write(2, text, sizeof(text) - 1);
  const int marker = open("runtime-signal-handler-ran", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (marker >= 0) { (void)write(marker, text, sizeof(text) - 1); (void)close(marker); }
}
static void* worker(void*) {
  worker_ready.store(true);
  for (;;) pause();
  return nullptr;
}
static int deny_syscall(unsigned number) {
  sock_filter instructions[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  sock_fprog program{static_cast<unsigned short>(sizeof(instructions) / sizeof(instructions[0])), instructions};
  return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
__attribute__((noinline)) static int inner(int seed, bool consume, char mode) {
  volatile unsigned int counter = 7;
  unsigned char canary[256];
  for (unsigned i = 0; i < sizeof(canary); ++i) canary[i] = static_cast<unsigned char>(i ^ seed);
  alignas(16) unsigned long long vector_seed[2] = {0xffffffffffffffffULL, 0x8000000000000001ULL};
  long double fp_seed = 1.125L;
  std::cout << "kept\n" << std::flush;
  std::cout << "pending";
  if (mode == 'p' && deny_syscall(SYS_mprotect)) return 98;
  if (mode == 'u' && deny_syscall(SYS_munmap)) return 98;
  if (mode == 'm' && deny_syscall(SYS_mmap)) return 98;
  if (mode == 'g' && deny_syscall(SYS_getpid)) return 98;
  errno = 123;
  asm volatile("movdqu %0, %%xmm0\n\tfldt %1" : : "m"(vector_seed), "m"(fp_seed) : "xmm0", "st", "memory");
  asm volatile("nop" : : : "memory"); // HOLD
  asm volatile("fstp %%st(0)" : : : "st", "memory");
  if (errno != 123) return 91;
  for (unsigned i = 0; i < sizeof(canary); ++i)
    if (canary[i] != static_cast<unsigned char>(i ^ seed)) return 92;
  unsigned long long total = 0;
  if (consume) {
    char data[4096];
    ssize_t count;
    while ((count = read(0, data, sizeof(data))) > 0) total += count;
    if (count < 0) return 93;
  }
  counter = counter + 1;
  std::cout << "done\n" << std::flush;
  asm volatile("nop" : : : "memory"); // AFTER
  return counter == 8 ? 0 : 94;
}
__attribute__((noinline)) static int outer(char mode) {
  volatile unsigned long long caller_canary = 0xfeed12345678beefULL;
  const int result = inner(37, mode == 'i', mode);
  return caller_canary == 0xfeed12345678beefULL ? result : 95;
}
int main(int argc, char** argv) {
  const char mode = argc > 1 ? argv[1][0] : 'n';
  struct sigaction action{};
  action.sa_handler = handler;
  if (sigemptyset(&action.sa_mask) || sigaction(SIGUSR1, &action, nullptr) || sigaction(SIGALRM, &action, nullptr)) return 96;
  sigset_t mask;
  if (sigemptyset(&mask) || sigaddset(&mask, SIGUSR2) || sigprocmask(SIG_BLOCK, &mask, nullptr)) return 97;
  if (mode == 'w') { char byte; if (read(0, &byte, 1) != 1) return 99; }
  if (mode == 'r') sleep(30);
  pthread_t thread{};
  if (mode == 't') {
    if (pthread_create(&thread, nullptr, worker, nullptr)) return 100;
    while (!worker_ready.load()) {}
  }
  return outer(mode);
}
'''


class Client(ProbeClient):
    def send(self, *frames):
        if self.record_requests:
            TRAFFIC.extend(('request', frame) for frame in frames)
        return LifecycleClient.send(self, *frames)

    def recv(self, timeout=25):
        frame = LifecycleClient.recv(self, timeout)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command, expected_stop=None):
        if expected_stop is None and command['kind'] in ('runRuntimeHelper', 'readRegisters', 'writeMemory', 'writeRegister',
                'inspectScalarStorage', 'appendInput', 'closeInput', 'captureMemory'):
            assert self.observation is not None
            expected_stop = self.observation['stop']
        return super().frame(command, expected_stop)

    def good(self, command):
        result = self.query(command)
        assert result['ok'], result
        return result['result']

    def reject(self, frame, codes=('INVALID_REQUEST',), *, valid=True):
        self.record_requests = valid
        try:
            self.send(frame)
        finally:
            self.record_requests = True
        response = self.recv()
        if valid:
            assert response.get('requestId') == frame['requestId'], response
        assert response['ok'] is False and response['error']['code'] in codes, response
        return response

    def runtime(self, artifact):
        frame = self.frame(COMMAND)
        self.send(frame)
        return self.receive_runtime(frame, artifact)

    def receive_runtime(self, frame, artifact):
        response = self.recv()
        assert response['ok'] and response['requestId'] == frame['requestId'], response
        audit = response['result']['intervention']
        assert response['result']['kind'] == 'runtimeIntervention'
        assert audit['requestId'] == frame['requestId'] and audit['profile'] == PROFILE
        assert audit['target'] == artifact['runtimeHelper'], audit
        report = audit['report']
        assert set(report) == {'profile', 'writeAttempted', 'executionAttempted', 'debuggerAlive',
            'cancelled', 'outcome', 'phase', 'evidence', 'error'}, report
        assert report['profile'] == PROFILE
        assert report['writeAttempted'] is True and report['executionAttempted'] is True
        if report['outcome'] == 'verified':
            assert report['phase'] == 'verify' and report['error'] is None
            assert report['debuggerAlive'] is True
            proof = report['evidence']
            assert set(proof) == EVIDENCE_FLAGS | {'pid', 'pageSize', 'scratchAddressHex', 'registerCount', 'stackBytes'}
            assert all(proof[key] is True for key in EVIDENCE_FLAGS), proof
            assert type(proof['pid']) is int and str(proof['pid']) == audit['processInstanceId']
            assert type(proof['registerCount']) is int and 32 <= proof['registerCount'] <= 512
            assert type(proof['stackBytes']) is int and 4096 <= proof['stackBytes'] <= 1048576
            page = proof['pageSize']
            assert type(page) is int and 4096 <= page <= 1048576 and page & (page - 1) == 0
            assert re.fullmatch(r'0x[1-9a-f][0-9a-f]*', proof['scratchAddressHex'])
            address = int(proof['scratchAddressHex'], 16)
            assert 0 < address < (1 << 63) and address % page == 0
        else:
            assert report['outcome'] == 'failed' and report['debuggerAlive'] is False, report
            assert report['evidence'] is None and report['error'], report
        events = []
        if audit['report']['writeAttempted']:
            kinds = ['branchCreated', 'state'] if audit['contextStatus'] == 'failed' else ['branchCreated', 'observation', 'state']
            events = [self.recv() for _ in kinds]
            assert [item['payload']['kind'] for item in events] == kinds, events
            assert all(item.get('causedByRequestId') == frame['requestId'] for item in events)
            assert events[0]['payload']['parent'] == audit['beforePoint']
            assert events[0]['payload']['branchId'] == audit['branchId']
            assert response['result']['throughSequence'] == events[-1]['sequence']
            if audit['contextStatus'] == 'refreshed':
                assert self.observation['reason'] == 'mutation'
                assert self.observation['point'] == audit['afterPoint'] and self.observation['stop'] == audit['afterStop']
            else:
                assert audit['afterPoint'] is None and audit['afterStop'] is None
                assert events[-1]['payload']['state']['live'] is None
                assert events[-1]['payload']['state']['phase'] == 'failed'
        return frame, response, events


def build(client, *, runtime=True, source=SOURCE):
    configuration = {'revisionId': 'runtime-helper-config', 'compiler': 'clang++',
        'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build',
        'addressProfile': 'fixed-executable'}
    if runtime:
        configuration['runtimeProfile'] = PROFILE
    response = client.good({'kind': 'build', 'source': {'id': 'runtime-helper-source', 'documents': [{
        'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1', 'path': 'runtime-helper.cpp',
        'text': source, 'sha256': hashlib.sha256(source.encode()).hexdigest()}]},
        'configuration': configuration, 'architecture': 'x86_64'})
    assert response['success'], response
    artifact = response['artifact']
    if runtime:
        manifest = artifact['runtimeHelper']
        assert set(manifest) == {'profile', 'symbol', 'addressHex', 'bytesHex', 'helperSha256'}
        assert manifest['profile'] == PROFILE and manifest['symbol'] == '__phantom_runtime_syscall_v1'
        assert manifest['bytesHex'] == '0f05cc' and re.fullmatch(r'[0-9a-f]{64}', manifest['helperSha256'])
        assert re.fullmatch(r'0x[0-9a-f]+', manifest['addressHex'])
        assert artifact['elf']['class'] == 64 and artifact['elf']['architecture'] == 'x86_64'
        assert artifact['elf']['elfType'] == 'ET_EXEC'
    else:
        assert 'runtimeHelper' not in artifact
    return artifact


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def launch(client, artifact, *, mode='n', recording=False):
    client.execute({'kind': 'launch', 'buildId': artifact['id'],
        'input': {'id': 'runtime-input', 'text': '', 'encoding': 'utf-8', 'closeAfterWrite': recording},
        'argv': [mode], 'environment': {}, 'stopAtEntry': True,
        'recordingProfile': 'gdb-record-full' if recording else 'native'})
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1',
        'breakpoints': [{'id': name, 'range': location(name), 'enabled': True} for name in ('HOLD', 'AFTER')]})
    assert all(item['verified'] for item in result['breakpoints']), result


def at_hold(client):
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'completed', events
    assert client.observation['location']['start']['line'] == location('HOLD')['start']['line']
    assert client.observation['stdout']['text'] == 'kept\n', client.observation
    return client.observation


def at_after(client):
    # Restoring RIP at a software breakpoint may make GDB report that same
    # breakpoint once more. It is a real stop and must not be silently eaten.
    for attempt in range(2):
        events = client.execute({'kind': 'continue'})
        assert events[-1]['payload']['outcome'] == 'completed', events
        line = client.observation['location']['start']['line']
        if line == location('AFTER')['start']['line']:
            return
        assert attempt == 0 and line == location('HOLD')['start']['line'], client.observation
    raise AssertionError('program did not resume after restored breakpoint')


def registers(client):
    return client.good({'kind': 'readRegisters', 'registers': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rsp', 'rbp', 'eflags', 'orig_rax',
        'fs_base', 'gs_base', 'xmm0', 'st0', 'mxcsr']})['registers']


def ledger(client):
    return client.good({'kind': 'listInterventions', 'start': 0, 'count': 128})


def journal(client, point):
    return client.good({'kind': 'readOutputJournal', 'stream': 'stdout', 'fromByte': 0, 'byteCount': 128, 'point': point})


def memory(client, address, count):
    result = client.good({'kind': 'readMemory', 'addressHex': address, 'byteCount': count})
    assert result['unreadableBytes'] == 0
    return base64.b64decode(result['bytesBase64'], validate=True)


def process_stack(pid, maps):
    ranges = [line.split()[0] for line in maps.splitlines() if line.endswith('[stack]')]
    assert len(ranges) == 1
    low, high = (int(value, 16) for value in ranges[0].split('-'))
    assert 4096 <= high - low <= 1048576
    descriptor = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
    try:
        contents = os.pread(descriptor, high - low, low)
        assert len(contents) == high - low
        return contents
    finally:
        os.close(descriptor)


def successful(client, artifact):
    launch(client, artifact)
    entry = client.observation
    before = at_hold(client)
    before_registers = registers(client)
    before_journal = journal(client, before['point'])
    before_maps = Path(f"/proc/{before['processInstanceId']}/maps").read_text()
    before_stack = process_stack(before['processInstanceId'], before_maps)
    before_signals = next(line for line in Path(f"/proc/{before['processInstanceId']}/status").read_text().splitlines() if line.startswith('SigBlk:'))
    manifest = artifact['runtimeHelper']
    assert memory(client, manifest['addressHex'], 3) == b'\x0f\x05\xcc'
    for patch in ({'profile': 'auto'}, {'syscall': 9}, {'code': 'cc'}, {'addressHex': manifest['addressHex']},
            {'arguments': []}, {'timeoutMs': 0}, {'frameLevel': 1}, {'target': manifest}):
        client.reject(client.frame({**COMMAND, **patch}), valid=False)
    no_stop = client.frame(COMMAND); del no_stop['expectedStop']
    client.reject(no_stop, valid=False)
    missing_profile = client.frame({'kind': 'runRuntimeHelper'})
    client.reject(missing_profile, valid=False)
    stale = client.frame(COMMAND); stale['expectedStop'] = entry['stop']
    client.reject(stale, ('STALE_CONTEXT',))
    no_session = client.frame(COMMAND); no_session['session'] = None
    client.reject(no_session, ('STALE_CONTEXT',))
    assert ledger(client)['total'] == 0
    assert client.checkpoint()['observation'] == before and registers(client) == before_registers

    # Public variable paging deliberately leaves GDB's selected frame at a
    # caller. The helper must save the physical innermost CPU context instead.
    caller = client.good({'kind': 'readVariables', 'reference': 'frame:1', 'start': 0, 'count': 64})
    assert any(item['name'] == 'caller_canary' for item in caller['variables']), caller
    saved_frame, response, events = client.runtime(artifact)
    audit = response['result']['intervention']
    assert audit['report']['writeAttempted'] and audit['contextStatus'] == 'refreshed', audit
    after = client.observation
    assert after['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
    assert after['location'] == before['location'] and after['stack'] == before['stack']
    assert after['processInstanceId'] == before['processInstanceId']
    for field in ('input', 'stdout', 'stderr', 'memoryMap'):
        assert after[field] == before[field], (field, before[field], after[field])
    assert registers(client) == before_registers
    assert Path(f"/proc/{after['processInstanceId']}/maps").read_text() == before_maps
    assert process_stack(after['processInstanceId'], before_maps) == before_stack
    assert next(line for line in Path(f"/proc/{after['processInstanceId']}/status").read_text().splitlines() if line.startswith('SigBlk:')) == before_signals
    assert memory(client, manifest['addressHex'], 3) == b'\x0f\x05\xcc'
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert journal(client, before['point']) == before_journal
    assert ledger(client)['items'] == [audit]
    assert client.good({'kind': 'readIntervention', 'interventionId': audit['id']})['intervention'] == audit
    assert client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})['total'] == 0
    assert client.good({'kind': 'listRegisterInterventions', 'start': 0, 'count': 128})['total'] == 0
    client.reject(client.frame({'kind': 'readMemoryIntervention', 'interventionId': audit['id']}), ('HISTORY_EVICTED',))
    client.reject(client.frame({'kind': 'readRegisterIntervention', 'interventionId': audit['id']}), ('HISTORY_EVICTED',))
    client.send(saved_frame)
    assert client.recv() == response
    assert client.checkpoint()['throughSequence'] == response['result']['throughSequence']
    client.reject({**saved_frame, 'command': {'kind': 'getState'}}, ('INVALID_REQUEST',))

    # A second explicit request is a distinct branch, despite fully restoring
    # machine state; only an exact original request is deduplicated.
    _, second, _ = client.runtime(artifact)
    second_audit = second['result']['intervention']
    assert second_audit['id'] != audit['id'] and second_audit['beforePoint'] == after['point']
    assert registers(client) == before_registers
    assert process_stack(after['processInstanceId'], before_maps) == before_stack
    client.send(saved_frame)
    assert client.recv() == response and ledger(client)['total'] == 2
    # The generic ledger interleaves runtime, memory and register entries;
    # legacy pagination counts only its own category, even after runtime writes.
    counter = next(item for item in client.observation['stack'][0]['variables'] if item['name'] == 'counter')
    current = memory(client, counter['addressHex'], 4).hex()
    memory_audit = client.good({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': counter['addressHex'], 'expectedBytesHex': current, 'replacementBytesHex': current})['intervention']
    rax = next(item for item in before_registers if item['name'] == 'rax')
    current_register = f"0x{int(rax['valueHex'], 16):016x}"
    register_audit = client.good({'kind': 'writeRegister', 'profile': 'native-x86_64-gpr-v1',
        'register': 'rax', 'expectedValueHex': current_register, 'replacementValueHex': current_register})['intervention']
    assert not memory_audit['report']['writeAttempted'] and not register_audit['report']['writeAttempted']
    assert ledger(client)['items'] == [audit, second_audit, memory_audit, register_audit]
    assert client.good({'kind': 'listInterventions', 'start': 1, 'count': 2})['items'] == [second_audit, memory_audit]
    for kind, expected in (('Memory', memory_audit), ('Register', register_audit)):
        assert client.good({'kind': f'list{kind}Interventions', 'start': 0, 'count': 1})['items'] == [expected]
        page = client.good({'kind': f'list{kind}Interventions', 'start': 1, 'count': 1})
        assert page['total'] == 1 and page['items'] == [] and not page['hasMore']
    at_after(client)
    client.execute({'kind': 'continue'})
    state = client.checkpoint()['state']
    assert state['phase'] == 'terminated' and state['exit']['code'] == 0, state
    client.send(saved_frame)
    assert client.recv() == response
    assert client.good({'kind': 'readIntervention', 'interventionId': audit['id']})['intervention'] == audit
    return saved_frame


def input_isolation(client, artifact):
    launch(client, artifact, mode='i')
    before = at_hold(client)
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        capacity = fcntl.fcntl(descriptor, fcntl.F_SETPIPE_SZ, 4096)
        chunk = {'kind': 'appendInput', 'id': 'final-chunk', 'text': 'q' * (2 * capacity)}
        assert client.good(chunk)['input']['deliveredBytes'] == capacity
        closed = client.good({'kind': 'closeInput'})['input']
        assert closed['eof'] == 'requested' and closed['status'] == 'reading'
        assert os.read(descriptor, capacity) == b'q' * capacity
        saved, response, _ = client.runtime(artifact)
        assert response['result']['intervention']['contextStatus'] == 'refreshed'
        count = array.array('i', [0]); fcntl.ioctl(descriptor, termios.FIONREAD, count, True)
        assert count[0] == 0, 'runtime helper exposed pending stdin'
        try:
            data = os.read(descriptor, 1)
        except BlockingIOError:
            pass
        else:
            raise AssertionError(('runtime helper delivered bytes or EOF', data))
        assert client.good(chunk)['input'] == closed
        assert client.observation['input'] == closed
        client.send(saved)
        assert client.recv() == response
        at_after(client)
        total = next(item for item in client.observation['stack'][0]['variables'] if item['name'] == 'total')
        assert total['value']['value']['decimal'] == str(capacity), total
        assert client.observation['input']['deliveredBytes'] == 2 * capacity
        assert client.observation['input']['status'] == 'complete'
        assert os.read(descriptor, 1) == b''
        client.execute({'kind': 'continue'})
        assert client.checkpoint()['state']['exit']['code'] == 0
    finally:
        os.close(descriptor)


def preflight_rejections(client, artifact):
    launch(client, artifact, mode='t')
    before = at_hold(client)
    client.reject(client.frame(COMMAND), ('UNSUPPORTED',))
    assert client.checkpoint()['observation'] == before and ledger(client)['total'] == 0
    client.execute({'kind': 'stop'})
    launch(client, artifact, mode='w')
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'waiting'
    before = client.checkpoint()
    client.reject(client.frame(COMMAND), ('STALE_CONTEXT', 'UNSUPPORTED'))
    assert client.checkpoint() == before and ledger(client)['total'] == 0
    client.good({'kind': 'appendInput', 'id': 'resume-wait', 'text': 'x'})
    at_hold(client)
    client.execute({'kind': 'stop'})
    launch(client, artifact, recording=True)
    before = client.checkpoint()
    client.reject(client.frame(COMMAND), ('UNSUPPORTED',))
    assert client.checkpoint() == before and ledger(client)['total'] == 0
    client.execute({'kind': 'stop'})

    # A stopped blocking syscall has kernel restart state. Pause must not turn
    # that checkpoint into permission to redirect the syscall's return path.
    launch(client, artifact, mode='r')
    resume = client.frame({'kind': 'continue'})
    client.send(resume)
    deadline = time.monotonic() + 3
    syscall = Path(f"/proc/{client.observation['processInstanceId']}/syscall")
    while True:
        call = syscall.read_text().split()[0]
        if call in ('35', '230'):  # nanosleep / clock_nanosleep, native x86_64
            break
        assert time.monotonic() < deadline, call
        time.sleep(.01)
    pause = client.frame({'kind': 'pause'}, resume['expectedStop'])
    client.send(pause)
    client.finish([resume, pause])
    stopped_syscall = client.checkpoint()
    assert stopped_syscall['state']['phase'] == 'stopped'
    origin = next(item for item in registers(client) if item['name'] == 'orig_rax')
    assert int(origin['valueHex'], 16) in (35, 230), origin
    client.reject(client.frame(COMMAND), ('UNSUPPORTED', 'STALE_CONTEXT'))
    assert client.checkpoint() == stopped_syscall and ledger(client)['total'] == 0
    client.execute({'kind': 'stop'})

    launch(client, artifact)
    before = at_hold(client)
    os.kill(int(before['processInstanceId']), signal.SIGUSR1)
    pending = Path(f"/proc/{before['processInstanceId']}/status")
    deadline = time.monotonic() + 2
    while True:
        masks = [int(line.split(':', 1)[1], 16) for line in pending.read_text().splitlines() if line.startswith(('SigPnd:', 'ShdPnd:'))]
        if any(mask & (1 << (signal.SIGUSR1 - 1)) for mask in masks):
            break
        assert time.monotonic() < deadline
        time.sleep(.01)
    client.reject(client.frame(COMMAND), ('UNSUPPORTED', 'STALE_CONTEXT'))
    assert client.checkpoint()['observation'] == before and ledger(client)['total'] == 0
    client.execute({'kind': 'continue'})
    signal_stop = client.checkpoint()
    assert signal_stop['state']['phase'] == 'stopped'
    client.reject(client.frame(COMMAND), ('UNSUPPORTED', 'STALE_CONTEXT'))
    assert client.checkpoint() == signal_stop and ledger(client)['total'] == 0
    client.execute({'kind': 'stop'})


def seccomp_failures(client, artifact):
    for mode in ('g', 'm', 'p', 'u'):
        launch(client, artifact, mode=mode)
        before = at_hold(client)
        frame, response, _ = client.runtime(artifact)
        audit = response['result']['intervention']
        assert audit['report']['writeAttempted'], audit
        assert audit['contextStatus'] == 'failed' and audit['refreshError'], audit
        state = client.checkpoint()
        assert state['state']['phase'] == 'failed' and state['state']['live'] is None
        assert state['observation'] is None
        require_inferior_exited(before['processInstanceId'])
        assert ledger(client)['items'] == [audit]
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        client.send(frame)
        assert client.recv() == response
        assert client.good({'kind': 'readIntervention', 'interventionId': audit['id']})['intervention'] == audit


def shadowed_errno(client):
    # A real, linkable executable can override the ordinary errno symbol with
    # non-TLS storage. The helper must prove libc's TLS identity without
    # accepting an equally named user object or calling __errno_location.
    artifact = build(client, source='#include <cerrno>\n#undef errno\nint errno = 123;\n'
        'int main() { volatile int guard = 7; return guard - 7; }\n')
    client.execute({'kind': 'launch', 'buildId': artifact['id'],
        'input': {'id': 'shadow-input', 'text': '', 'encoding': 'utf-8', 'closeAfterWrite': False},
        'argv': [], 'environment': {}, 'stopAtEntry': True, 'recordingProfile': 'native'})
    before = client.checkpoint()
    baseline = registers(client)
    client.reject(client.frame(COMMAND), ('UNSUPPORTED',))
    assert client.checkpoint() == before and registers(client) == baseline
    assert ledger(client)['total'] == 0
    client.execute({'kind': 'continue'})
    assert client.checkpoint()['state']['exit']['code'] == 0


def proxy(path, real_gdb):
    """Forward real MI while injecting a fault at a named transaction boundary."""
    path.write_text(f'#!{sys.executable}\nREAL = {real_gdb!r}\n' + r'''
import json, os, pathlib, re, signal, subprocess, sys, threading, time
if '--version' in sys.argv:
    os.execv(REAL, [REAL, *sys.argv[1:]])
root = pathlib.Path(__file__).parent
child = subprocess.Popen([REAL, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
lock = threading.Lock()
prepare_token = execute_token = execute_ack_token = None
executed = False
mode = ''
def output(line):
    with lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
def fault():
    (root / 'fault').write_text(mode)
def forward():
    global executed
    for line in child.stdout:
        if mode == 'malformed-proof' and execute_token is not None and line.startswith(b'~'):
            text = json.loads(line[1:])
            prefix = 'PHANTOM_RUNTIME_HELPER_RESULT_V1:'
            if text.startswith(prefix):
                proof = json.loads(text[len(prefix):])
                proof['registersRestored'] = 1  # A number is not positive boolean evidence.
                line = b'~' + json.dumps(prefix + json.dumps(proof, separators=(',', ':')) + '\n').encode() + b'\n'
                fault()
        preparing = prepare_token is not None and line.startswith(prepare_token + b'^done')
        executing = execute_ack_token is not None and line.startswith(execute_ack_token + b'^done')
        if executing:
            executed = True
            if mode == 'ack-error':
                line = execute_ack_token + b'^error,msg="injected lost runtime acknowledgement"\n'
                fault()
        if (preparing and mode == 'prepare-cancel') or (executing and mode in ('cancel', 'timeout', 'queued-stop')):
            fault()
            while not (root / 'release').exists(): time.sleep(.005)
        output(line)
reader = threading.Thread(target=forward, daemon=True)
reader.start()
try:
    for line in sys.stdin.buffer:
        match = re.match(rb'(\d+)(.*)', line.rstrip(b'\n'))
        token, command = match.groups()
        if (root / 'arm').exists():
            mode = (root / 'mode').read_text()
            with (root / 'commands').open('ab') as file: file.write(line)
            if b'_phantom_runtime_helper_prepare(' in command:
                prepare_token = token
            if command == b'-interpreter-exec console "python _phantom_runtime_helper_execute()"':
                execute_token = token
                with (root / 'executions').open('ab') as file: file.write(line)
                if mode == 'signal-during':
                    # Send a real normally-pass SIGALRM at the first execution
                    # event, after the helper installed its signal guard.
                    script = "import os, signal\ndef _runtime_test_signal(event):\n gdb.events.cont.disconnect(_runtime_test_signal)\n os.kill(gdb.selected_inferior().pid, signal.SIGALRM)\n"
                    script += "gdb.events.cont.connect(_runtime_test_signal)\n_phantom_runtime_helper_execute()\n"
                    console = 'python exec(' + json.dumps(script) + ')'
                    line = token + b'-interpreter-exec console ' + json.dumps(console).encode() + b'\n'
                    fault()
            if execute_token is not None and command == b'-list-features':
                # A Python command resuming an MI inferior emits ^running;
                # its queued read-only barrier acknowledges complete return.
                execute_ack_token = token
            if executed and command == b'-stack-info-frame' and mode == 'refresh-death':
                fault()
                child.kill()
                break
        child.stdin.write(line)
        child.stdin.flush()
finally:
    if child.poll() is None: child.terminate()
    try: child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill(); child.wait()
    reader.join(timeout=.2)
''')
    path.chmod(0o700)


def wait_fault(path):
    deadline = time.monotonic() + 8
    while not path.exists():
        assert time.monotonic() < deadline, 'runtime fault boundary was not reached'
        time.sleep(.01)


def runtime_faults(executable, real_gdb, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    proxy(tools / 'gdb', real_gdb)
    environment = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')}
    client = Client(executable, workspace, environment)
    try:
        artifact = build(client)
        for mode in ('prepare-cancel', 'ack-error', 'malformed-proof', 'refresh-death',
                     'signal-during', 'cancel', 'timeout', 'queued-stop'):
            for name in ('arm', 'fault', 'release', 'commands', 'executions'):
                (tools / name).unlink(missing_ok=True)
            (tools / 'mode').write_text(mode)
            launch(client, artifact)
            before = at_hold(client)
            baseline = registers(client)
            signal_marker = Path(f"/proc/{before['processInstanceId']}/cwd").resolve() / 'runtime-signal-handler-ran'
            signal_marker.unlink(missing_ok=True)
            (tools / 'arm').touch()
            frame = client.frame(COMMAND)
            client.send(frame)
            wait_fault(tools / 'fault')
            started = time.monotonic()
            control = None
            if mode in ('prepare-cancel', 'cancel'):
                control = client.frame({'kind': 'cancel', 'targetRequestId': frame['requestId']})
                client.send(control)
                if mode == 'prepare-cancel':
                    # The read-only command finishes before cancellation is
                    # returned, so no stale MI acknowledgement can escape it.
                    time.sleep(.1)
                    (tools / 'release').touch()
            elif mode == 'queued-stop':
                control = client.frame({'kind': 'stop'})
                client.send(control)
                time.sleep(.1)
                (tools / 'release').touch()
            if mode == 'prepare-cancel':
                response = client.recv()
                assert response['requestId'] == frame['requestId'] and response['error']['code'] == 'CANCELLED', response
                accepted, finished = client.recv(), client.recv()
                assert accepted['requestId'] == control['requestId'] and accepted['ok']
                assert finished['payload']['kind'] == 'commandFinished' and finished['payload']['outcome'] == 'completed'
                assert client.checkpoint()['observation'] == before and registers(client) == baseline
                assert ledger(client)['total'] == 0 and not (tools / 'executions').exists()
                (tools / 'arm').unlink()
                _, recovered, _ = client.runtime(artifact)
                assert recovered['result']['intervention']['report']['outcome'] == 'verified'
                assert registers(client) == baseline and ledger(client)['total'] == 1
                client.execute({'kind': 'stop'})
                continue
            _, response, _ = client.receive_runtime(frame, artifact)
            audit = response['result']['intervention']
            assert (tools / 'fault').read_text() == mode
            assert len((tools / 'executions').read_bytes().splitlines()) == 1
            if mode in ('cancel', 'queued-stop'):
                accepted = client.recv()
                assert accepted['requestId'] == control['requestId'] and accepted['ok'], accepted
                if mode == 'cancel':
                    finished = client.recv()
                    assert finished['payload']['kind'] == 'commandFinished' and finished['payload']['outcome'] == 'completed'
                    assert audit['report']['cancelled'] and time.monotonic() - started < 4, audit
                else:
                    stopped = []
                    while not stopped or stopped[-1].get('payload', {}).get('kind') != 'commandFinished':
                        stopped.append(client.recv())
                    assert stopped[-1]['payload']['requestId'] == control['requestId']
                    assert stopped[-1]['payload']['outcome'] == 'completed'
                    assert audit['report']['outcome'] == 'verified' and not audit['report']['cancelled']
                    assert audit['contextStatus'] == 'refreshed'
                    assert client.checkpoint()['state']['phase'] == 'terminated'
            if mode != 'queued-stop':
                assert audit['contextStatus'] == 'failed' and audit['refreshError'], audit
                assert audit['report']['outcome'] == ('verified' if mode == 'refresh-death' else 'failed')
                assert audit['report']['cancelled'] == (mode == 'cancel')
                checkpoint = client.checkpoint()
                assert checkpoint['state']['phase'] == 'failed' and checkpoint['observation'] is None
                if mode == 'timeout':
                    assert audit['report']['error']['code'] == 'TIMEOUT', audit
                    assert 5 < time.monotonic() - started < 15
            require_inferior_exited(before['processInstanceId'])
            assert not signal_marker.exists(), 'signal handler executed during the runtime helper'
            assert ledger(client)['items'] == [audit]
            assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
            client.send(frame)
            assert client.recv() == response
            assert len((tools / 'executions').read_bytes().splitlines()) == 1
            client.reject(client.frame({'kind': 'cancel', 'targetRequestId': frame['requestId']}), ('STALE_CONTEXT',))
    finally:
        client.close()


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    executable = str(Path(sys.argv[1]).resolve())
    real_gdb = str(Path(shutil.which('gdb')).resolve())
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-helper-') as directory:
        client = Client(executable, Path(directory), dict(os.environ))
        try:
            native = build(client, runtime=False)
            launch(client, native)
            at_hold(client)
            client.reject(client.frame(COMMAND), ('UNSUPPORTED',))
            assert ledger(client)['total'] == 0
            client.execute({'kind': 'stop'})
            artifact = build(client)
            assert artifact['id'] != native['id'], 'runtime opt-in reused the ordinary build identity'
            old_frame = successful(client, artifact)
            input_isolation(client, artifact)
            client.reject(old_frame, ('STALE_CONTEXT',))
            preflight_rejections(client, artifact)
            seccomp_failures(client, artifact)
            shadowed_errno(client)
        finally:
            client.close()
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-helper-faults-') as directory:
        runtime_faults(executable, real_gdb, Path(directory))
    print('runtime helper: opt-in identity, nested frame restoration, machine state, stdin/EOF, guards, denied syscalls, signal/cancel/timeout/ack faults and once-only audit passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
