"""Checked native memory edits through NDJSON, with retained branch evidence."""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'native-private-memory-v1'
SOURCE = r'''#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <atomic>
static std::atomic<bool> threadReady{false};
static void* worker(void*) {
  threadReady.store(true);
  for (;;) pause();
  return nullptr;
}
int main(int argc, char** argv) {
  volatile unsigned int counter = 7;
  if (argc > 1 && argv[1][0] == 'w') {
    char input = 0;
    if (read(0, &input, 1) != 1) return 90;
  }
  const unsigned long page = static_cast<unsigned long>(sysconf(_SC_PAGESIZE));
  void* arena = mmap(nullptr, 5 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (arena == MAP_FAILED) return 91;
  auto* middle = static_cast<unsigned char*>(arena) + page;
  auto* readOnly = static_cast<unsigned char*>(arena) + 3 * page;
  if (mprotect(middle, page, PROT_READ | PROT_WRITE) || mprotect(readOnly, page, PROT_READ)) return 92;
  for (unsigned i = 0; i < 256; ++i) middle[i] = static_cast<unsigned char>(i);
  middle[page - 1] = 0xa7;
  void* executable = mmap(nullptr, page, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  void* shared = mmap(nullptr, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (executable == MAP_FAILED || shared == MAP_FAILED) return 93;
  pthread_t thread{};
  if (argc > 1 && argv[1][0] == 't') {
    if (pthread_create(&thread, nullptr, worker, nullptr)) return 94;
    while (!threadReady.load()) {}
  }
  if (write(1, "kept\n", 5) != 5) return 95;
  asm volatile("nop" : : : "memory"); // EDIT
  counter = counter + 1;
  if (write(1, "done\n", 5) != 5) return 96;
  asm volatile("nop" : : : "memory"); // AFTER
  return counter == 44 ? 0 : 97;
}
'''


class Client(BaseClient):
    def send(self, frame):
        if self.record_requests:
            TRAFFIC.append(('request', frame))
        return TransportClient.send(self, frame)

    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command):
        frame = super().frame(command)
        if command['kind'] in ('writeMemory', 'readRecording') and self.observation is not None:
            frame['expectedStop'] = self.observation['stop']
        return frame

    def launch_edit(self, artifact, *, argv=(), text='', recording=False):
        events = self.execute({'kind': 'launch', 'buildId': artifact['id'],
            'input': {'id': 'edit-input', 'text': text, 'encoding': 'utf-8',
                      'closeAfterWrite': recording},
            'argv': list(argv), 'environment': {}, 'stopAtEntry': True,
            'recordingProfile': 'gdb-record-full' if recording else 'native'})
        assert events[-1]['payload']['outcome'] == 'completed', events

    def edit(self, command):
        frame = self.frame(command)
        response = self.send(frame)
        assert response['ok'] and response['requestId'] == frame['requestId'], response
        result = response['result']
        assert result['kind'] == 'memoryIntervention', result
        intervention = result['intervention']
        report = intervention['report']
        assert intervention['requestId'] == frame['requestId'] and intervention['profile'] == PROFILE
        assert report['atomic'] is False and report['rollbackAttempted'] is False, report
        events = []
        if report['writeAttempted']:
            events = [self.recv() for _ in range(3)]
            assert [e['payload']['kind'] for e in events] == ['branchCreated', 'observation', 'state'], events
            assert all(e.get('causedByRequestId') == frame['requestId'] for e in events), events
            assert events[0]['payload']['parent'] == intervention['beforePoint']
            assert events[0]['payload']['branchId'] == intervention['branchId']
            self.observation = events[1]['payload']['observation']
            assert self.observation['reason'] == 'mutation', self.observation
            assert self.observation['point'] == intervention['afterPoint']
            assert self.observation['stop'] == intervention['afterStop']
            assert events[2]['payload']['state']['live'] == {
                'point': intervention['afterPoint'], 'stop': intervention['afterStop']}
            assert result['throughSequence'] == events[-1]['sequence'], result
        else:
            assert intervention['branchId'] is None
            assert intervention['afterPoint'] is None and intervention['afterStop'] is None
            assert intervention['contextStatus'] == 'unchanged'
        return frame, response, events


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'memory-edit', 'revisionId': 'memory-edit-1',
            'range': {'start': offset, 'end': offset},
            'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def breakpoints(client):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'memory-edit', 'revisionId': 'memory-edit-1',
        'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True} for marker in ('EDIT', 'AFTER')]})
    assert all(bp['verified'] for bp in result['breakpoints']), result


def at_edit(client):
    breakpoints(client)
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'completed', events
    assert client.observation['location']['start']['line'] == location('EDIT')['start']['line'], client.observation
    return client.observation


def variable(client, name):
    return next(v for v in client.observation['stack'][0]['variables'] if v['name'] == name)


def pointer(client, name):
    return int(variable(client, name)['value']['value']['addressHex'], 16)


def memory(client, address, count):
    result = client.good({'kind': 'readMemory', 'addressHex': hex(address), 'byteCount': count})
    data = base64.b64decode(result['bytesBase64'], validate=True)
    assert len(data) == count and result['unreadableBytes'] == 0, result
    return data


def write(address, before, after):
    return {'kind': 'writeMemory', 'profile': PROFILE, 'addressHex': hex(address),
            'expectedBytesHex': before.hex(), 'replacementBytesHex': after.hex()}


def number(value):
    return value.to_bytes(4, 'little')


def audits(client):
    result = client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})
    assert result['kind'] == 'memoryInterventions' and result['start'] == 0, result
    return result


def journal(client, point):
    return client.good({'kind': 'readOutputJournal', 'stream': 'stdout',
                        'fromByte': 0, 'byteCount': 64, 'point': point})


def reject_frame(client, frame, code, *, valid=True):
    client.record_requests = valid
    try:
        response = client.send(frame)
    finally:
        client.record_requests = True
    if valid:
        assert response.get('requestId') == frame['requestId'], response
    assert not response['ok'] and response['error']['code'] == code, response
    return response


def verify_native(client, artifact):
    client.launch_edit(artifact)
    entry = client.observation
    before = at_edit(client)
    initial_state = client.good({'kind': 'getState'})
    address = int(variable(client, 'counter')['addressHex'], 16)
    assert memory(client, address, 4) == number(7)
    saved = client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': hex(address), 'byteCount': 4}]})['capture']
    original_journal = journal(client, before['point'])
    assert base64.b64decode(original_journal['segments'][0]['bytesBase64']) == b'kept\n'
    initial_branches = client.good({'kind': 'listBranches'})
    assert initial_branches == {'kind': 'branches', 'currentBranchId': 'main',
                                'branches': [{'id': 'main', 'parent': None, 'interventionId': None}]}, initial_branches
    assert audits(client)['total'] == 0

    # Shape/context/map rejection cannot consume an intervention slot or write.
    valid = write(address, number(7), number(42))
    for patch in ({'profile': 'auto'}, {'addressHex': '0x1\n-exec-continue'},
                  {'addressHex': '0xffffffffffffffff'}, {'expectedBytesHex': ''},
                  {'expectedBytesHex': '0'}, {'expectedBytesHex': 'zz'},
                  {'replacementBytesHex': '01'}, {'expectedBytesHex': '00' * 257, 'replacementBytesHex': '01' * 257},
                  {'expression': 'counter = 42'}):
        client.bad({**valid, **patch})
    missing = client.frame(valid); del missing['expectedStop']
    reject_frame(client, missing, 'INVALID_REQUEST', valid=False)
    stale = client.frame(valid); stale['expectedStop'] = entry['stop']
    reject_frame(client, stale, 'STALE_CONTEXT')
    no_session = client.frame(valid); no_session['session'] = None
    reject_frame(client, no_session, 'STALE_CONTEXT')
    middle = pointer(client, 'middle')
    page = int(variable(client, 'page')['value']['value']['decimal'])
    for target, count in ((pointer(client, 'readOnly'), 1), (pointer(client, 'executable'), 1),
                          (pointer(client, 'shared'), 1), (middle + page, 1), (middle + page - 1, 2), (0, 1)):
        client.bad(write(target, bytes(count), b'\x01' * count), ('INVALID_REQUEST',))
    assert audits(client)['total'] == 0
    assert client.good({'kind': 'getState'}) == initial_state

    conflict_frame, conflict, _ = client.edit(write(address, number(8), number(42)))
    record = conflict['result']['intervention']; report = record['report']
    assert report['outcome'] == 'conflict' and report['beforeBytesHex'] == number(7).hex(), report
    assert report['beforeMatchesExpected'] is False and not report['writeAttempted'] and not report['writeAcknowledged']
    assert client.good({'kind': 'getState'}) == initial_state
    assert client.send(conflict_frame) == conflict
    assert audits(client)['total'] == 1
    noop_frame, noop, _ = client.edit(write(address, number(7), number(7)))
    assert noop['result']['intervention']['report']['outcome'] == 'unchanged', noop
    assert client.good({'kind': 'getState'}) == initial_state
    assert client.send(noop_frame) == noop

    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rax']})['registers']
    successful_frame, successful, _ = client.edit(valid)
    intervention = successful['result']['intervention']; report = intervention['report']
    assert intervention['contextStatus'] == 'refreshed', intervention
    assert report['outcome'] == 'verified' and report['writeAcknowledged'] and report['debuggerAlive'], report
    assert report['beforeBytesHex'] == number(7).hex() and report['afterBytesHex'] == number(42).hex()
    assert report['beforeMatchesExpected'] and report['afterMatchesReplacement'] and not report['afterMatchesBefore']
    first_branch = intervention['branchId']; first = client.observation
    assert first_branch != 'main' and first['point']['branchId'] == first_branch
    assert first['stop']['stateRevision'] > before['stop']['stateRevision']
    assert first['input'] == before['input'] and first['stdout'] == before['stdout']
    assert first['processInstanceId'] == before['processInstanceId']
    assert int(variable(client, 'counter')['value']['value']['decimal']) == 42
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rax']})['registers'] == registers
    assert memory(client, address, 4) == number(42)
    assert client.send(successful_frame) == successful  # Deliberately carries the now stale expectedStop.
    assert client.good({'kind': 'getState'})['throughSequence'] == successful['result']['throughSequence']
    changed_id = {**successful_frame, 'command': write(address, number(7), number(43))}
    reject_frame(client, changed_id, 'INVALID_REQUEST')
    reused_id = {**successful_frame, 'command': {'kind': 'getState'}}
    reject_frame(client, reused_id, 'INVALID_REQUEST')
    assert memory(client, address, 4) == number(42)
    assert audits(client)['total'] == 3

    branches = client.good({'kind': 'listBranches'})
    assert branches['currentBranchId'] == first_branch and branches['branches'][1] == {
        'id': first_branch, 'parent': before['point'], 'interventionId': intervention['id']}, branches
    original_history = client.good({'kind': 'listHistory', 'branchId': 'main', 'afterOrdinal': None, 'limit': 100})
    assert [item['point'] for item in original_history['items']] == [entry['point'], before['point']]
    branch_history = client.good({'kind': 'listHistory', 'branchId': first_branch, 'afterOrdinal': None, 'limit': 100})
    assert [item['point'] for item in branch_history['items']] == [first['point']]
    for wrong_point in ({'branchId': first_branch, 'eventOrdinal': before['point']['eventOrdinal']},
                        {'branchId': 'main', 'eventOrdinal': first['point']['eventOrdinal']}):
        client.bad({'kind': 'readHistory', 'point': wrong_point}, ('HISTORY_EVICTED',))
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readMemoryCapture', 'captureId': saved['id']})['capture'] == saved
    assert journal(client, before['point']) == original_journal
    changed_capture = client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': hex(address), 'byteCount': 4}]})['capture']
    delta = client.good({'kind': 'diffMemoryCaptures', 'beforeCaptureId': saved['id'],
                        'afterCaptureId': changed_capture['id'], 'start': 0, 'count': 10})
    assert delta['changedBytes'] == 1 and delta['changes'][0]['beforeBytesHex'] == '07' and delta['changes'][0]['afterBytesHex'] == '2a', delta

    _, second_response, _ = client.edit(write(address, number(42), number(43)))
    second = second_response['result']['intervention']; second_branch = second['branchId']
    assert second_branch not in ('main', first_branch)
    assert second['beforePoint'] == first['point'] and second['beforeStop'] == first['stop']
    assert client.good({'kind': 'listBranches'})['branches'][2] == {
        'id': second_branch, 'parent': first['point'], 'interventionId': second['id']}
    assert client.good({'kind': 'listHistory', 'branchId': first_branch, 'afterOrdinal': None, 'limit': 100}) == branch_history
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': intervention['id']})['intervention'] == intervention
    all_records = audits(client)
    assert all_records['total'] == 4 and not all_records['hasMore']
    one = client.good({'kind': 'listMemoryInterventions', 'start': 1, 'count': 1})
    assert one['items'] == [noop['result']['intervention']] and one['hasMore']
    empty = client.good({'kind': 'listMemoryInterventions', 'start': 9007199254740991, 'count': 1})
    assert empty['items'] == [] and not empty['hasMore']
    client.bad({'kind': 'readMemoryIntervention', 'interventionId': 'missing'}, ('HISTORY_EVICTED',))

    trace_before = client.observation['point']
    events = client.execute({'kind': 'traceInstructions', 'count': 1, 'registers': ['rip'],
                             'memoryRanges': [{'addressHex': hex(address), 'byteCount': 4}]})
    trace_event = next(e['payload'] for e in events if e['payload']['kind'] == 'instructionTraceRecorded')
    trace = client.good({'kind': 'readInstructionTrace', 'traceId': trace_event['traceId'], 'start': 0, 'count': 1})
    assert trace['trace']['beforePoint'] == trace_before
    assert trace['trace']['afterPoint']['branchId'] == second_branch
    assert base64.b64decode(trace['trace']['initialMemory'][0]['bytesBase64']) == number(43)
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('AFTER')['start']['line']
    assert int(variable(client, 'counter')['value']['value']['decimal']) == 44
    physical_output = journal(client, before['point'])
    assert physical_output['selectedPoint'] == before['point'] and physical_output['selectedThroughByte'] == 5
    assert physical_output['totalBytes'] == 10
    assert b''.join(base64.b64decode(s['bytesBase64']) for s in physical_output['segments']) == b'kept\ndone\n'
    client.execute({'kind': 'continue'})
    state = client.good({'kind': 'getState'})['state']
    assert state['phase'] == 'terminated' and state['exit']['code'] == 0, state
    assert client.send(successful_frame) == successful  # Dedup also precedes the live-inferior gate.
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': intervention['id']})['intervention'] == intervention
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readMemoryCapture', 'captureId': saved['id']})['capture'] == saved
    assert client.good({'kind': 'readInstructionTrace', 'traceId': trace_event['traceId'], 'start': 0, 'count': 1}) == trace
    previous_session = client.session
    client.launch_edit(artifact)
    assert audits(client)['total'] == 0 and client.good({'kind': 'listBranches'}) == initial_branches
    client.bad({'kind': 'readMemoryIntervention', 'interventionId': intervention['id']}, ('HISTORY_EVICTED',))
    stale_audit = client.frame({'kind': 'readMemoryIntervention', 'interventionId': intervention['id']})
    stale_audit['session'] = previous_session
    reject_frame(client, stale_audit, 'STALE_CONTEXT')
    reject_frame(client, successful_frame, 'STALE_CONTEXT')
    client.execute({'kind': 'stop'})


def verify_limits(client, artifact):
    client.launch_edit(artifact)
    at_edit(client)
    middle = pointer(client, 'middle')
    expected = bytes(range(256)); replacement = bytes(reversed(range(256)))
    _, response, _ = client.edit(write(middle, expected, replacement))
    assert response['result']['intervention']['report']['outcome'] == 'verified'
    assert memory(client, middle, 256) == replacement
    stable = client.good({'kind': 'getState'})
    first_noop = None
    for _ in range(127):
        frame, result, _ = client.edit(write(middle, replacement[:1], replacement[:1]))
        if first_noop is None:
            first_noop = frame, result
    assert audits(client)['total'] == 128
    client.bad(write(middle, replacement[:1], expected[:1]), ('LIMIT_EXCEEDED',))
    assert client.send(first_noop[0]) == first_noop[1]
    assert audits(client)['total'] == 128
    assert client.good({'kind': 'getState'}) == stable
    assert memory(client, middle, 256) == replacement
    assert len(client.good({'kind': 'listBranches'})['branches']) == 2
    client.execute({'kind': 'stop'})


def verify_input_is_not_fed(client, artifact):
    # Free FIFO capacity externally while every inferior thread is stopped.
    # This makes a hidden input pump observable without executing target code.
    client.launch_edit(artifact, text='q' * 131072)
    before = at_edit(client)
    delivered = before['input']['deliveredBytes']
    assert 4096 <= delivered < 131072, before['input']
    address = int(variable(client, 'counter')['addressHex'], 16)
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert os.read(descriptor, 4096) == b'q' * 4096
        _, response, _ = client.edit(write(address, number(7), number(42)))
    finally:
        os.close(descriptor)
    assert response['result']['intervention']['report']['outcome'] == 'verified'
    assert client.observation['input'] == before['input'], client.observation['input']
    client.execute({'kind': 'stop'})


def verify_unsupported(client, artifact):
    client.launch_edit(artifact, argv=('t',))
    before = at_edit(client)
    address = int(variable(client, 'counter')['addressHex'], 16)
    client.bad(write(address, number(7), number(42)), ('UNSUPPORTED',))
    assert audits(client)['total'] == 0
    assert client.good({'kind': 'getState'})['observation'] == before
    assert memory(client, address, 4) == number(7)
    client.execute({'kind': 'stop'})

    client.launch_edit(artifact, argv=('w',))
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'waiting', events
    waiting = client.good({'kind': 'getState'})
    assert waiting['state']['phase'] == 'waitingForInput', waiting
    client.bad(write(1, b'\0', b'\1'), ('STALE_CONTEXT',))
    assert audits(client)['total'] == 0
    assert client.good({'kind': 'getState'}) == waiting
    client.execute({'kind': 'stop'})

    client.launch_edit(artifact, recording=True)
    recording = client.good({'kind': 'readRecording'})
    state = client.good({'kind': 'getState'})
    client.bad(write(1, b'\0', b'\1'), ('UNSUPPORTED',))
    assert client.good({'kind': 'readRecording'}) == recording
    assert client.good({'kind': 'getState'}) == state
    assert audits(client)['total'] == 0
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-memory-edits-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            for command in ({'kind': 'listBranches'}, {'kind': 'listMemoryInterventions', 'start': 0, 'count': 1},
                            {'kind': 'readMemoryIntervention', 'interventionId': 'missing'}):
                client.bad(command, ('STALE_CONTEXT',))
            result = client.good({'kind': 'build', 'source': {'id': 'memory-edit-source', 'documents': [{
                'documentId': 'memory-edit', 'revisionId': 'memory-edit-1', 'path': 'memory-edit.cpp',
                'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
                'configuration': {'revisionId': 'memory-edit-config', 'compiler': 'clang++',
                    'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build',
                    'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
            assert result['success'], result
            artifact = result['artifact']
            verify_native(client, artifact)
            verify_limits(client, artifact)
            verify_input_is_not_fed(client, artifact)
            verify_unsupported(client, artifact)
        finally:
            client.close()
    print('memory edit integration: checked writes, immutable branches/audits, idempotency, retention, input isolation, limits and profile guards passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
