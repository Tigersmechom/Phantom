"""Typed scalar storage edits through the public protocol and retained history."""
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
PROFILE = 'native-dwarf-scalar-v1'
SOURCE = r'''#include <atomic>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
struct Object { int value; };
enum Number { One = 1, Two = 2 };
using Byte = unsigned char;
using Unsigned = unsigned long long;
static std::atomic<bool> threadReady{false};
static void* worker(void*) {
  threadReady.store(true);
  for (;;) pause();
  return nullptr;
}
__attribute__((noinline)) void nested(int argument) {
  int local = argument;
  asm volatile("nop" : "+m"(local) : : "memory"); // NESTED
}
int main(int argc, char** argv) {
  int scalar = 7;
  unsigned int unsignedValue = 9;
  signed char signedByte = -5;
  Byte byte = 3;
  short shortValue = 11;
  unsigned short unsignedShort = 13;
  long long signedWide = -17;
  Unsigned unsignedWide = 19;
  char character = 'A';
  bool flag = false;
  const int constant = 23;
  volatile int volatileValue = 29;
  int& reference = scalar;
  int* pointer = &scalar;
  float floating = 1.5f;
  double doubleValue = 2.5;
  Number enumeration = One;
  Object object{31};
  int array[2] = {37, 41};
  std::atomic<int> atomicValue{43};
  pthread_t thread{};
  if (argc > 1 && argv[1][0] == 't') {
    if (pthread_create(&thread, nullptr, worker, nullptr)) return 90;
    while (!threadReady.load()) {}
  }
  if (write(1, "kept\n", 5) != 5) return 91;
  asm volatile("nop" : : : "memory"); // READY
  if (argc > 1 && argv[1][0] == 'w') {
    char input = 0;
    if (read(0, &input, 1) != 1) return 92;
  }
  nested(scalar);
  {
    int scalar = 47;
    asm volatile("nop" : "+m"(scalar) : : "memory"); // SHADOWED
  }
  asm volatile("nop" : : : "memory"); // AFTER
  return 0;
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
        if command['kind'] in ('inspectScalarStorage', 'writeScalarStorage', 'writeMemory',
                               'readVariables', 'readRecording') and self.observation is not None:
            frame['expectedStop'] = self.observation['stop']
        return frame

    def launch_scalar(self, artifact, *, text='', argv=(), recording=False):
        events = self.execute({'kind': 'launch', 'buildId': artifact['id'],
            'input': {'id': 'scalar-input', 'text': text, 'encoding': 'utf-8',
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
        audit = result['intervention']
        report = audit['report']
        assert audit['requestId'] == frame['requestId'], audit
        assert report['atomic'] is False and report['rollbackAttempted'] is False, report
        events = []
        if report['writeAttempted']:
            events = [self.recv() for _ in range(3)]
            assert [event['payload']['kind'] for event in events] == ['branchCreated', 'observation', 'state'], events
            assert all(event.get('causedByRequestId') == frame['requestId'] for event in events), events
            assert events[0]['payload']['parent'] == audit['beforePoint']
            assert events[0]['payload']['branchId'] == audit['branchId']
            self.observation = events[1]['payload']['observation']
            assert self.observation['reason'] == 'mutation', self.observation
            assert self.observation['point'] == audit['afterPoint']
            assert self.observation['stop'] == audit['afterStop']
            assert events[2]['payload']['state']['live'] == {
                'point': audit['afterPoint'], 'stop': audit['afterStop']}
            assert result['throughSequence'] == events[-1]['sequence'], result
        else:
            assert audit['branchId'] is None and audit['afterPoint'] is None and audit['afterStop'] is None
            assert audit['contextStatus'] == 'unchanged', audit
        return frame, response, events


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'scalar-storage', 'revisionId': 'scalar-storage-1',
            'range': {'start': offset, 'end': offset},
            'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def set_breakpoints(client, markers):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'scalar-storage',
        'revisionId': 'scalar-storage-1', 'breakpoints': [
            {'id': marker, 'range': location(marker), 'enabled': True} for marker in markers]})
    assert all(item['verified'] for item in result['breakpoints']), result


def at_ready(client):
    set_breakpoints(client, ('READY',))
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'completed', events
    assert client.observation['location']['start']['line'] == location('READY')['start']['line'], client.observation
    return client.observation


def memory(client, address, count):
    result = client.good({'kind': 'readMemory', 'addressHex': address, 'byteCount': count})
    data = base64.b64decode(result['bytesBase64'], validate=True)
    assert len(data) == count and result['unreadableBytes'] == 0, result
    return data


def audits(client):
    return client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})


def reject_frame(client, frame, code, *, valid=True):
    client.record_requests = valid
    try:
        response = client.send(frame)
    finally:
        client.record_requests = True
    assert not response['ok'] and response['error']['code'] == code, response
    return response


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'scalar-storage-source', 'documents': [{
        'documentId': 'scalar-storage', 'revisionId': 'scalar-storage-1', 'path': 'scalar-storage.cpp',
        'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'scalar-storage-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def inspect(client, name, *, frame=0, available=True):
    locator = f'frame:{frame}:{name}'
    result = client.good({'kind': 'inspectScalarStorage', 'locator': locator})
    assert result['kind'] == 'scalarStorage', result
    snapshot = result['snapshot']
    assert snapshot['type'] == 'scalarStorageSnapshot' and snapshot['profile'] == PROFILE, snapshot
    assert snapshot['point'] == client.observation['point'] and snapshot['stop'] == client.observation['stop']
    assert snapshot['processInstanceId'] == client.observation['processInstanceId']
    target = snapshot['target']
    assert target['source'] == 'gdb-python-dwarf' and target['locator'] == locator, target
    assert target['lifetime'] == 'unknown', target
    assert target['available'] is available, target
    storage = snapshot['storage']
    if available:
        assert storage['available'] and storage['reason'] is None, storage
        scalar = target['scalar']
        assert scalar['byteSize'] in (1, 2, 4, 8) and scalar['bits'] == scalar['byteSize'] * 8, scalar
        assert scalar['byteOrder'] == 'little'
        assert memory(client, target['addressHex'], scalar['byteSize']).hex() == storage['bytesHex'], snapshot
    else:
        assert not storage['available'] and storage['value'] is None and storage['bytesHex'] is None, snapshot
    return snapshot


def integer(value, bits=32, signed=True):
    return {'kind': 'integer', 'decimal': str(value), 'bits': bits, 'signed': signed}


def boolean(value):
    return {'kind': 'boolean', 'value': value}


def write(snapshot, value):
    return {'kind': 'writeScalarStorage', 'profile': PROFILE, 'snapshotId': snapshot['id'], 'value': value}


def raw_write(snapshot, replacement):
    return {'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': snapshot['target']['addressHex'], 'expectedBytesHex': snapshot['storage']['bytesHex'],
        'replacementBytesHex': replacement.hex()}


def read_snapshot(client, snapshot):
    assert client.good({'kind': 'readScalarStorage', 'snapshotId': snapshot['id']})['snapshot'] == snapshot


def verify_native(client, artifact):
    client.launch_scalar(artifact)
    # A readable frame slot is not evidence that the declaration/lifetime ran.
    entry_snapshot = inspect(client, 'scalar')
    assert entry_snapshot['target']['lifetime'] == 'unknown'
    before = at_ready(client)
    assert all(not value['writable'] for value in before['stack'][0]['variables'])
    scalar = inspect(client, 'scalar')
    assert scalar['storage']['value'] == integer(7)
    assert scalar['target']['scalar']['representation'] == 'twos-complement'
    assert audits(client)['total'] == 0
    stable = client.good({'kind': 'getState'})
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})
    read_snapshot(client, scalar)
    read_snapshot(client, entry_snapshot)
    assert client.good({'kind': 'getState'}) == stable

    # No caller expressions, implicit width/sign conversion or lossy integers.
    valid = write(scalar, integer(42))
    for value in (integer('01'), integer('+1'), integer('-0'), integer(' 1'), integer('1 '),
                  integer('1e2'), integer('0x10'), integer('1\ncontinue'),
                  integer(1, 64), integer(1, 32, False), integer(2**31), integer(-2**31 - 1),
                  boolean(True), {'kind': 'integer', 'decimal': 42, 'bits': 32, 'signed': True},
                  {'kind': 'float', 'text': '1.5', 'bits': 32, 'classification': 'finite'},
                  {'kind': 'pointer', 'addressHex': '0x1', 'pointeeType': 'int'}):
        client.bad({**valid, 'value': value})
    for patch in ({'profile': 'native-private-memory-v1'}, {'locator': 'frame:0:scalar'},
                  {'addressHex': scalar['target']['addressHex']}, {'expression': 'scalar = 42'}):
        client.bad({**valid, **patch})
    for locator in ('frame:0:scalar + 1', 'frame:0:*pointer', 'frame:0:object.value',
                    'frame:0:scalar\ncontinue', 'frame:00:scalar', 'frame:4096:scalar'):
        client.bad({'kind': 'inspectScalarStorage', 'locator': locator})
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:0:missing'}, ('READ_FAILED',))
    client.bad(write({**scalar, 'id': 'missing'}, integer(42)), ('HISTORY_EVICTED',))
    missing_stop = client.frame(valid); del missing_stop['expectedStop']
    reject_frame(client, missing_stop, 'INVALID_REQUEST', valid=False)
    stale = client.frame(valid); stale['expectedStop'] = entry_snapshot['stop']
    reject_frame(client, stale, 'STALE_CONTEXT')
    client.bad(write(entry_snapshot, integer(42)), ('STALE_CONTEXT',))
    assert client.good({'kind': 'getState'}) == stable and audits(client)['total'] == 0
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']}) == registers

    for name in ('constant', 'volatileValue', 'reference', 'pointer', 'floating', 'doubleValue',
                 'enumeration', 'object', 'array', 'atomicValue'):
        unsupported = inspect(client, name, available=False)
        assert unsupported['target']['reason'], unsupported
        client.bad(write(unsupported, integer(1)), ('UNSUPPORTED',))
    assert audits(client)['total'] == 0

    noop_frame, noop, events = client.edit(write(scalar, integer(7)))
    assert not events and noop['result']['intervention']['report']['outcome'] == 'unchanged'
    assert client.good({'kind': 'getState'}) == stable
    assert client.send(noop_frame) == noop
    first_frame, first_response, events = client.edit(valid)
    first_audit = first_response['result']['intervention']
    assert first_audit['profile'] == PROFILE and first_audit['report']['outcome'] == 'verified', first_audit
    origin = first_audit['scalar']
    assert origin == {'snapshotId': scalar['id'], 'locator': 'frame:0:scalar', 'target': scalar['target'],
        'requestedValue': integer(42), 'beforeValue': integer(7), 'afterValue': integer(42)}, origin
    assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
    assert memory(client, scalar['target']['addressHex'], 4) == (42).to_bytes(4, 'little')
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers'] == registers['registers']
    read_snapshot(client, scalar)
    client.bad(write(scalar, integer(43)), ('STALE_CONTEXT',))
    assert client.send(first_frame) == first_response
    changed = {**first_frame, 'command': write(scalar, integer(43))}
    reject_frame(client, changed, 'INVALID_REQUEST')

    # Byte encoding follows target metadata, including char typedefs and values
    # well beyond JavaScript's exact Number range.
    cases = [('scalar', -2**31, 32, True), ('scalar', 2**31 - 1, 32, True),
             ('unsignedValue', 2**32 - 1, 32, False), ('signedByte', -128, 8, True),
             ('signedByte', 127, 8, True), ('byte', 255, 8, False),
             ('shortValue', -32768, 16, True), ('unsignedShort', 65535, 16, False),
             ('signedWide', -2**63, 64, True), ('signedWide', 2**63 - 1, 64, True),
             ('unsignedWide', 2**64 - 1, 64, False), ('unsignedWide', 0, 64, False),
             ('character', -1, 8, True)]
    for name, number, bits, signed in cases:
        snapshot = inspect(client, name)
        assert snapshot['target']['scalar']['signed'] is signed, snapshot
        desired = integer(number, bits, signed)
        _, response, _ = client.edit(write(snapshot, desired))
        audit = response['result']['intervention']; report = audit['report']
        encoded = number.to_bytes(bits // 8, 'little', signed=signed).hex()
        assert report['outcome'] == 'verified' and report['replacementBytesHex'] == encoded, report
        assert report['afterBytesHex'] == encoded and audit['scalar']['afterValue'] == desired, audit
        fresh = inspect(client, name)
        assert fresh['storage']['value'] == desired and fresh['storage']['bytesHex'] == encoded, fresh
        read_snapshot(client, snapshot)
    for desired in (True, False):
        snapshot = inspect(client, 'flag')
        assert snapshot['target']['scalar']['representation'] == 'boolean-01'
        assert snapshot['target']['scalar']['signed'] is None
        client.bad(write(snapshot, integer(int(desired), 8, False)))
        _, response, _ = client.edit(write(snapshot, boolean(desired)))
        assert response['result']['intervention']['scalar']['afterValue'] == boolean(desired)
        assert memory(client, snapshot['target']['addressHex'], 1) == bytes([desired])

    # Raw and typed edits share stop invalidation and a single lineage/ledger.
    snapshot = inspect(client, 'scalar')
    _, raw_response, _ = client.edit(raw_write(snapshot, (91).to_bytes(4, 'little')))
    assert raw_response['result']['intervention']['profile'] == 'native-private-memory-v1'
    assert 'scalar' not in raw_response['result']['intervention']
    client.bad(write(snapshot, integer(92)), ('STALE_CONTEXT',))
    assert inspect(client, 'scalar')['storage']['value'] == integer(91)

    # At the same logical stop an external debugger can still alter storage.
    # Fresh byte comparison must detect that, with neither write nor branch.
    snapshot = inspect(client, 'scalar')
    unchanged_stop = client.observation['stop']
    descriptor = os.open(f"/proc/{client.observation['processInstanceId']}/mem", os.O_RDWR)
    try:
        assert os.pwrite(descriptor, (92).to_bytes(4, 'little'), int(snapshot['target']['addressHex'], 16)) == 4
    finally:
        os.close(descriptor)
    branch_count = len(client.good({'kind': 'listBranches'})['branches'])
    _, conflict, events = client.edit(write(snapshot, integer(93)))
    report = conflict['result']['intervention']['report']
    assert report['outcome'] == 'conflict' and report['beforeBytesHex'] == '5c000000', report
    assert not events and client.observation['stop'] == unchanged_stop
    assert len(client.good({'kind': 'listBranches'})['branches']) == branch_count
    assert memory(client, snapshot['target']['addressHex'], 4) == (92).to_bytes(4, 'little')

    # A noncanonical bool byte remains raw evidence, never silently coerced.
    flag = inspect(client, 'flag')
    client.edit(raw_write(flag, b'\x02'))
    invalid_flag = client.good({'kind': 'inspectScalarStorage', 'locator': 'frame:0:flag'})['snapshot']
    assert invalid_flag['target']['available'] and invalid_flag['storage']['bytesHex'] == '02'
    assert invalid_flag['storage']['value'] is None, invalid_flag
    _, corrected, _ = client.edit(write(invalid_flag, boolean(True)))
    assert corrected['result']['intervention']['scalar']['beforeValue'] is None
    assert corrected['result']['intervention']['scalar']['afterValue'] == boolean(True)

    client.execute({'kind': 'continue'})
    assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
    read_snapshot(client, scalar)
    assert client.send(first_frame) == first_response
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': first_audit['id']})['intervention'] == first_audit
    client.launch_scalar(artifact)
    client.bad({'kind': 'readScalarStorage', 'snapshotId': scalar['id']}, ('HISTORY_EVICTED',))
    reject_frame(client, first_frame, 'STALE_CONTEXT')
    client.execute({'kind': 'stop'})


def verify_frames(client, artifact):
    client.launch_scalar(artifact)
    at_ready(client)
    set_breakpoints(client, ('NESTED', 'SHADOWED'))
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('NESTED')['start']['line']
    local = inspect(client, 'local')
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:1:scalar'}, ('READ_FAILED',))
    variables = client.good({'kind': 'readVariables', 'reference': 'frame:1', 'start': 0, 'count': 128})
    assert any(value['name'] == 'scalar' for value in variables['variables']), variables
    parent = inspect(client, 'scalar', frame=1)
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']})
    _, response, _ = client.edit(write(parent, integer(123)))
    assert response['result']['intervention']['scalar']['locator'] == 'frame:1:scalar'
    assert memory(client, parent['target']['addressHex'], 4) == (123).to_bytes(4, 'little')
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']})['registers'] == registers['registers']
    read_snapshot(client, local)
    client.bad(write(local, integer(17)), ('STALE_CONTEXT',))
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('SHADOWED')['start']['line']
    shadowed = [value for value in client.observation['stack'][0]['variables'] if value['name'] == 'scalar']
    assert len(shadowed) == 2, shadowed
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:0:scalar'}, ('UNSUPPORTED',))
    client.execute({'kind': 'stop'})


def verify_input_is_not_fed(client, artifact):
    client.launch_scalar(artifact, text='q' * 131072)
    before = at_ready(client)
    assert 4096 <= before['input']['deliveredBytes'] < 131072, before['input']
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert os.read(descriptor, 4096) == b'q' * 4096
        snapshot = inspect(client, 'scalar')
        _, response, _ = client.edit(write(snapshot, integer(42)))
    finally:
        os.close(descriptor)
    assert response['result']['intervention']['report']['outcome'] == 'verified'
    assert client.observation['input'] == before['input'], client.observation['input']
    client.execute({'kind': 'stop'})


def verify_profile_guards(client, artifact):
    client.launch_scalar(artifact, argv=('t',))
    at_ready(client)
    stable = client.good({'kind': 'getState'})
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:0:scalar'}, ('UNSUPPORTED',))
    assert client.good({'kind': 'getState'}) == stable and audits(client)['total'] == 0
    client.execute({'kind': 'stop'})

    client.launch_scalar(artifact, argv=('w',))
    at_ready(client)
    snapshot = inspect(client, 'scalar')
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'waiting', events
    stable = client.good({'kind': 'getState'})
    assert stable['state']['phase'] == 'waitingForInput', stable
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:0:scalar'}, ('STALE_CONTEXT',))
    client.bad(write(snapshot, integer(42)), ('STALE_CONTEXT',))
    assert client.good({'kind': 'getState'}) == stable and audits(client)['total'] == 0
    read_snapshot(client, snapshot)
    client.execute({'kind': 'stop'})

    client.launch_scalar(artifact, recording=True)
    stable = client.good({'kind': 'getState'})
    recording = client.good({'kind': 'readRecording'})
    client.bad({'kind': 'inspectScalarStorage', 'locator': 'frame:0:scalar'}, ('UNSUPPORTED',))
    assert client.good({'kind': 'readRecording'}) == recording
    assert client.good({'kind': 'getState'}) == stable and audits(client)['total'] == 0
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-scalar-storage-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            capabilities = client.good({'kind': 'capabilities'})['capabilities']
            assert capabilities['scalarStorage'] == PROFILE and capabilities['variableWrite'] is False, capabilities
            client.bad({'kind': 'readScalarStorage', 'snapshotId': 'missing'}, ('STALE_CONTEXT',))
            artifact = build(client)
            verify_native(client, artifact)
            verify_frames(client, artifact)
            verify_input_is_not_fed(client, artifact)
            verify_profile_guards(client, artifact)
        finally:
            client.close()
    print('scalar storage integration: exact types/bytes, retained snapshots, branches, idempotency, input isolation and native guards passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
