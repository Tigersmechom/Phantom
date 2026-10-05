"""Mixed typed storage batches bind snapshots/types before any mutation."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile

import float_storage_integration as floats
import scalar_storage_integration as scalars
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'native-dwarf-scalar-batch-v1'
SOURCE = r'''#include <unistd.h>
int main() {
  int scalar = 7;
  unsigned long long unsignedWide = 19;
  long long signedWide = -17;
  bool flag = false;
  float floating = 1.5f;
  double doubleValue = 2.5;
  unsigned char byte = 3;
  unsigned short unsignedShort = 13;
  const int constant = 23;
  volatile double guarded = 29;
  int& reference = scalar;
  unsigned long long wide0 = 0, wide1 = 1, wide2 = 2, wide3 = 3;
  unsigned long long wide4 = 4, wide5 = 5, wide6 = 6, wide7 = 7;
  if (write(1, "kept\n", 5) != 5) return 90;
  asm volatile("nop" : : : "memory"); // READY
  asm volatile("nop" : : : "memory"); // AFTER
  return 0;
}
'''


class Client(scalars.Client):
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
        if command['kind'] == 'writeScalarStorageBatch' and self.observation is not None:
            frame['expectedStop'] = self.observation['stop']
        return frame


def command(entries):
    return {'kind': 'writeScalarStorageBatch', 'profile': PROFILE, 'edits': entries}


def item(snapshot, value, *, profile=None):
    return {'profile': profile or snapshot['profile'], 'snapshotId': snapshot['id'], 'value': value}


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'scalar-batch-source', 'documents': [{
        'documentId': 'scalar-batch', 'revisionId': 'scalar-batch-1', 'path': 'scalar-batch.cpp',
        'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'scalar-batch-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'scalar-batch', 'revisionId': 'scalar-batch-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def at_ready(client):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'scalar-batch', 'revisionId': 'scalar-batch-1',
        'breakpoints': [{'id': 'ready', 'range': location('READY'), 'enabled': True}]})
    assert result['breakpoints'][0]['verified'], result
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('READY')['start']['line']
    return client.observation


def inspect(client, name, *, profile=scalars.PROFILE, available=True):
    return floats.inspect(client, name, profile=profile, available=available)


def journal(client, point):
    return client.good({'kind': 'readOutputJournal', 'stream': 'stdout', 'fromByte': 0,
        'byteCount': 64, 'point': point})


def batch(client, snapshots, values):
    frame, response, events = client.edit(command([item(snapshot, value) for snapshot, value in zip(snapshots, values)]))
    audit = response['result']['intervention']; report = audit['report']
    assert audit['profile'] == PROFILE and len(audit['scalars']) == len(snapshots)
    assert 'scalar' not in audit and 'mapping' not in audit and len(audit['mappings']) == len(snapshots)
    for index, (origin, snapshot, desired) in enumerate(zip(audit['scalars'], snapshots, values)):
        assert origin['index'] == index and origin['profile'] == snapshot['profile']
        assert origin['snapshotId'] == snapshot['id'] and origin['target'] == snapshot['target']
        assert origin['locator'] == snapshot['target']['locator'] and origin['requestedValue'] == desired
        assert report['items'][index]['addressHex'] == snapshot['target']['addressHex']
        assert report['items'][index]['expectedBytesHex'] == snapshot['storage']['bytesHex']
    return frame, response, events


def verify_validation(client, early):
    first = inspect(client, 'scalar')
    second = inspect(client, 'unsignedWide')
    modern = inspect(client, 'doubleValue', profile=floats.PROFILE)
    duplicate_address = inspect(client, 'scalar')
    unsupported = inspect(client, 'constant', available=False)
    assert first['id'] != duplicate_address['id']
    stable = client.good({'kind': 'getState'})
    good = item(first, scalars.integer(42))
    for invalid in ([], [good] * 9, [good, good],
                    [good, {**item(second, scalars.integer(1, 64, False)), 'extra': True}]):
        client.bad(command(invalid))
    client.bad({**command([good]), 'profile': scalars.PROFILE})
    missing = client.frame(command([good])); del missing['expectedStop']
    scalars.reject_frame(client, missing, 'INVALID_REQUEST', valid=False)
    for second_item, error in (
        (item(duplicate_address, scalars.integer(43)), 'INVALID_REQUEST'),
        (item(second, scalars.integer(2**64, 64, False)), 'INVALID_REQUEST'),
        (item(second, scalars.integer(1, 64, True)), 'INVALID_REQUEST'),
        (item(second, scalars.integer(1, 32, False)), 'INVALID_REQUEST'),
        (item(unsupported, scalars.integer(1)), 'UNSUPPORTED'),
        (item(early, scalars.integer(1)), 'STALE_CONTEXT'),
        (item(modern, scalars.integer(1), profile=scalars.PROFILE), 'INVALID_REQUEST'),
        (item(second, scalars.integer(1, 64, False), profile=floats.PROFILE), 'INVALID_REQUEST'),
        ({**item(second, scalars.integer(1, 64, False)), 'snapshotId': 'missing'}, 'HISTORY_EVICTED'),
    ):
        client.bad(command([good, second_item]), (error,))
        assert scalars.memory(client, first['target']['addressHex'], 4) == (7).to_bytes(4, 'little')
        assert client.good({'kind': 'getState'}) == stable
        assert scalars.audits(client)['total'] == 0


def verify_preflight(client):
    snapshots = [inspect(client, 'scalar'), inspect(client, 'flag'),
                 inspect(client, 'floating', profile=floats.PROFILE)]
    values = [scalars.integer(42), scalars.boolean(True), floats.floating('7fa12345')]
    stable = client.good({'kind': 'getState'})
    address = int(snapshots[1]['target']['addressHex'], 16)
    descriptor = os.open(f"/proc/{client.observation['processInstanceId']}/mem", os.O_RDWR)
    try:
        assert os.pwrite(descriptor, b'\x02', address) == 1
        _, response, events = batch(client, snapshots, values)
        audit = response['result']['intervention']; report = audit['report']
        assert report['outcome'] == 'preflight-failed' and report['failureIndex'] == 1
        assert not report['writeAttempted'] and not report['preflightPassed'] and not events
        assert audit['scalars'][0]['preflightValue'] == scalars.integer(7)
        assert audit['scalars'][1]['preflightValue'] is None, 'invalid bool bits are not true'
        assert audit['scalars'][2]['preflightValue'] is None, 'unread phase has no value'
        assert all(origin[key] is None for origin in audit['scalars']
                   for key in ('beforeValue', 'afterValue', 'finalValue'))
        assert scalars.memory(client, snapshots[0]['target']['addressHex'], 4) == (7).to_bytes(4, 'little')
        assert scalars.memory(client, snapshots[1]['target']['addressHex'], 1) == b'\x02'
        assert client.good({'kind': 'getState'}) == stable
    finally:
        os.pwrite(descriptor, b'\x00', address)
        os.close(descriptor)


def verify_mixed(client):
    names = ['scalar', 'unsignedWide', 'signedWide', 'flag', 'floating', 'doubleValue', 'byte', 'unsignedShort']
    profiles = [floats.PROFILE if name in ('floating', 'doubleValue') else scalars.PROFILE for name in names]
    snapshots = [inspect(client, name, profile=profile) for name, profile in zip(names, profiles)]
    values = [scalars.integer(2**31 - 1), scalars.integer(2**64 - 1, 64, False),
        scalars.integer(-2**63, 64), scalars.boolean(True), floats.floating('7fa12345'),
        floats.floating('8000000000000000'), scalars.integer(3, 8, False), scalars.integer(65535, 16, False)]
    before = client.observation
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers']
    physical_output = journal(client, before['point'])
    capture = client.good({'kind': 'captureMemory', 'ranges': [{
        'addressHex': snapshots[0]['target']['addressHex'], 'byteCount': 4}]})['capture']
    frame, response, events = batch(client, snapshots, values)
    audit = response['result']['intervention']; report = audit['report']
    assert report['outcome'] == 'verified' and report['byteCount'] == 36
    assert report['preflightPassed'] and report['failureIndex'] is None
    assert len(events) == 3 and len(client.good({'kind': 'listBranches'})['branches']) == 2
    assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
    for index, (origin, snapshot, desired) in enumerate(zip(audit['scalars'], snapshots, values)):
        assert origin['preflightValue'] == snapshot['storage']['value']
        assert origin['beforeValue'] == snapshot['storage']['value']
        assert origin['afterValue'] == (None if index == 6 else desired)
        assert origin['finalValue'] == desired
        assert inspect(client, names[index], profile=profiles[index])['storage']['value'] == desired
        scalars.read_snapshot(client, snapshot)
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers'] == registers
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readMemoryCapture', 'captureId': capture['id']})['capture'] == capture
    assert journal(client, before['point']) == physical_output
    client.bad(command([item(snapshots[0], values[0])]), ('STALE_CONTEXT',))
    assert client.send(frame) == response
    changed = {**frame, 'command': command(list(reversed(frame['command']['edits'])))}
    scalars.reject_frame(client, changed, 'INVALID_REQUEST')

    current = [inspect(client, name, profile=profile) for name, profile in zip(names, profiles)]
    stable = client.good({'kind': 'getState'})
    noop_frame, noop, noop_events = batch(client, current, values)
    noop_audit = noop['result']['intervention']; noop_report = noop_audit['report']
    assert not noop_events and not noop_report['writeAttempted'] and noop_report['outcome'] == 'unchanged'
    for origin, desired in zip(noop_audit['scalars'], values):
        assert origin['preflightValue'] == desired and origin['beforeValue'] == desired
        assert origin['afterValue'] is None and origin['finalValue'] is None
    assert client.good({'kind': 'getState'}) == stable and client.send(noop_frame) == noop

    # Immutable audit provenance outlives the evictable snapshots which
    # originally authorized the batch, including idempotent request replay.
    old = inspect(client, 'byte')
    for _ in range(128):
        client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': old['target']['addressHex'], 'byteCount': 1}]})
    fresh = inspect(client, 'scalar')
    count = scalars.audits(client)['total']
    client.bad(command([item(fresh, scalars.integer(1)), item(old, scalars.integer(4, 8, False))]), ('HISTORY_EVICTED',))
    assert scalars.audits(client)['total'] == count
    assert inspect(client, 'scalar')['storage']['value'] == values[0]
    client.bad({'kind': 'readScalarStorage', 'snapshotId': snapshots[0]['id']}, ('HISTORY_EVICTED',))
    assert client.send(frame) == response and client.send(noop_frame) == noop
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
    return frame, response


def verify_limit_and_input(client, artifact):
    client.launch_scalar(artifact, text='q' * 131072)
    before = at_ready(client)
    assert 4096 <= before['input']['deliveredBytes'] < 131072
    snapshots = [inspect(client, f'wide{index}') for index in range(8)]
    values = [scalars.integer(2**64 - 1 - index, 64, False) for index in range(8)]
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert os.read(descriptor, 4096) == b'q' * 4096
        _, response, _ = batch(client, snapshots, values)
    finally:
        os.close(descriptor)
    audit = response['result']['intervention']; report = audit['report']
    assert report['outcome'] == 'verified' and report['byteCount'] == 64 and len(report['items']) == 8
    assert [origin['finalValue'] for origin in audit['scalars']] == values
    assert client.observation['input'] == before['input'], client.observation['input']
    client.execute({'kind': 'stop'})


def verify_ledger_budget(client, artifact, budget):
    client.launch_scalar(artifact)
    at_ready(client)
    snapshot = inspect(client, 'scalar')
    stable = client.good({'kind': 'getState'})
    # The documented reservations differ: a typed batch retains 64 KiB,
    # ordinary raw edits 32 KiB. Available bytes, not record count, gate writes.
    assert budget % 65536 == 0 and budget >= 131072
    typed_count = budget // 65536 - 1
    first = None
    for _ in range(typed_count):
        frame, response, events = batch(client, [snapshot], [scalars.integer(7)])
        assert not events and response['result']['intervention']['report']['outcome'] == 'unchanged'
        if first is None:
            first = frame, response
    noop = scalars.raw_write(snapshot, bytes.fromhex(snapshot['storage']['bytesHex']))
    client.edit(noop)
    client.bad(command([item(snapshot, scalars.integer(8))]), ('LIMIT_EXCEEDED',))
    client.edit(noop)
    assert scalars.audits(client)['total'] == typed_count + 2
    assert typed_count + 2 == 65, 'default 4 MiB ledger fits 63 typed + 2 raw reservations'
    client.bad(command([item(snapshot, scalars.integer(8))]), ('LIMIT_EXCEEDED',))
    client.bad(scalars.raw_write(snapshot, (8).to_bytes(4, 'little')), ('LIMIT_EXCEEDED',))
    assert client.send(first[0]) == first[1]
    assert len(client.good({'kind': 'listBranches'})['branches']) == 1
    assert client.good({'kind': 'getState'}) == stable
    assert scalars.memory(client, snapshot['target']['addressHex'], 4) == (7).to_bytes(4, 'little')
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-scalar-batch-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            caps = client.good({'kind': 'capabilities'})['capabilities']
            assert caps['scalarStorageBatch'] == PROFILE
            assert caps['limits']['maxScalarStorageBatchItems'] == 8 and caps['limits']['maxScalarStorageBatchBytes'] == 64
            artifact = build(client)
            client.launch_scalar(artifact)
            early = inspect(client, 'scalar')
            at_ready(client)
            verify_validation(client, early)
            verify_preflight(client)
            frame, response = verify_mixed(client)
            client.execute({'kind': 'continue'})
            assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
            assert client.send(frame) == response
            verify_limit_and_input(client, artifact)
            verify_ledger_budget(client, artifact, caps['limits']['maxInterventionStoreBytes'])
            scalars.reject_frame(client, frame, 'STALE_CONTEXT')
        finally:
            client.close()
    print('scalar batch integration: mixed profiles/types, full validation, exact phase provenance, one branch, limits, eviction/dedup and stdin passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
