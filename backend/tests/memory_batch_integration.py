"""Bounded memory batches share one audit/branch and check every range first."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile

import memory_edit_integration as edits
import scalar_storage_integration as scalars
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'native-private-memory-batch-v1'


class Client(edits.Client):
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
        if command['kind'] in ('writeMemoryBatch', 'inspectScalarStorage', 'writeScalarStorage') and self.observation is not None:
            frame['expectedStop'] = self.observation['stop']
        return frame

    def batch(self, ranges):
        frame = self.frame(command(ranges))
        response = self.send(frame)
        assert response['ok'] and response['requestId'] == frame['requestId'], response
        result = response['result']
        assert result['kind'] == 'memoryIntervention', result
        audit = result['intervention']; report = audit['report']
        assert audit['requestId'] == frame['requestId'] and audit['profile'] == PROFILE, audit
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        assert 'mapping' not in audit and len(audit['mappings']) == len(ranges), audit
        assert len(report['items']) == len(ranges)
        assert report['byteCount'] == sum(len(item['expectedBytesHex']) // 2 for item in ranges)
        for index, (item, requested, mapping) in enumerate(zip(report['items'], ranges, audit['mappings'])):
            assert item['index'] == index and int(item['addressHex'], 16) == int(requested['addressHex'], 16)
            assert item['expectedBytesHex'] == requested['expectedBytesHex'].lower()
            assert item['replacementBytesHex'] == requested['replacementBytesHex'].lower()
            assert mapping['permissions'] == 'rw-p'
            assert int(mapping['startAddressHex'], 16) <= int(item['addressHex'], 16)
            assert int(mapping['endAddressHex'], 16) >= int(item['addressHex'], 16) + item['byteCount']
        events = []
        if report['writeAttempted']:
            events = [self.recv() for _ in range(3)]
            assert [event['payload']['kind'] for event in events] == ['branchCreated', 'observation', 'state'], events
            assert all(event.get('causedByRequestId') == frame['requestId'] for event in events)
            assert events[0]['payload']['parent'] == audit['beforePoint']
            self.observation = events[1]['payload']['observation']
            assert self.observation['reason'] == 'mutation' and self.observation['point'] == audit['afterPoint']
            assert self.observation['stop'] == audit['afterStop']
            assert events[2]['payload']['state']['live'] == {
                'point': audit['afterPoint'], 'stop': audit['afterStop']}
            assert result['throughSequence'] == events[-1]['sequence']
        else:
            assert audit['branchId'] is None and audit['afterPoint'] is None and audit['afterStop'] is None
            assert audit['contextStatus'] == 'unchanged'
        return frame, response, events


def command(ranges):
    return {'kind': 'writeMemoryBatch', 'profile': PROFILE, 'edits': ranges}


def item(address, before, after):
    return {'addressHex': hex(address), 'expectedBytesHex': before.hex(), 'replacementBytesHex': after.hex()}


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'memory-edit-source', 'documents': [{
        'documentId': 'memory-edit', 'revisionId': 'memory-edit-1', 'path': 'memory-edit.cpp',
        'text': edits.SOURCE, 'sha256': hashlib.sha256(edits.SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'memory-edit-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def verify_native(client, artifact):
    client.launch_edit(artifact)
    entry = client.observation
    before = edits.at_edit(client)
    address = edits.pointer(client, 'middle')
    counter = int(edits.variable(client, 'counter')['addressHex'], 16)
    initial = bytes(range(12))
    assert edits.memory(client, address, 12) == initial
    stable = client.good({'kind': 'getState'})
    saved = client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': hex(address), 'byteCount': 12}]})['capture']
    journal = edits.journal(client, before['point'])
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers']
    valid = [item(address, initial[:4], b'abcd')]
    for bad in ([], valid * 9,
                [item(address, b'', b'')],
                [item(address, b'a', b'ab')],
                [item(address, bytes(257), bytes(257))],
                [item(address, bytes(128), bytes(128)), item(address + 128, bytes(129), bytes(129))],
                [item(2**64 - 1, b'x', b'y')],
                [*valid, item(address + 3, b'a', b'b')],
                [*valid, {**valid[0], 'addressHex': f'0x{address:016X}'}],
                [{**valid[0], 'addressHex': '0x1\n-exec-continue'}],
                [{**valid[0], 'expectedBytesHex': '0'}],
                [{**valid[0], 'replacementBytesHex': 'zzzzzzzz'}],
                [{**valid[0], 'expression': '*pointer = 42'}]):
        client.bad(command(bad))
    client.bad({**command(valid), 'profile': edits.PROFILE})
    missing = client.frame(command(valid)); del missing['expectedStop']
    edits.reject_frame(client, missing, 'INVALID_REQUEST', valid=False)
    stale = client.frame(command(valid)); stale['expectedStop'] = entry['stop']
    edits.reject_frame(client, stale, 'STALE_CONTEXT')

    # Check every VMA before executing even the first otherwise valid range.
    for bad_address in (edits.pointer(client, 'readOnly'), edits.pointer(client, 'shared'),
                        edits.pointer(client, 'executable'), edits.pointer(client, 'arena')):
        client.bad(command([*valid, item(bad_address, b'\0', b'\1')]), ('INVALID_REQUEST',))
        assert edits.memory(client, address, 4) == initial[:4]
    page = int(edits.variable(client, 'page')['value']['value']['decimal'])
    client.bad(command([*valid, item(address + page - 1, b'\xa7\0', b'xy')]), ('INVALID_REQUEST',))
    assert edits.audits(client)['total'] == 0 and client.good({'kind': 'getState'}) == stable

    # A late preflight conflict must not write any earlier range. Ranges after
    # the first conflict remain explicitly unread rather than fabricated.
    conflict_ranges = [*valid, item(address + 4, initial[4:8], b'efgh'),
                       item(address + 8, b'bad!', b'ijkl'), item(counter, edits.number(7), edits.number(43))]
    _, conflict, events = client.batch(conflict_ranges)
    report = conflict['result']['intervention']['report']
    assert report['outcome'] == 'preflight-failed' and report['failureIndex'] == 2
    assert not report['preflightPassed'] and not report['writeAttempted'] and not events
    assert [part['preflight']['matchesExpected'] for part in report['items'][:3]] == [True, True, False]
    assert report['items'][3]['preflight'] is None
    assert all(part['execution'] is None and part['final'] is None for part in report['items'])
    assert edits.memory(client, address, 12) == initial and edits.memory(client, counter, 4) == edits.number(7)
    assert client.good({'kind': 'getState'}) == stable

    # Unsorted adjacent ranges and a separate stack mapping retain request
    # order, with exactly one branch/stop for the entire mixed-change batch.
    ranges = [item(address + 8, initial[8:12], b'\x00\xff\x80\x0a'),
              item(counter, edits.number(7), edits.number(43)),
              item(address, initial[:4], b'ABCD'), item(address + 4, initial[4:8], initial[4:8])]
    frame, response, events = client.batch(ranges)
    audit = response['result']['intervention']; report = audit['report']
    assert report['outcome'] == 'verified' and report['preflightPassed'] and report['failureIndex'] is None
    assert len(events) == 3 and len(client.good({'kind': 'listBranches'})['branches']) == 2
    assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
    assert client.observation['point']['eventOrdinal'] == before['point']['eventOrdinal'] + 1
    assert [part['execution']['outcome'] for part in report['items']] == ['verified', 'verified', 'verified', 'unchanged']
    for part in report['items']:
        assert part['preflight']['bytesHex'] == part['expectedBytesHex'] and part['preflight']['error'] is None
        assert part['final']['bytesHex'] == part['replacementBytesHex'] and part['final']['matchesReplacement'] is True
        assert part['final']['error'] is None
    assert edits.memory(client, address, 12) == b'ABCD' + initial[4:8] + b'\x00\xff\x80\x0a'
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers'] == registers
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readMemoryCapture', 'captureId': saved['id']})['capture'] == saved
    assert edits.journal(client, before['point']) == journal
    stable_after = client.good({'kind': 'getState'})

    noop = [{**part, 'expectedBytesHex': part['replacementBytesHex']} for part in ranges]
    noop_frame, noop_response, noop_events = client.batch(noop)
    noop_report = noop_response['result']['intervention']['report']
    assert noop_report['outcome'] == 'unchanged' and noop_report['preflightPassed']
    assert noop_report['failureIndex'] is None and not noop_report['writeAttempted'] and not noop_events
    assert all(part['execution']['outcome'] == 'unchanged' and part['final'] is None for part in noop_report['items'])
    assert client.good({'kind': 'getState'}) == stable_after
    assert client.send(noop_frame) == noop_response and client.send(frame) == response
    changed = {**frame, 'command': command(list(reversed(ranges)))}
    edits.reject_frame(client, changed, 'INVALID_REQUEST')
    stale = client.frame(command(ranges)); stale['expectedStop'] = before['stop']
    edits.reject_frame(client, stale, 'STALE_CONTEXT')
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit

    # Raw and batch operations share the same ID namespace and lineage ledger.
    _, raw, _ = client.edit(edits.write(address, b'A', b'Z'))
    assert raw['result']['intervention']['beforePoint'] == audit['afterPoint']
    assert client.send(frame) == response
    collision = {**frame, 'command': edits.write(address, b'Z', b'Y')}
    edits.reject_frame(client, collision, 'INVALID_REQUEST')
    typed = client.good({'kind': 'inspectScalarStorage', 'locator': 'frame:0:argc'})['snapshot']
    assert typed['storage']['value'] == scalars.integer(1), typed
    typed_frame, typed_response, _ = scalars.Client.edit(client, scalars.write(typed, scalars.integer(2)))
    typed_audit = typed_response['result']['intervention']
    assert typed_audit['profile'] == scalars.PROFILE
    assert typed_audit['beforePoint'] == raw['result']['intervention']['afterPoint']
    assert client.send(frame) == response and client.send(typed_frame) == typed_response
    assert edits.audits(client)['total'] == 5
    client.execute({'kind': 'continue'})
    client.execute({'kind': 'continue'})
    assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
    assert client.send(frame) == response
    assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit


def verify_limit_and_input(client, artifact):
    client.launch_edit(artifact, text='q' * 131072)
    before = edits.at_edit(client)
    address = edits.pointer(client, 'middle')
    assert 4096 <= before['input']['deliveredBytes'] < 131072
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert os.read(descriptor, 4096) == b'q' * 4096
        ranges = [item(address + start, bytes(range(start, start + 32)), bytes([255 - start]) * 32)
                  for start in range(224, -1, -32)]
        _, response, _ = client.batch(ranges)
    finally:
        os.close(descriptor)
    report = response['result']['intervention']['report']
    assert report['byteCount'] == 256 and len(report['items']) == 8 and report['outcome'] == 'verified'
    assert client.observation['input'] == before['input'], client.observation['input']
    assert len(client.good({'kind': 'listBranches'})['branches']) == 2
    for part in ranges:
        assert edits.memory(client, int(part['addressHex'], 16), 32).hex() == part['replacementBytesHex']
    client.execute({'kind': 'stop'})


def verify_guards(client, artifact):
    client.launch_edit(artifact, argv=('t',))
    edits.at_edit(client)
    address = edits.pointer(client, 'middle')
    stable = client.good({'kind': 'getState'})
    client.bad(command([item(address, b'\0', b'\1')]), ('UNSUPPORTED',))
    assert client.good({'kind': 'getState'}) == stable and edits.audits(client)['total'] == 0
    client.execute({'kind': 'stop'})
    client.launch_edit(artifact, argv=('w',))
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'waiting'
    stable = client.good({'kind': 'getState'})
    client.bad(command([item(1, b'\0', b'\1')]), ('STALE_CONTEXT',))
    assert client.good({'kind': 'getState'}) == stable and edits.audits(client)['total'] == 0
    client.execute({'kind': 'stop'})
    client.launch_edit(artifact, recording=True)
    stable = client.good({'kind': 'getState'})
    client.bad(command([item(1, b'\0', b'\1')]), ('UNSUPPORTED',))
    assert client.good({'kind': 'getState'}) == stable and edits.audits(client)['total'] == 0
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-memory-batch-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            capabilities = client.good({'kind': 'capabilities'})['capabilities']
            assert capabilities['memoryWriteBatch'] == PROFILE
            assert capabilities['limits']['maxMemoryBatchRanges'] == 8
            assert capabilities['limits']['maxMemoryBatchBytes'] == 256
            artifact = build(client)
            verify_native(client, artifact)
            verify_limit_and_input(client, artifact)
            verify_guards(client, artifact)
        finally:
            client.close()
    print('memory batch integration: complete preflight, one branch, exact ordered ranges, immutable history, limits, stdin and profile guards passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
