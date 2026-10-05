"""Opt-in IEEE scalar storage edits preserve exact bits, including NaN payloads."""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

import scalar_storage_integration as scalars
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'native-dwarf-scalar-v2'
SOURCE = r'''#include <unistd.h>
using Real = float;
int main() {
  float floating = 1.5f;
  double doubleValue = 2.5;
  Real alias = 3.5f;
  long double extended = 4.5L;
  _Float16 half = 1.25f;
  const float constant = 5.5f;
  volatile double volatileValue = 6.5;
  float& reference = floating;
  double* pointer = &doubleValue;
  int scalar = 7;
  bool flag = false;
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


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'float-storage-source', 'documents': [{
        'documentId': 'float-storage', 'revisionId': 'float-storage-1', 'path': 'float-storage.cpp',
        'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'float-storage-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'float-storage', 'revisionId': 'float-storage-1',
            'range': {'start': offset, 'end': offset},
            'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def at_ready(client):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'float-storage',
        'revisionId': 'float-storage-1', 'breakpoints': [
            {'id': 'ready', 'range': location('READY'), 'enabled': True}]})
    assert result['breakpoints'][0]['verified'], result
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('READY')['start']['line']
    return client.observation


def floating(pattern):
    return {'kind': 'float', 'bits': len(pattern) * 4, 'rawBitsHex': pattern}


def inspect(client, name, *, profile=PROFILE, available=True):
    command = {'kind': 'inspectScalarStorage', 'locator': f'frame:0:{name}'}
    if profile is not None:
        command['profile'] = profile
    result = client.good(command)
    assert result['kind'] == 'scalarStorage', result
    snapshot = result['snapshot']
    assert snapshot['type'] == 'scalarStorageSnapshot' and snapshot['profile'] == (profile or scalars.PROFILE)
    assert snapshot['point'] == client.observation['point'] and snapshot['stop'] == client.observation['stop']
    assert snapshot['processInstanceId'] == client.observation['processInstanceId']
    target = snapshot['target']; storage = snapshot['storage']
    assert target['source'] == 'gdb-python-dwarf' and target['locator'] == command['locator']
    assert target['lifetime'] == 'unknown' and target['available'] is available, target
    if available:
        assert storage['available'] and storage['reason'] is None, storage
        info = target['scalar']
        assert info['byteOrder'] == 'little' and info['byteSize'] * 8 == info['bits']
        assert scalars.memory(client, target['addressHex'], info['byteSize']).hex() == storage['bytesHex']
        if info['kind'] == 'float':
            assert info['bits'] in (32, 64) and info['signed'] is None, info
            assert info['representation'] == f"ieee754-binary{info['bits']}"
            assert storage['value'] == floating(bytes.fromhex(storage['bytesHex'])[::-1].hex()), snapshot
    else:
        assert not storage['available'] and storage['bytesHex'] is None and storage['value'] is None, snapshot
    return snapshot


def write(snapshot, value, *, profile=None):
    return {'kind': 'writeScalarStorage', 'profile': profile or snapshot['profile'],
            'snapshotId': snapshot['id'], 'value': value}


def verify_profiles(client):
    for profile in (None, scalars.PROFILE):
        legacy = inspect(client, 'floating', profile=profile, available=False)
        client.bad(write(legacy, floating('3f800000')), ('UNSUPPORTED', 'INVALID_REQUEST'))
        # Merely changing the command profile cannot upgrade a saved v1 target.
        client.bad(write(legacy, floating('3f800000'), profile=PROFILE), ('INVALID_REQUEST',))
    modern = inspect(client, 'floating')
    assert modern['storage']['value'] == floating('3fc00000')
    client.bad(write(modern, floating('3f800000'), profile=scalars.PROFILE), ('INVALID_REQUEST',))
    assert scalars.audits(client)['total'] == 0
    for name in ('extended', 'half', 'constant', 'volatileValue', 'reference', 'pointer'):
        unsupported = inspect(client, name, available=False)
        client.bad(write(unsupported, floating('3f800000')), ('UNSUPPORTED',))
    alias = inspect(client, 'alias')
    assert alias['storage']['value'] == floating('40600000'), alias

    # Opting into v2 retains exact integer/bool support and profile provenance.
    legacy_integer = inspect(client, 'scalar', profile=None)
    client.bad(write(legacy_integer, scalars.integer(42), profile=PROFILE), ('INVALID_REQUEST',))
    integer = inspect(client, 'scalar')
    client.bad(write(integer, scalars.integer(42), profile=scalars.PROFILE), ('INVALID_REQUEST',))
    _, response, _ = client.edit(write(integer, scalars.integer(42)))
    assert response['result']['intervention']['profile'] == PROFILE
    assert response['result']['intervention']['scalar']['afterValue'] == scalars.integer(42)
    flag = inspect(client, 'flag')
    _, response, _ = client.edit(write(flag, scalars.boolean(True)))
    assert response['result']['intervention']['scalar']['afterValue'] == scalars.boolean(True)


def verify_invalid(client):
    snapshot = inspect(client, 'floating')
    stable = client.good({'kind': 'getState'})
    count = scalars.audits(client)['total']
    # Canonical MSB-first bit strings are distinct from memory byte order and
    # from the existing approximate display DTO. No implicit numeric parsing.
    for value in (
        floating('8000000'), floating('800000000'), floating('8000000000000000'),
        {'kind': 'float', 'bits': 32, 'rawBitsHex': '7FC00001'},
        {'kind': 'float', 'bits': 32, 'rawBitsHex': '0x80000000'},
        {'kind': 'float', 'bits': 32, 'rawBitsHex': 'gg000000'},
        {'kind': 'float', 'bits': 32, 'rawBitsHex': '80000000\n'},
        {'kind': 'float', 'bits': 32, 'rawBitsHex': 0},
        {'kind': 'float', 'bits': 32},
        {'kind': 'float', 'bits': 16, 'rawBitsHex': '8000'},
        {'kind': 'float', 'bits': 32, 'rawBitsHex': '80000000', 'text': '-0'},
        {'kind': 'float', 'bits': 32, 'text': '1.5', 'classification': 'finite'},
        scalars.integer(1), scalars.boolean(True),
    ):
        client.bad(write(snapshot, value))
    assert client.good({'kind': 'getState'}) == stable and scalars.audits(client)['total'] == count
    assert inspect(client, 'floating')['storage']['value'] == snapshot['storage']['value']


def verify_patterns(client):
    original = client.observation
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers']
    patterns = {
        'floating': ('00000000', '80000000', '00000001', '80000001', '007fffff', '00800000',
                     '3f800001', '7f7fffff', 'ff7fffff', '7f800000', 'ff800000',
                     '7fc00001', '7fc12345', 'ffc54321', '7f800001', 'ff800123'),
        'doubleValue': ('0000000000000000', '8000000000000000', '0000000000000001',
                        '8000000000000001', '000fffffffffffff', '0010000000000000',
                        '3ff0000000000001', '7fefffffffffffff', 'ffefffffffffffff',
                        '7ff0000000000000', 'fff0000000000000', '7ff8000000000001',
                        '7ff8123456789abc', 'fff8fedcba987654', '7ff0000000000001', 'fff0000000000123'),
    }
    first_request = None
    for name, bits in patterns.items():
        for pattern in bits:
            snapshot = inspect(client, name)
            desired = floating(pattern)
            previous_stop = client.observation['stop']
            frame, response, events = client.edit(write(snapshot, desired))
            audit = response['result']['intervention']; report = audit['report']
            expected_memory = bytes.fromhex(pattern)[::-1].hex()
            assert events and report['outcome'] == 'verified', report
            assert report['beforeBytesHex'] == snapshot['storage']['bytesHex'], report
            assert report['replacementBytesHex'] == expected_memory and report['afterBytesHex'] == expected_memory
            assert audit['profile'] == PROFILE and audit['scalar'] == {
                'snapshotId': snapshot['id'], 'locator': f'frame:0:{name}', 'target': snapshot['target'],
                'requestedValue': desired, 'beforeValue': snapshot['storage']['value'], 'afterValue': desired}, audit
            assert client.observation['stop']['stateRevision'] == previous_stop['stateRevision'] + 1
            fresh = inspect(client, name)
            assert fresh['storage']['value'] == desired, fresh
            # Repeated inspections must not quiet a signaling NaN in target memory.
            assert inspect(client, name)['storage']['bytesHex'] == expected_memory
            assert scalars.memory(client, snapshot['target']['addressHex'], len(pattern) // 2).hex() == expected_memory
            scalars.read_snapshot(client, snapshot)
            if first_request is None:
                first_request = frame, response, snapshot
            # Exact same payload is a no-op even when IEEE comparisons would
            # report NaN != NaN. Distinct signed-zero/NaN payloads above wrote.
            if pattern in ('80000000', '7fc12345', '7f800001', '8000000000000000',
                           '7ff8123456789abc', '7ff0000000000001'):
                noop_frame, noop, noop_events = client.edit(write(fresh, desired))
                assert not noop_events and noop['result']['intervention']['report']['outcome'] == 'unchanged'
                assert client.send(noop_frame) == noop
                assert client.good({'kind': 'getState'})['state']['live']['stop'] == fresh['stop']
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp', 'rbp']})['registers'] == registers
    assert client.good({'kind': 'readHistory', 'point': original['point']})['observation'] == original
    frame, response, saved = first_request
    client.bad(write(saved, floating('3f800000')), ('STALE_CONTEXT',))
    assert client.send(frame) == response
    changed = {**frame, 'command': write(saved, floating('3f800000'))}
    scalars.reject_frame(client, changed, 'INVALID_REQUEST')
    # A raw edit has the same stop invalidation boundary as typed storage.
    snapshot = inspect(client, 'floating')
    _, raw, _ = client.edit(scalars.raw_write(snapshot, bytes.fromhex('0000803f')))
    assert raw['result']['intervention']['profile'] == 'native-private-memory-v1'
    client.bad(write(snapshot, floating('3fc00000')), ('STALE_CONTEXT',))
    assert inspect(client, 'floating')['storage']['value'] == floating('3f800000')
    return first_request


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-float-storage-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            capabilities = client.good({'kind': 'capabilities'})['capabilities']
            assert capabilities['scalarStorage'] == scalars.PROFILE
            assert capabilities['scalarStorageProfiles'] == [scalars.PROFILE, PROFILE], capabilities
            artifact = build(client)
            client.launch_scalar(artifact)
            at_ready(client)
            verify_profiles(client)
            verify_invalid(client)
            frame, response, saved = verify_patterns(client)
            client.execute({'kind': 'continue'})
            assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
            assert client.send(frame) == response
            scalars.read_snapshot(client, saved)
            audit = response['result']['intervention']
            assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        finally:
            client.close()
    print('float storage integration: opt-in profile, exact IEEE bytes, signed zero, subnormals, infinities, NaN payloads and retained audits passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
