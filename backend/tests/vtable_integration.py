"""Real Itanium vptr memory, construction tables, bounded words and saved evidence."""
from __future__ import annotations
import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient
from symbols_integration import gather, address as symbol_address

TRAFFIC: list[tuple[str, dict]] = []
SOURCE = (Path(__file__).resolve().parents[1] / 'fixtures/vtable-inspection.cpp').read_text()
ABI = 'itanium-x86_64-absolute-v1'
REAL_PHASES = set(range(1, 6)) | set(range(10, 18)) | set(range(20, 40)) | set(range(51, 55))
CONSTRUCTION_PHASES = {21, 22, 23, 24, 34, 35, 36, 37, 51, 54}
EXPECTED_PHASES = list(range(1, 6)) + list(range(10, 18)) + list(range(20, 40)) + [51, 52, 53, 54, 50, 40, 41, 43, 48, 42, 44, 45, 46, 47]


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
        if command['kind'] in ('inspectVtable', 'inspectModules', 'inspectModuleSymbols', 'readRecording'):
            frame['expectedStop'] = self.observation['stop']
        return frame

    def launch_vtable(self, artifact, *, traps=False, recording=False):
        events = self.execute({'kind': 'launch', 'buildId': artifact['id'],
            'input': {'id': 'vtable-input', 'text': '', 'encoding': 'utf-8', 'closeAfterWrite': True},
            'argv': ['t'] if traps else [], 'environment': {}, 'stopAtEntry': True,
            'addressPolicy': 'disable-aslr', 'recordingProfile': 'gdb-record-full' if recording else 'native'})
        assert events[-1]['payload']['outcome'] == 'completed', events


def build(client, profile, extra_flags=()):
    return client.good({'kind': 'build', 'source': {'id': 'vtable-source-' + profile, 'documents': [{
        'documentId': 'vtable', 'revisionId': profile, 'path': 'vtable.cpp', 'text': SOURCE,
        'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]}, 'configuration': {
        'revisionId': 'vtable-config-' + profile, 'compiler': 'clang++',
        'flags': ['-std=c++20', '-g', '-O0', *extra_flags],
        'outputDirectory': '.phantom/build', 'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})


def set_checkpoint(client, revision):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// VTABLE_CHECKPOINT'))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    location = {'documentId': 'vtable', 'revisionId': revision, 'range': {'start': offset, 'end': offset},
                'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'vtable', 'revisionId': revision,
        'breakpoints': [{'id': 'checkpoint', 'range': location, 'enabled': True}]})
    assert result['breakpoints'][0]['verified'], result


def variable(client, name):
    value = next(v for v in client.observation['stack'][0]['variables'] if v['name'] == name)['value']
    assert value['availability'] == 'available', value
    return value['value']


def checkpoint(client):
    return (int(variable(client, 'phase')['decimal']),
            int(variable(client, 'vptrSlot')['addressHex'], 16),
            int(variable(client, 'expectedTop')['addressHex'], 16))


def memory(client, address, count):
    response = client.good({'kind': 'readMemory', 'addressHex': hex(address), 'byteCount': count})
    data = base64.b64decode(response['bytesBase64'])
    assert len(data) == count and response['unreadableBytes'] == 0, response
    return data


def command(address, count=4):
    return {'kind': 'inspectVtable', 'abi': ABI, 'vptrAddressHex': hex(address), 'maxEntries': count}


def inspect(client, address, count=4, *, verify_memory=True):
    state = client.good({'kind': 'getState'})['state']
    registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']})
    result = client.good(command(address, count))
    assert result['kind'] == 'vtableSnapshot', result
    saved = result['snapshot']; report = saved['report']
    assert saved['type'] == 'vtableSnapshot'
    assert saved['point'] == client.observation['point'] and saved['stop'] == client.observation['stop']
    assert saved['processInstanceId'] == client.observation['processInstanceId']
    assert saved['evidenceScope'] == 'debugger-memory-and-current-os-metadata'
    assert report['source'] == 'itanium-vtable-memory' and report['abi'] == ABI
    assert report['abiEvidence'] == 'requested-profile' and report['lifetime'] == 'unknown'
    assert report['consistency'] == 'sampled-not-atomic' and report['tableEnd'] == 'unknown'
    assert int(report['vptrAddressHex'], 16) == address and report['requestedEntries'] == count
    assert len(report['entries']) <= count
    if verify_memory and report['vptrSlot'] is not None:
        slot = report['vptrSlot']
        raw = memory(client, int(slot['addressHex'], 16), 8)
        assert raw.hex() == slot['bytesHex'] and int.from_bytes(raw, 'little') == int(slot['valueHex'], 16)
    if verify_memory and report['header'] is not None:
        header = report['header']
        raw = memory(client, int(header['addressHex'], 16), 16)
        assert raw.hex() == header['bytesHex']
        assert int.from_bytes(raw[:8], 'little', signed=True) == int(header['offsetToTopDecimal'])
        assert int.from_bytes(raw[8:], 'little') == int(header['rttiAddressHex'], 16)
        candidate = address + int(header['offsetToTopDecimal'])
        if 0 <= candidate <= 2**64 - 1:
            assert int(header['topAddressCandidateHex'], 16) == candidate
        else:
            assert header['topAddressCandidateHex'] is None
    if verify_memory and report['entries']:
        entries = report['entries']
        raw = memory(client, int(entries[0]['addressHex'], 16), len(entries) * 8)
        for index, entry in enumerate(entries):
            part = raw[index * 8:(index + 1) * 8]
            assert entry['index'] == index and int(entry['addressHex'], 16) == int(entries[0]['addressHex'], 16) + index * 8
            assert part.hex() == entry['bytesHex'] and int.from_bytes(part, 'little') == int(entry['valueHex'], 16)
    assert client.good({'kind': 'getState'})['state'] == state
    assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']}) == registers
    assert client.good({'kind': 'readVtableSnapshot', 'snapshotId': saved['id']})['snapshot'] == saved
    return saved


def run_native(client, artifact):
    client.launch_vtable(artifact)
    entry = client.observation
    set_checkpoint(client, 'native')
    seen, snapshots = [], {}
    while True:
        client.execute({'kind': 'continue'})
        state = client.good({'kind': 'getState'})['state']
        if state['phase'] == 'terminated':
            assert state['exit']['code'] == 0, state
            break
        phase, slot, top = checkpoint(client)
        seen.append(phase)
        saved = inspect(client, slot, 1 if phase == 43 else 4)
        report = saved['report']; snapshots[phase] = saved
        if phase in REAL_PHASES:
            assert report['available'] and report['sampleStatus'] == 'stable', report
            assert int(report['header']['topAddressCandidateHex'], 16) == top, report
            assert report['tableSymbols'], report
            if phase != 39:
                assert any(e['classification'] == 'executable-address' for e in report['entries']), report
            if phase in CONSTRUCTION_PHASES:
                assert any(s['kind'] == 'construction-vtable' for s in report['tableSymbols']), report
        elif phase in {40, 41, 42, 44, 45, 46, 48}:
            assert not report['available'], report
        elif phase == 43:
            assert report['available'] and report['tableSymbols'] == [] and report['rttiSymbols'] == [], report
            assert report['entries'][0]['classification'] == 'executable-address'
            assert any(s['name'] == 'phantom_vtable_function' for s in report['entries'][0]['functions'])
        elif phase in {47, 50}:
            assert report['available'] and report['tableSymbols'], report
        if phase == 3:
            client.bad({'kind': 'inspectVtable', 'abi': ABI, 'vptrAddressHex': hex(slot), 'maxEntries': 0})
            client.bad({'kind': 'inspectVtable', 'abi': ABI, 'vptrAddressHex': hex(slot), 'maxEntries': 65})
            client.bad({**command(slot), 'abi': 'auto'})
            client.bad({**command(slot), 'vptrAddressHex': '0x1\n-exec-continue'})
            client.bad({**command(slot), 'expression': 'call()'})
            client.bad({'kind': 'readVtableSnapshot', 'snapshotId': 'missing'}, ('HISTORY_EVICTED',))
            stale = client.frame(command(slot)); stale['expectedStop'] = entry['stop']
            response = client.send(stale)
            assert not response['ok'] and response['error']['code'] == 'STALE_CONTEXT'
            missing = client.frame(command(slot)); del missing['expectedStop']
            client.record_requests = False
            response = client.send(missing)
            client.record_requests = True
            assert not response['ok'] and response['error']['code'] == 'INVALID_REQUEST'
        if phase == 39:
            assert report['entries'] == [], report
            point = int(report['vptrSlot']['valueHex'], 16)
            assert any(point == int(s['addressHex'], 16) + int(s['sizeHex'], 16) for s in report['tableSymbols']), report
    assert seen == EXPECTED_PHASES, seen
    assert snapshots[1]['report']['vptrSlot']['valueHex'] == snapshots[5]['report']['vptrSlot']['valueHex']
    assert snapshots[2]['report']['vptrSlot']['valueHex'] == snapshots[3]['report']['vptrSlot']['valueHex'] == snapshots[4]['report']['vptrSlot']['valueHex']
    assert snapshots[1]['report']['vptrSlot']['valueHex'] != snapshots[3]['report']['vptrSlot']['valueHex']
    assert int(snapshots[13]['report']['header']['offsetToTopDecimal']) < 0
    assert int(snapshots[30]['report']['header']['offsetToTopDecimal']) < 0
    assert int(snapshots[51]['report']['header']['offsetToTopDecimal']) > 0
    assert int(snapshots[54]['report']['header']['offsetToTopDecimal']) > 0
    saved = snapshots[3]
    assert client.good({'kind': 'readVtableSnapshot', 'snapshotId': saved['id']})['snapshot'] == saved
    client.bad(command(int(saved['report']['vptrAddressHex'], 16)), ('STALE_CONTEXT',))
    previous_session = client.session
    client.launch_vtable(artifact)
    client.bad({'kind': 'readVtableSnapshot', 'snapshotId': saved['id']}, ('HISTORY_EVICTED',))
    stale = client.frame({'kind': 'readVtableSnapshot', 'snapshotId': saved['id']}); stale['session'] = previous_session
    response = client.send(stale)
    assert not response['ok'] and response['error']['code'] == 'STALE_CONTEXT'
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-vtables-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            client.bad({'kind': 'readVtableSnapshot', 'snapshotId': 'missing'}, ('STALE_CONTEXT',))
            artifact = build(client, 'native')['artifact']
            run_native(client, artifact)
            client.launch_vtable(artifact, recording=True)
            set_checkpoint(client, 'native')
            client.execute({'kind': 'continue'})
            phase, slot, top = checkpoint(client)
            before = client.good({'kind': 'readRecording'})['recording']
            assert inspect(client, slot)['report']['available']
            assert client.good({'kind': 'readRecording'})['recording'] == before
            client.execute({'kind': 'stop'})
            no_rtti = build(client, 'no-rtti', ['-fno-rtti'])['artifact']
            client.launch_vtable(no_rtti)
            set_checkpoint(client, 'no-rtti')
            for _ in range(3):
                client.execute({'kind': 'continue'})
                phase, slot, top = checkpoint(client)
                report = inspect(client, slot)['report']
                assert report['available'] and report['tableSymbols'], report
                assert int(report['header']['rttiAddressHex'], 16) == 0 and report['rttiSymbols'] == [], report
            assert phase == 3
            client.execute({'kind': 'stop'})

            # Keep only the entry point and fixture facts in .dynsym; remove
            # DWARF, .symtab and all vtable/RTTI symbol labels.
            stripped = build(client, 'stripped', ['-Wl,--strip-all',
                '-Wl,--export-dynamic-symbol=main', '-Wl,--export-dynamic-symbol=phantom_vptr_slots',
                '-Wl,--export-dynamic-symbol=phantom_vtable_phase'])['artifact']
            client.launch_vtable(stripped, traps=True)
            modules = client.good({'kind': 'inspectModules'})['snapshot']['modules']['modules']
            app = next(module for module in modules if module['path'] == stripped['binaryPath'])
            symbols = gather(client, client.good({'kind': 'inspectModuleSymbols', 'moduleId': app['id']}))
            phase_address = symbol_address(symbols, 'phantom_vtable_phase')
            slots_address = symbol_address(symbols, 'phantom_vptr_slots')
            # Undefined ABI runtime imports such as __class_type_info's
            # vtable legitimately remain in .dynsym after stripping. Check
            # the fixture's own class metadata, not those loader imports.
            fixture_classes = ('SingleBase', 'SingleDerived', 'MultiLeft', 'MultiRight', 'Multiple',
                               'Common', 'Diamond', 'VirtualOnly', 'Positive')
            assert not any((s['name'] or '').startswith(('_ZTV', '_ZTC', '_ZTI')) and
                           any(name in (s['name'] or '') for name in fixture_classes)
                           for s in symbols['report']['symbols'])
            client.execute({'kind': 'continue'})
            phase = int.from_bytes(memory(client, phase_address, 4), 'little')
            assert phase == 1
            slot = int.from_bytes(memory(client, slots_address + phase * 8, 8), 'little')
            report = inspect(client, slot)['report']
            assert report['available'] and report['tableSymbols'] == [] and report['rttiSymbols'] == [], report
            client.execute({'kind': 'stop'})

            relative = build(client, 'relative', ['-fexperimental-relative-c++-abi-vtables'])
            if relative['success']:
                client.launch_vtable(relative['artifact'])
                set_checkpoint(client, 'relative')
                client.execute({'kind': 'continue'})
                phase, slot, top = checkpoint(client)
                report = inspect(client, slot)['report']
                # A caller-selected absolute profile cannot prove that the
                # compiler actually emitted absolute entries. No auto detector
                # is promised even when particular bytes reject this sample.
                assert report['abiEvidence'] == 'requested-profile' and report['lifetime'] == 'unknown'
                client.execute({'kind': 'stop'})
            else:
                assert 'unknown argument' in str(relative) or 'unsupported' in str(relative), relative

        finally:
            client.close()
    print('vtable integration: inheritance/constructor/destructor bytes, no RTTI, malformed storage, stripped/relative ABI, history and recorder passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
