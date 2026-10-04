"""ELF overlays at the public boundary: live pointer evidence and immutable pages."""
from __future__ import annotations
import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []

SOURCE = r'''#include <dlfcn.h>
struct AppBase {
  virtual ~AppBase();
  virtual int value() const;
};
AppBase::~AppBase() = default;
int AppBase::value() const { return 91; }
AppBase appObject;
int appData = 91;
thread_local int appTls = 11;
int appFunction() { return appData; }
int main(int argc, char** argv) {
  if (argc != 2) return 90;
  void* handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) return 91;
  auto function = reinterpret_cast<int (*)()>(dlsym(handle, "phantomSymbolFunction"));
  if (!function) return 92;
  int value = function();
  asm volatile("nop" : : "r"(value) : "memory"); // LOADED
  if (dlclose(handle)) return 93;
  asm volatile("nop" : : "r"(value) : "memory"); // UNLOADED
  return value == 73 ? 0 : 94;
}
'''


class Client(BaseClient):
    def send(self, frame):
        if self.record_requests: TRAFFIC.append(('request', frame))
        return TransportClient.send(self, frame)

    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command):
        frame = super().frame(command)
        if command['kind'] in {'inspectModules', 'inspectModuleSymbols'}:
            frame['expectedStop'] = self.observation['stop']
        return frame

    def build(self, profile):
        return self.good({'kind': 'build', 'source': {'id': 'symbols-source', 'documents': [{
            'documentId': 'symbols', 'revisionId': 'symbols-1', 'path': 'symbols.cpp', 'text': SOURCE,
            'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]}, 'configuration': {
            'revisionId': 'symbols-config-' + profile, 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0', '-fPIE', '-pie', '-Wl,--no-as-needed', '-ldl'],
            'outputDirectory': '.phantom/build', 'addressProfile': profile}, 'architecture': 'x86_64'})['artifact']

    def launch_module(self, artifact, path):
        events = self.execute({'kind': 'launch', 'buildId': artifact['id'],
            'input': {'id': 'symbols-input', 'text': '', 'encoding': 'utf-8', 'closeAfterWrite': True},
            'argv': [str(path)], 'environment': {}, 'stopAtEntry': True, 'addressPolicy': 'disable-aslr'})
        assert events[-1]['payload']['outcome'] == 'completed', events


def location(marker):
    line = next(i for i, s in enumerate(SOURCE.splitlines(), 1) if s.endswith('// ' + marker))
    offset = sum(len(s) + 1 for s in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'symbols', 'revisionId': 'symbols-1', 'range': {'start': offset, 'end': offset},
            'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def gather(client, first):
    snapshot = first['snapshot']
    all_symbols = list(snapshot['report']['symbols'])
    while len(all_symbols) < first['totalSymbols']:
        page = client.good({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'],
                            'start': len(all_symbols), 'count': 64})
        assert page['totalSymbols'] == first['totalSymbols'] and page['start'] == len(all_symbols)
        assert page['snapshot']['report']['sections'] == snapshot['report']['sections']
        assert page['snapshot']['point'] == snapshot['point'] and page['snapshot']['stop'] == snapshot['stop']
        assert page['snapshot']['report']['symbols']
        all_symbols.extend(page['snapshot']['report']['symbols'])
    return {**snapshot, 'report': {**snapshot['report'], 'symbols': all_symbols}}


def item(snapshot, name):
    return next(s for s in snapshot['report']['symbols'] if s['name'] == name)


def address(snapshot, name):
    symbol = item(snapshot, name)
    location = next(p for p in symbol['runtimeLocations'] if p['status'] == 'mapped')
    return int(location['addressHex'], 16)


def memory_word(client, address_value, size=8):
    result = client.good({'kind': 'readMemory', 'addressHex': hex(address_value), 'byteCount': size})
    assert result['unreadableBytes'] == 0, result
    data = base64.b64decode(result['bytesBase64'])
    assert len(data) == size
    return int.from_bytes(data, 'little')


def inspect_object(client, snapshot, object_name, vtable_name, typeinfo_name):
    # Independent evidence: read the actual object vptr, then read the RTTI
    # pointer preceding the address point under the x86-64 Itanium ABI.
    vptr = memory_word(client, address(snapshot, object_name))
    vtable = item(snapshot, vtable_name)
    assert vtable['classification'] == 'vtable' and vtable['classificationEvidence'] == 'itanium-mangled-prefix'
    assert any(int(p['addressHex'], 16) <= vptr < int(p['endAddressHex'], 16)
               for p in vtable['runtimeLocations'] if p['status'] == 'mapped'), (vptr, vtable)
    assert memory_word(client, vptr - 8) == address(snapshot, typeinfo_name)


def main():
    if len(sys.argv) != 3: return 2
    if not sys.platform.startswith('linux') or any(not shutil.which(t) for t in ['gdb', 'clang++', 'strip']):
        return 77
    library = Path(sys.argv[2]).resolve()
    assert library.is_file()
    with tempfile.TemporaryDirectory(prefix='phantom-symbols-') as directory:
        workspace = Path(directory)
        stripped = workspace / 'stripped fixture.so'
        shutil.copyfile(library, stripped)
        subprocess.run(['strip', '--strip-unneeded', str(stripped)], check=True, capture_output=True)
        client = Client(sys.argv[1], workspace)
        try:
            previous_snapshot = None
            previous_session = None
            for profile, loaded_library in [('native', library), ('fixed-executable', stripped)]:
                artifact = client.build(profile)
                client.launch_module(artifact, loaded_library)
                if previous_snapshot:
                    client.bad({'kind': 'readModuleSymbols', 'snapshotId': previous_snapshot['id'],
                                'start': 0, 'count': 1}, ('HISTORY_EVICTED',))
                    stale = client.frame({'kind': 'readModuleSymbols', 'snapshotId': previous_snapshot['id'],
                                          'start': 0, 'count': 1})
                    stale['session'] = previous_session
                    result = client.send(stale)
                    assert not result['ok'] and result['error']['code'] == 'STALE_CONTEXT', result
                module_snapshot = client.good({'kind': 'inspectModules'})['snapshot']
                app = next(m for m in module_snapshot['modules']['modules'] if m['path'] == artifact['binaryPath'])
                assert app['elf']['elfType'] == ('ET_DYN' if profile == 'native' else 'ET_EXEC')
                captured = client.good({'kind': 'inspectModuleSymbols', 'moduleId': app['id']})
                snapshot = gather(client, captured)
                report = snapshot['report']
                assert report['available'] and report['identityVerified'] and report['coverage'] == 'complete', report
                assert snapshot['type'] == 'moduleSymbolsSnapshot' and snapshot['evidenceScope'] == 'current-os-state'
                assert snapshot['point'] == client.observation['point'] and snapshot['stop'] == client.observation['stop']
                assert report['moduleId'] == app['id'] and report['contentIdentity'] == 'file-metadata-only'
                if profile == 'fixed-executable': assert report['module']['instances'][0]['loadBiasHex'] == '0x0'
                assert memory_word(client, address(snapshot, 'appData'), 4) == 91
                inspect_object(client, snapshot, 'appObject', '_ZTV7AppBase', '_ZTI7AppBase')
                tls = item(snapshot, 'appTls')
                assert tls['runtimeMeaning'] == 'tls-offset' and tls['runtimeLocations'] == []
                assert any(s['name'] == '.text' and s['runtimeLocations'] for s in report['sections'])
                assert any(s['name'] == '.debug_info' and s['runtimeReason'] == 'non-allocated-section'
                           for s in report['sections'])
                one = client.good({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'], 'start': 0, 'count': 1})
                assert one['snapshot']['report']['symbols'] == report['symbols'][:1] and one['hasMore']
                empty = client.good({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'],
                                     'start': 9007199254740991, 'count': 1})
                assert empty['start'] == len(report['symbols']) and not empty['hasMore']
                assert empty['snapshot']['report']['symbols'] == []
                client.bad({'kind': 'readModuleSymbols', 'snapshotId': module_snapshot['id'], 'start': 0, 'count': 1},
                           ('HISTORY_EVICTED',))
                for invalid in [{'start': -1, 'count': 1}, {'start': 0, 'count': 0},
                                {'start': 0, 'count': 1025}, {'start': True, 'count': 1}]:
                    client.bad({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'], **invalid})
                client.bad({'kind': 'inspectModuleSymbols', 'moduleId': app['id'], 'path': '/etc/passwd'})
                missing = client.frame({'kind': 'inspectModuleSymbols', 'moduleId': app['id']})
                missing.pop('expectedStop'); client.record_requests = False
                result = client.send(missing); client.record_requests = True
                assert not result['ok'] and result['error']['code'] == 'INVALID_REQUEST', result
                null_session = client.frame({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'],
                                             'start': 0, 'count': 1})
                null_session['session'] = None
                result = client.send(null_session)
                assert not result['ok'] and result['error']['code'] == 'STALE_CONTEXT', result
                unknown = client.good({'kind': 'inspectModuleSymbols', 'moduleId': 'module:missing'})['snapshot']['report']
                assert not unknown['available'] and unknown['reason'] == 'module-not-mapped'
                assert unknown['sections'] == [] and unknown['symbols'] == []
                bps = client.good({'kind': 'setBreakpoints', 'documentId': 'symbols', 'revisionId': 'symbols-1',
                    'breakpoints': [{'id': m, 'range': location(m), 'enabled': True} for m in ['LOADED', 'UNLOADED']]})
                assert all(b['verified'] for b in bps['breakpoints']), bps
                client.execute({'kind': 'continue'})
                assert client.observation['location']['start']['line'] == location('LOADED')['start']['line']
                modules = client.good({'kind': 'inspectModules'})['snapshot']['modules']['modules']
                inode = str(loaded_library.stat().st_ino)
                module = next(m for m in modules if m['inodeDecimal'] == inode)
                shared_page = client.good({'kind': 'inspectModuleSymbols', 'moduleId': module['id']})
                shared = gather(client, shared_page)
                assert shared['report']['available'] and shared['report']['coverage'] == 'complete'
                assert memory_word(client, address(shared, 'phantomSymbolData'), 4) == 73
                inspect_object(client, shared, 'phantomSymbolObject', '_ZTV20PhantomSymbolFixture', '_ZTI20PhantomSymbolFixture')
                if loaded_library == stripped:
                    assert all(t['kind'] == 'dynsym' for t in shared['report']['elfMetadata']['symbolTables'])
                stale = client.frame({'kind': 'inspectModuleSymbols', 'moduleId': module['id']})
                stale['expectedStop'] = snapshot['stop']
                result = client.send(stale)
                assert not result['ok'] and result['error']['code'] == 'STALE_CONTEXT', result
                client.execute({'kind': 'continue'})
                assert client.observation['location']['start']['line'] == location('UNLOADED')['start']['line']
                absent = client.good({'kind': 'inspectModuleSymbols', 'moduleId': module['id']})['snapshot']['report']
                assert not absent['available'] and absent['reason'] == 'module-not-mapped', absent
                retained = client.good({'kind': 'readModuleSymbols', 'snapshotId': shared['id'], 'start': 0, 'count': 100})
                assert retained == shared_page
                client.execute({'kind': 'continue'})
                assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
                assert client.good({'kind': 'readModuleSymbols', 'snapshotId': snapshot['id'],
                                    'start': 0, 'count': 100}) == captured
                assert client.good({'kind': 'readModuleSymbols', 'snapshotId': shared['id'],
                                    'start': 0, 'count': 100}) == shared_page
                client.bad({'kind': 'inspectModuleSymbols', 'moduleId': app['id']}, ('STALE_CONTEXT',))
                previous_snapshot, previous_session = shared, client.session
        finally:
            client.close()
    print('symbols integration: PIE/fixed/shared/stripped ELF, vptr and RTTI bytes, immutable pages and stale contexts passed')
    return 0


if __name__ == '__main__': raise SystemExit(main())
