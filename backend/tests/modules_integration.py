"""Owned runtime ELF indexing and immutable snapshots across dlopen/dlclose."""
from __future__ import annotations
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []

SOURCE = r'''#include <dlfcn.h>
int main(int argc, char** argv) {
  if (argc != 2) return 90;
  void* handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!handle) return 91;
  auto function = reinterpret_cast<int (*)()>(dlsym(handle, "phantomModuleFixture"));
  if (!function) return 92;
  int value = function();
  asm volatile("nop" : : "r"(value) : "memory"); // LOADED
  if (dlclose(handle)) return 93;
  asm volatile("nop" : : "r"(value) : "memory"); // UNLOADED
  return value == 42 ? 0 : 94;
}
'''

class Client(BaseClient):
    def send(self, frame):
        if self.record_requests: TRAFFIC.append(('request',frame))
        return TransportClient.send(self,frame)
    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received',frame))
        return frame
    def frame(self, command):
        frame = super().frame(command)
        if command['kind'] == 'inspectModules': frame['expectedStop'] = self.observation['stop']
        return frame
    def launch_module(self, artifact, path):
        events = self.execute({'kind':'launch','buildId':artifact['id'],
            'input':{'id':'module-input','text':'','encoding':'utf-8','closeAfterWrite':False},
            'argv':[str(path)],'environment':{},'stopAtEntry':True,'addressPolicy':'disable-aslr'})
        assert events[-1]['payload']['outcome'] == 'completed', events

def location(marker):
    line = next(i for i,s in enumerate(SOURCE.splitlines(),1) if s.endswith('// '+marker))
    offset = sum(len(s)+1 for s in SOURCE.splitlines()[:line-1])
    return {'documentId':'modules','revisionId':'modules-1','range':{'start':offset,'end':offset},
            'start':{'line':line,'column':1},'end':{'line':line,'column':1}}

def main():
    if len(sys.argv) != 3: return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'): return 77
    library = Path(sys.argv[2]).resolve()
    assert library.is_file(), library
    inode = str(library.stat().st_ino)
    def mapped(snapshot):
        return next((m for m in snapshot['modules']['modules'] if m['inodeDecimal'] == inode), None)
    with tempfile.TemporaryDirectory(prefix='phantom-modules-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            artifact = client.good({'kind':'build','source':{'id':'modules-source','documents':[{
                'documentId':'modules','revisionId':'modules-1','path':'modules.cpp','text':SOURCE,
                'sha256':hashlib.sha256(SOURCE.encode()).hexdigest()}]},'configuration':{
                'revisionId':'modules-config','compiler':'clang++','flags':['-std=c++20','-g','-O0','-Wl,--no-as-needed','-ldl'],
                'outputDirectory':'.phantom/build','addressProfile':'fixed-executable'},'architecture':'x86_64'})['artifact']
            client.launch_module(artifact,library)
            entry = client.good({'kind':'inspectModules'})['snapshot']
            assert entry['type'] == 'moduleSnapshot' and entry['evidenceScope'] == 'current-os-state', entry
            assert entry['point'] == client.observation['point'] and entry['stop'] == client.observation['stop']
            assert entry['modules']['available'] and entry['modules']['identityVerified'], entry
            assert entry['modules']['pid'] == client.observation['processInstanceId']
            assert mapped(entry) is None
            app = next(m for m in entry['modules']['modules'] if m['path'] == artifact['binaryPath'])
            assert app['elf']['elfType'] == 'ET_EXEC' and app['instances'][0]['loadBiasHex'] == '0x0', app
            assert app['file']['identityVerified'] and app['contentIdentity'] == 'file-metadata-only'
            assert client.good({'kind':'readModuleSnapshot','snapshotId':entry['id']})['snapshot'] == entry
            client.bad({'kind':'inspectModules','pid':1})
            client.bad({'kind':'readModuleSnapshot','snapshotId':'missing'},('HISTORY_EVICTED',))
            missing = client.frame({'kind':'inspectModules'}); missing.pop('expectedStop')
            client.record_requests = False
            invalid = client.send(missing)
            client.record_requests = True
            assert not invalid['ok'] and invalid['error']['code'] == 'INVALID_REQUEST', invalid
            bps = client.good({'kind':'setBreakpoints','documentId':'modules','revisionId':'modules-1',
                'breakpoints':[{'id':s,'range':location(s),'enabled':True} for s in ['LOADED','UNLOADED']]})
            assert all(b['verified'] for b in bps['breakpoints']), bps
            client.execute({'kind':'continue'})
            assert client.observation['location']['start']['line'] == location('LOADED')['start']['line']
            loaded = client.good({'kind':'inspectModules'})['snapshot']
            module = mapped(loaded); assert module is not None, loaded
            assert module['elf']['available'] and module['elf']['elfType'] == 'ET_DYN', module
            assert module['file']['identityVerified'] and module['instances'], module
            assert any(i['coverage'] == 'complete' for i in module['instances']), module
            assert any(r['backing'] == 'anonymous' for i in module['instances'] for s in i['segments']
                       for r in s['mappedRanges']), module
            stale = client.frame({'kind':'inspectModules'}); stale['expectedStop'] = entry['stop']
            invalid = client.send(stale)
            assert not invalid['ok'] and invalid['error']['code'] == 'STALE_CONTEXT', invalid
            client.execute({'kind':'continue'})
            assert client.observation['location']['start']['line'] == location('UNLOADED')['start']['line']
            unloaded = client.good({'kind':'inspectModules'})['snapshot']
            assert mapped(unloaded) is None
            assert client.good({'kind':'readModuleSnapshot','snapshotId':loaded['id']})['snapshot'] == loaded
            assert client.good({'kind':'readModuleSnapshot','snapshotId':entry['id']})['snapshot'] == entry
            client.execute({'kind':'continue'})
            assert client.good({'kind':'getState'})['state']['phase'] == 'terminated'
            assert client.good({'kind':'readModuleSnapshot','snapshotId':loaded['id']})['snapshot'] == loaded
            client.bad({'kind':'inspectModules'},('STALE_CONTEXT',))
            old_session = client.session
            client.launch_module(artifact,library)
            client.bad({'kind':'readModuleSnapshot','snapshotId':loaded['id']},('HISTORY_EVICTED',))
            stale = client.frame({'kind':'readModuleSnapshot','snapshotId':entry['id']}); stale['session'] = old_session
            invalid = client.send(stale)
            assert not invalid['ok'] and invalid['error']['code'] == 'STALE_CONTEXT', invalid
            null_session = client.frame({'kind':'readModuleSnapshot','snapshotId':entry['id']}); null_session['session'] = None
            invalid = client.send(null_session)
            assert not invalid['ok'] and invalid['error']['code'] == 'STALE_CONTEXT', invalid
            client.execute({'kind':'stop'})
        finally:
            client.close()
    print('modules integration: real dlopen/dlclose, PIE/load bias, BSS, history and stale contexts passed')
    return 0

if __name__ == '__main__': raise SystemExit(main())
