"""Bounded DWARF object-layout gateway and immutable saved layout snapshots."""
from __future__ import annotations
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
LONG_NAME = 'layout_' + 'x' * 249
assert len(LONG_NAME) == 256
UNSUPPORTED_NAME = 'unsupported_' + 'x' * 245
assert len(UNSUPPORTED_NAME) == 257
SOURCE = r'''struct Data {
  int first;
  unsigned low : 3;
  unsigned high : 5;
  int values[2][3];
  int* pointer;
  union { int number; unsigned char bytes[4]; } overlap;
  static int separate;
};
int Data::separate = 47;
struct Base { int base = 11; };
struct Derived : virtual Base { virtual int method() { return tail; } int tail = 22; };
template<int N> struct Nested { Nested<N-1> child; };
template<> struct Nested<0> { int leaf; };
volatile int sink;
__attribute__((noinline)) void nestedCall(int argument) {
  int inner = argument;
  sink = inner; // INNER
}
int main() {
  int scalar = 17;
  int LONG_VARIABLE = 31;
  int UNSUPPORTED_VARIABLE = 37;
  Data object{1, 5, 17, {{1, 2, 3}, {4, 5, 6}}, &scalar, {123}};
  int* invalidPointer = reinterpret_cast<int*>(1);
  int& reference = scalar;
  Derived derived;
  Nested<12> deep;
  sink = scalar + LONG_VARIABLE + UNSUPPORTED_VARIABLE; // READY
  nestedCall(scalar);
  object.first = 99;
  sink = object.first; // CHANGED
  return 0;
}
'''.replace('LONG_VARIABLE', LONG_NAME).replace('UNSUPPORTED_VARIABLE', UNSUPPORTED_NAME)


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
        if command['kind'] in ('inspectVariableLayout', 'readVariables'):
            frame['expectedStop'] = self.observation['stop']
        return frame

    def launch_layout(self, artifact, recording=False):
        events = self.execute({'kind': 'launch', 'buildId': artifact['id'],
            'input': {'id': 'layout-input', 'text': '', 'encoding': 'utf-8', 'closeAfterWrite': True},
            'argv': [], 'environment': {}, 'stopAtEntry': True, 'addressPolicy': 'disable-aslr',
            'recordingProfile': 'gdb-record-full' if recording else 'native'})
        assert events[-1]['payload']['outcome'] == 'completed', events


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'layout', 'revisionId': 'layout-1', 'range': {'start': offset, 'end': offset},
            'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def field(node, name):
    return next(item for item in node['fields'] if item['name'] == name)


def inspect(client, name):
    snapshot = client.good({'kind': 'inspectVariableLayout', 'locator': 'frame:0:' + name})['snapshot']
    assert snapshot['type'] == 'variableLayoutSnapshot', snapshot
    assert snapshot['point'] == client.observation['point'] and snapshot['stop'] == client.observation['stop']
    assert snapshot['processInstanceId'] == client.observation['processInstanceId']
    layout = snapshot['layout']
    assert layout['available'] and layout['source'] == 'gdb-python-dwarf', layout
    assert layout['lifetime'] == 'unknown' and layout['bitOffsetConvention'] == 'gdb-target-bitpos'
    return snapshot


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-layout-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            client.bad({'kind': 'readVariableLayout', 'snapshotId': 'missing'}, ('STALE_CONTEXT',))
            artifact = client.good({'kind': 'build', 'source': {'id': 'layout-source', 'documents': [{
                'documentId': 'layout', 'revisionId': 'layout-1', 'path': 'layout.cpp', 'text': SOURCE,
                'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]}, 'configuration': {
                'revisionId': 'layout-config', 'compiler': 'clang++', 'flags': ['-std=c++20', '-g', '-O0'],
                'outputDirectory': '.phantom/build', 'addressProfile': 'fixed-executable'},
                'architecture': 'x86_64'})['artifact']
            client.launch_layout(artifact)
            entry = client.observation
            assert inspect(client, 'object')['layout']['lifetime'] == 'unknown'
            breakpoints = client.good({'kind': 'setBreakpoints', 'documentId': 'layout', 'revisionId': 'layout-1',
                'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True}
                                for marker in ('READY', 'INNER', 'CHANGED')]})
            assert all(item['verified'] for item in breakpoints['breakpoints'])
            client.execute({'kind': 'continue'})
            long_variable = next(item for item in client.observation['stack'][0]['variables'] if item['name'] == LONG_NAME)
            assert long_variable['locator'] == 'frame:0:' + LONG_NAME and len(long_variable['locator']) == 264
            long_layout = inspect(client, LONG_NAME)['layout']
            assert long_layout['root']['kind'] == 'integer' and long_layout['root']['byteSize'] == '4'
            assert long_layout['storage']['addressHex'] == long_variable['addressHex']
            unsupported_variable = next(item for item in client.observation['stack'][0]['variables'] if item['name'] == UNSUPPORTED_NAME)
            assert len(unsupported_variable['locator']) == 265
            client.bad({'kind': 'inspectVariableLayout', 'locator': unsupported_variable['locator']}, ('INVALID_REQUEST',))
            state = client.good({'kind': 'getState'})['state']
            registers = client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']})
            saved = inspect(client, 'object')
            layout = saved['layout']; root = layout['root']; base = int(root['addressHex'], 16)
            assert root['kind'] == 'struct' and int(root['byteSize']) == 48, root
            assert field(root, 'first')['byteOffset'] == '0'
            assert int(field(root, 'first')['type']['addressHex'], 16) == base
            low = field(root, 'low'); high = field(root, 'high')
            assert (low['bitOffset'], low['bitSize'], low['bitOffsetInByte']) == ('32', '3', 0)
            assert (high['bitOffset'], high['bitSize'], high['bitOffsetInByte']) == ('35', '5', 3)
            assert low['type']['addressHex'] is None and high['type']['addressHex'] is None
            matrix = field(root, 'values')['type']
            assert matrix['array']['elementCount'] == '2' and matrix['array']['strideBytes'] == '12'
            assert matrix['array']['elementLayout']['array']['elementCount'] == '3'
            overlap = field(root, 'overlap')['type']
            assert overlap['kind'] == 'union'
            assert field(overlap, 'number')['type']['addressHex'] == field(overlap, 'bytes')['type']['addressHex']
            assert field(root, 'separate')['byteOffset'] is None and field(root, 'separate')['kind'] == 'static'
            assert inspect(client, 'invalidPointer')['layout']['root']['kind'] == 'pointer'
            reference = inspect(client, 'reference')['layout']
            assert reference['root']['kind'] == 'reference' and reference['storage']['addressHex'] is None
            derived = inspect(client, 'derived')['layout']['root']
            bases = [item for item in derived['fields'] if item['kind'] == 'base']
            assert len(bases) == 1 and bases[0]['byteOffset'] is None and bases[0]['type']['addressHex'] is None
            assert any(item['artificial'] for item in derived['fields'])
            deep = inspect(client, 'deep')['layout']
            assert deep['coverage'] == 'truncated' and 'depth-limit' in deep['truncationReasons']
            assert client.good({'kind': 'readVariableLayout', 'snapshotId': saved['id']})['snapshot'] == saved
            assert client.good({'kind': 'getState'})['state'] == state
            assert client.good({'kind': 'readRegisters', 'registers': ['rip', 'rsp']}) == registers
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:0:missing'}, ('READ_FAILED',))
            for locator in ('frame:0:object.first', 'frame:0:*invalidPointer',
                            'frame:0:object.method()', 'frame:0:object\ncontinue', 'frame:0:object\rcontinue',
                            'frame:0:object\x00', 'frame:0:object\t', 'frame:4096:object'):
                client.bad({'kind': 'inspectVariableLayout', 'locator': locator})
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'x' * 273}, ('LIMIT_EXCEEDED',))
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:0:object', 'depth': 100})
            client.bad({'kind': 'readVariableLayout', 'snapshotId': 'missing'}, ('HISTORY_EVICTED',))
            stale = client.frame({'kind': 'inspectVariableLayout', 'locator': 'frame:0:object'})
            stale['expectedStop'] = entry['stop']
            response = client.send(stale)
            assert not response['ok'] and response['error']['code'] == 'STALE_CONTEXT', response
            missing = client.frame({'kind': 'inspectVariableLayout', 'locator': 'frame:0:object'})
            del missing['expectedStop']
            client.record_requests = False
            response = client.send(missing)
            client.record_requests = True
            assert not response['ok'] and response['error']['code'] == 'INVALID_REQUEST', response
            client.execute({'kind': 'continue'})
            assert client.observation['location']['start']['line'] == location('INNER')['start']['line']
            inspect(client, 'inner')
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:1:object'}, ('READ_FAILED',))
            variables = client.good({'kind': 'readVariables', 'reference': 'frame:1', 'start': 0, 'count': 128})
            assert any(item['locator'] == 'frame:1:object' for item in variables['variables']), variables
            outer = client.good({'kind': 'inspectVariableLayout', 'locator': 'frame:1:object'})['snapshot']
            assert outer['layout']['root']['addressHex'] == root['addressHex']
            inspect(client, 'inner')  # Previously emitted inner handles survive reading the outer frame.
            client.good({'kind': 'readVariables', 'reference': 'frame:0', 'start': 0, 'count': 128})
            assert client.good({'kind': 'inspectVariableLayout', 'locator': 'frame:1:object'})['snapshot']['layout'] == outer['layout']
            client.execute({'kind': 'continue'})
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:0:inner'}, ('READ_FAILED',))
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:1:object'}, ('READ_FAILED',))
            changed = inspect(client, 'object')
            assert changed['id'] != saved['id'] and changed['point'] != saved['point']
            assert client.good({'kind': 'readVariableLayout', 'snapshotId': saved['id']})['snapshot'] == saved
            assert client.observation['stdout']['totalBytes'] == 0 and client.observation['stderr']['totalBytes'] == 0
            client.execute({'kind': 'continue'})
            assert client.good({'kind': 'getState'})['state']['phase'] == 'terminated'
            assert client.good({'kind': 'readVariableLayout', 'snapshotId': saved['id']})['snapshot'] == saved
            client.bad({'kind': 'inspectVariableLayout', 'locator': 'frame:0:object'}, ('STALE_CONTEXT',))
            old_session = client.session
            client.launch_layout(artifact, recording=True)
            client.bad({'kind': 'readVariableLayout', 'snapshotId': saved['id']}, ('HISTORY_EVICTED',))
            stale = client.frame({'kind': 'readVariableLayout', 'snapshotId': saved['id']})
            stale['session'] = old_session
            response = client.send(stale)
            assert not response['ok'] and response['error']['code'] == 'STALE_CONTEXT'
            before = client.observation['recording']
            inspect(client, 'object')
            recording = client.frame({'kind': 'readRecording'})
            recording['expectedStop'] = client.observation['stop']
            response = client.send(recording)
            assert response['ok'] and response['result']['recording'] == before, response
            client.execute({'kind': 'stop'})
        finally:
            client.close()
    print('layout integration: bounded DWARF metadata, storage, bits, arrays, union/base/pointer boundaries, history and recorder passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
