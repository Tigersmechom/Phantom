"""Inspection must neither expose queued stdin nor deliver a requested EOF."""
from __future__ import annotations

import array
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import termios

from advanced_gateway_integration import Client as BaseClient
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
SOURCE = r'''#include <unistd.h>
int main() {
  unsigned long long total = 0;
  char buffer[4096];
  if (write(1, "ready\n", 6) != 6) return 90;
  asm volatile("nop" : : : "memory"); // READY
  ssize_t count;
  while ((count = read(0, buffer, sizeof(buffer))) > 0) total += count;
  if (count < 0) return 91;
  if (write(1, "done\n", 5) != 5) return 92;
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
        if self.observation is not None and command['kind'] in (
                'readVariables', 'inspectVariableLayout', 'inspectScalarStorage', 'inspectVtable',
                'readRecording', 'appendInput', 'closeInput', 'disassemble'):
            frame['expectedStop'] = self.observation['stop']
        return frame


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'inspection-input', 'revisionId': 'inspection-input-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'inspection-input-source', 'documents': [{
        'documentId': 'inspection-input', 'revisionId': 'inspection-input-1', 'path': 'inspection-input.cpp',
        'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'inspection-input-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def launch(client, artifact, *, profile='native', text='', closed=False):
    events = client.execute({'kind': 'launch', 'buildId': artifact['id'],
        'input': {'id': 'inspection-input', 'text': text, 'encoding': 'utf-8', 'closeAfterWrite': closed},
        'argv': [], 'environment': {}, 'stopAtEntry': True, 'recordingProfile': profile})
    assert events[-1]['payload']['outcome'] == 'completed', events


def ready(client):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'inspection-input', 'revisionId': 'inspection-input-1',
        'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True} for marker in ('READY', 'AFTER')]})
    assert all(item['verified'] for item in result['breakpoints']), result
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'completed', events
    assert client.observation['location']['start']['line'] == location('READY')['start']['line']
    assert client.observation['stdout']['text'] == 'ready\n'


def queued(fd):
    count = array.array('i', [0])
    fcntl.ioctl(fd, termios.FIONREAD, count, True)
    return count[0]


def require_open_empty(fd, label):
    try:
        value = os.read(fd, 1)
    except BlockingIOError:
        return
    raise AssertionError((label, 'stdin received an unrequested byte or premature EOF', value))


def history(client):
    return client.good({'kind': 'listHistory', 'branchId': 'main', 'afterOrdinal': None, 'limit': 100})


def journal(client, point):
    return client.good({'kind': 'readOutputJournal', 'stream': 'stdout', 'fromByte': 0, 'byteCount': 64, 'point': point})


def query(client, artifact, name, address, pc):
    commands = {
        'registers': {'kind': 'readRegisters', 'registers': ['rax', 'rsp', 'rip']},
        'variables': {'kind': 'readVariables', 'reference': 'frame:0', 'start': 0, 'count': 64},
        'layout': {'kind': 'inspectVariableLayout', 'locator': 'frame:0:total'},
        'asm': {'kind': 'disassemble', 'buildId': artifact['id'],
            'target': {'kind': 'pc', 'addressHex': pc}, 'maxInstructions': 4},
        'scalar': {'kind': 'inspectScalarStorage', 'locator': 'frame:0:total'},
        'process': {'kind': 'inspectProcess'},
        'memory': {'kind': 'readMemory', 'addressHex': address, 'byteCount': 8},
        'capture': {'kind': 'captureMemory', 'ranges': [{'addressHex': address, 'byteCount': 8}]},
        'vtable': {'kind': 'inspectVtable', 'abi': 'itanium-x86_64-absolute-v1',
            'vptrAddressHex': address, 'maxEntries': 1},
        'recording': {'kind': 'readRecording'},
        'state': {'kind': 'getState'},
        'bad-memory': {'kind': 'readMemory', 'addressHex': '0x0', 'byteCount': 1},
        'empty-frame': {'kind': 'readVariables', 'reference': 'frame:9999', 'start': 0, 'count': 1},
        'bad-asm': {'kind': 'disassemble', 'buildId': artifact['id'],
            'target': {'kind': 'pc', 'addressHex': '0x0'}, 'maxInstructions': 1},
    }
    response = client.query(commands[name])
    if name.startswith('bad-'):
        assert not response['ok'] and response['error']['code'] == 'READ_FAILED', response
    else:
        assert response['ok'], response
        if name == 'empty-frame':
            assert response['result']['variables'] == [] and response['result']['hasMore'] is False
    return response


def native_scenario(client, artifact, name):
    launch(client, artifact)
    ready(client)
    before = client.observation
    saved_state = client.good({'kind': 'getState'})
    saved_history = history(client)
    saved_output = journal(client, before['point'])
    address = next(variable['addressHex'] for variable in before['stack'][0]['variables'] if variable['name'] == 'total')
    pc = client.good({'kind': 'readRegisters', 'registers': ['rip']})['registers'][0]['valueHex']
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        # Fix the capacity while the FIFO is empty; shrinking an empty FIFO
        # needs no elevated permissions and avoids relying on system defaults.
        default_capacity = fcntl.fcntl(descriptor, fcntl.F_GETPIPE_SZ)
        capacity = fcntl.fcntl(descriptor, fcntl.F_SETPIPE_SZ, 4096)
        chunk = {'kind': 'appendInput', 'id': 'queued-chunk', 'text': 'q' * (2 * capacity)}
        submitted = client.good(chunk)['input']
        assert submitted['deliveredBytes'] == capacity and queued(descriptor) == capacity, submitted
        closed = client.good({'kind': 'closeInput'})['input']
        assert closed['deliveredBytes'] == capacity and closed['eof'] == 'requested'
        assert closed['status'] == 'reading'
        # Only the test reads this prefix. The stopped inferior has not run;
        # freeing FIFO space must not turn an inspection into an input action.
        assert os.read(descriptor, capacity) == b'q' * capacity
        require_open_empty(descriptor, name)
        query(client, artifact, name, address, pc)
        assert queued(descriptor) == 0, (name, 'inspection exposed queued stdin', queued(descriptor))
        require_open_empty(descriptor, name)
        # An idempotent input chunk returns current transport state without
        # pumping the FIFO, unlike submitting new input or requesting EOF.
        assert client.good(chunk)['input'] == closed, name
        assert client.good({'kind': 'getState'}) == saved_state, name
        assert history(client) == saved_history, name
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        assert journal(client, before['point']) == saved_output

        # Normal execution must still feed the remaining queue and deliver EOF.
        # This rules out a leaked suspension counter that merely blocks all I/O.
        events = client.execute({'kind': 'continue'})
        assert events[-1]['payload']['outcome'] == 'completed', (name, events)
        after = client.observation
        assert after['location']['start']['line'] == location('AFTER')['start']['line'], after
        total = next(variable for variable in after['stack'][0]['variables'] if variable['name'] == 'total')
        assert total['value']['value']['decimal'] == str(capacity), (name, total)
        assert after['input']['deliveredBytes'] == 2 * capacity
        assert after['input']['status'] == 'complete' and after['input']['eof'] == 'requested'
        assert after['stdout']['text'] == 'ready\ndone\n'
        assert os.read(descriptor, 1) == b''
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        output = journal(client, before['point'])
        assert output['selectedThroughByte'] == 6 and output['totalBytes'] == 11
        assert b''.join(base64.b64decode(segment['bytesBase64']) for segment in output['segments']) == b'ready\ndone\n'
        client.execute({'kind': 'continue'})
        state = client.good({'kind': 'getState'})['state']
        assert state['phase'] == 'terminated' and state['exit']['code'] == 0, state
        return default_capacity
    finally:
        os.close(descriptor)


def recording_scenario(client, artifact, default_capacity):
    # record-full deliberately forbids mutable input, so use a finite initial
    # queue larger than the usual FIFO and inspect at its first stopped point.
    launch(client, artifact, profile='gdb-record-full', text='r' * (2 * default_capacity), closed=True)
    before = client.observation
    saved_state = client.good({'kind': 'getState'})
    saved_history = history(client)
    saved_recording = client.good({'kind': 'readRecording'})
    assert saved_recording['recording']['available'], saved_recording
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        capacity = fcntl.fcntl(descriptor, fcntl.F_GETPIPE_SZ)
        assert capacity < 2 * default_capacity and queued(descriptor) == capacity
        assert os.read(descriptor, capacity) == b'r' * capacity
        require_open_empty(descriptor, 'record-full')
        assert client.good({'kind': 'readRecording'}) == saved_recording
        assert queued(descriptor) == 0, 'readRecording exposed queued stdin'
        require_open_empty(descriptor, 'record-full')
        assert client.good({'kind': 'getState'}) == saved_state
        assert history(client) == saved_history
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        client.execute({'kind': 'stop'})
    finally:
        os.close(descriptor)


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-inspection-input-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            artifact = build(client)
            for name in ('registers', 'variables', 'layout', 'asm', 'scalar', 'process', 'memory',
                    'capture', 'vtable', 'recording', 'state', 'bad-memory', 'empty-frame', 'bad-asm'):
                default_capacity = native_scenario(client, artifact, name)
            recording_scenario(client, artifact, default_capacity)
        finally:
            client.close()
    print('inspection input: physical FIFO/EOF isolation, failed reads, immutable history and resumed input delivery passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
