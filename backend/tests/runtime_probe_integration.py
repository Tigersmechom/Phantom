"""Runtime probe isolation, cancellation and cleanup at the NDJSON boundary.

The trusted PATH GDB wrapper only substitutes isolated batch failures. The live
debugger and successful syscall/code/protection probes use the real GDB.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited
from recorder_probe_integration import Client as ProbeClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'linux-x86_64-syscall-probe-v1'
CAPABILITY = 'isolated-linux-x86_64-syscall-v1'
SOURCE = r'''#include <iostream>
int main() {
  volatile unsigned int counter = 7;
  std::cout << "kept\n" << std::flush;
  std::cout << "pending";
  asm volatile("nop" : : : "memory"); // HOLD
  counter = counter + 1;
  std::cout << "done\n";
  return counter == 8 ? 0 : 91;
}
'''
PROOFS = ('getpid', 'allocated', 'writable', 'executable', 'payloadExecuted', 'released',
          'deniedSyscall', 'registersRestored', 'stackUnchanged', 'errnoUnchanged',
          'signalMaskUnchanged', 'codeUnchanged', 'signalStopVerified', 'handlerNotRun')


class Client(ProbeClient):
    def send(self, *frames):
        if self.record_requests:
            TRAFFIC.extend(('request', frame) for frame in frames)
        LifecycleClient.send(self, *frames)

    def recv(self, timeout=20):
        frame = LifecycleClient.recv(self, timeout)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command, expected_stop=None):
        if expected_stop is None and command['kind'] in ('readRegisters', 'writeMemory'):
            assert self.observation is not None
            expected_stop = self.observation['stop']
        return super().frame(command, expected_stop)

    def good(self, command):
        response = self.query(command)
        assert response['ok'], response
        return response['result']

    def reject(self, frame, code='INVALID_REQUEST', *, valid=True):
        self.record_requests = valid
        try:
            self.send(frame)
        finally:
            self.record_requests = True
        response = self.recv()
        if valid:
            assert response.get('requestId') == frame['requestId'], response
        assert response['ok'] is False and response['error']['code'] == code, response
        return response


def wrapper(path, real_gdb, mode, marker, invocations):
    path.write_text(f'#!{sys.executable}\n' +
        f'REAL = {real_gdb!r}\nMODE = {str(mode)!r}\nMARKER = {str(marker)!r}\nLOG = {str(invocations)!r}\n' + r'''
import json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
# Live GDB always remains real, including while a batch probe is blocked.
if '--batch' not in args:
    os.execv(REAL, [REAL, *args])
with open(LOG, 'a') as output:
    output.write(json.dumps({'pid': os.getpid(), 'cwd': os.getcwd(), 'argv': args}) + '\n')
mode = pathlib.Path(MODE).read_text()
if mode == 'block':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    pathlib.Path(MARKER).write_text(json.dumps({'parent': os.getpid(), 'child': child.pid, 'cwd': os.getcwd()}))
    while pathlib.Path(MODE).read_text() == 'block':
        time.sleep(.01)
    child.terminate()
    child.wait(timeout=3)
    mode = pathlib.Path(MODE).read_text()
if mode == 'fail':
    print('deliberate isolated GDB failure', file=sys.stderr)
    sys.exit(23)
if mode == 'garbage':
    print('PHANTOM_RUNTIME_PROBE_V1:{"available":true}')
    sys.exit(0)
os.execv(REAL, [REAL, *args])
''')
    path.chmod(0o700)


def checked_probe(response, *, available=None):
    assert response['ok'] and response['result']['kind'] == 'runtimeProbe', response
    probe = response['result']['probe']
    assert probe['scope'] == 'isolated-runtime-fixture' and probe['profile'] == PROFILE, probe
    assert type(probe['elapsedMs']) is int and probe['elapsedMs'] >= 0
    assert type(probe['available']) is bool and type(probe['cancelled']) is bool
    assert isinstance(probe['limitations'], list) and probe['limitations']
    assert all(isinstance(item, str) and item for item in probe['limitations'])
    for name in ('gdbVersion', 'execution'):
        stage = probe[name]
        assert set(stage) == {'attempted', 'ok', 'status', 'exitCode', 'signal', 'stdout', 'stderr', 'detail'}, stage
        assert type(stage['attempted']) is bool and type(stage['ok']) is bool
        assert isinstance(stage['status'], str) and isinstance(stage['stdout'], str) and isinstance(stage['stderr'], str)
        assert stage['exitCode'] is None or type(stage['exitCode']) is int
        assert stage['signal'] is None or type(stage['signal']) is int
        assert stage['detail'] is None or isinstance(stage['detail'], str)
    if available is not None:
        assert probe['available'] is available, probe
    if probe['available']:
        assert probe['reason'] == 'verified' and probe['cancelled'] is False
        assert probe['gdbVersion']['ok'] and probe['execution']['ok']
        evidence = probe['evidence']
        assert set(evidence) == {*PROOFS, 'profile', 'pid', 'pageSize', 'scratchAddressHex', 'registerCount', 'stackBytes'}, evidence
        assert evidence['profile'] == PROFILE
        assert all(evidence.get(key) is True for key in PROOFS), evidence
        assert type(evidence['pid']) is int and 1 <= evidence['pid'] <= 2147483647
        assert type(evidence['pageSize']) is int and 4096 <= evidence['pageSize'] <= 1024 * 1024
        assert evidence['pageSize'] & (evidence['pageSize'] - 1) == 0
        assert isinstance(evidence['scratchAddressHex'], str) and re.fullmatch(r'0x[0-9a-f]+', evidence['scratchAddressHex'])
        assert 0 < int(evidence['scratchAddressHex'], 16) < 1 << 63
        assert int(evidence['scratchAddressHex'], 16) % evidence['pageSize'] == 0
        assert type(evidence['registerCount']) is int and 32 <= evidence['registerCount'] <= 512
        assert type(evidence['stackBytes']) is int and 4096 <= evidence['stackBytes'] <= 1024 * 1024
        require_inferior_exited(str(evidence['pid']))
    else:
        assert isinstance(probe['reason'], str) and probe['reason'], probe
        assert probe['evidence'] is None or isinstance(probe['evidence'], dict)
    return probe


def build(client):
    result = client.good({'kind': 'build', 'architecture': 'x86_64',
        'source': {'id': 'runtime-probe-source', 'documents': [{
            'documentId': 'runtime-main', 'revisionId': 'runtime-main-1', 'path': 'main.cpp',
            'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'runtime-probe-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0'], 'outputDirectory': '.phantom/runtime-build'}})
    assert result['success'], result
    return result['artifact']


def launch_stopped(client, artifact):
    events = client.execute({'kind': 'launch', 'buildId': artifact['id'],
        'input': {'id': 'queued-input', 'text': 'q' * 131072, 'encoding': 'utf-8', 'closeAfterWrite': False},
        'argv': [], 'environment': {}, 'stopAtEntry': True})
    assert events[-1]['payload']['outcome'] == 'completed'
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// HOLD'))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    location = {'documentId': 'runtime-main', 'revisionId': 'runtime-main-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'runtime-main', 'revisionId': 'runtime-main-1',
        'breakpoints': [{'id': 'hold', 'range': location, 'enabled': True}]})
    assert result['breakpoints'][0]['verified'], result
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == line, client.observation
    assert client.observation['stdout']['text'] == 'kept\n', client.observation
    variable = next(item for item in client.observation['stack'][0]['variables'] if item['name'] == 'counter')
    # Keep a nonempty existing audit so probe isolation tests retention too.
    edit = client.frame({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': variable['addressHex'], 'expectedBytesHex': '07000000', 'replacementBytesHex': '07000000'})
    client.send(edit)
    response = client.recv()
    assert response['ok'] and response['result']['intervention']['report']['outcome'] == 'unchanged', response
    return edit, response


def live_evidence(client):
    checkpoint = client.checkpoint()
    point = checkpoint['observation']['point']
    return {'state': checkpoint['state'], 'observation': checkpoint['observation'],
        'history': client.good({'kind': 'listHistory', 'branchId': point['branchId'], 'afterOrdinal': None, 'limit': 100}),
        'historical': client.good({'kind': 'readHistory', 'point': point}),
        'journal': client.good({'kind': 'readOutputJournal', 'stream': 'stdout', 'fromByte': 0, 'byteCount': 64, 'point': point}),
        'registers': client.good({'kind': 'readRegisters', 'registers': []}),
        'interventions': client.good({'kind': 'listInterventions', 'start': 0, 'count': 128}),
        'branches': client.good({'kind': 'listBranches'})}


def wait_marker(marker):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if marker.exists():
            try:
                return json.loads(marker.read_text())
            except json.JSONDecodeError:
                pass
        time.sleep(.01)
    raise AssertionError('isolated runtime probe did not reach blocking child')


def assert_cleanup(children):
    for key in ('parent', 'child'):
        require_inferior_exited(str(children[key]))
    assert not Path(children['cwd']).exists(), children


def cancel_probe(client, mode, marker, *, session_null=False):
    mode.write_text('block')
    marker.unlink(missing_ok=True)
    request = client.frame({'kind': 'probeRuntime'})
    if session_null:
        request['session'] = None
    client.send(request)
    children = wait_marker(marker)
    cancel = client.frame({'kind': 'cancel', 'targetRequestId': request['requestId']})
    cancel['session'] = request['session']
    started = time.monotonic()
    client.send(cancel)
    responses, completed = {}, False
    while len(responses) != 2 or not completed:
        frame = client.recv(timeout=4)
        if 'requestId' in frame:
            assert frame['requestId'] in (request['requestId'], cancel['requestId'])
            assert frame['requestId'] not in responses
            responses[frame['requestId']] = frame
        else:
            payload = frame['payload']
            assert payload['kind'] == 'commandFinished' and payload['requestId'] == cancel['requestId'], frame
            assert payload['outcome'] == 'completed' and not completed, frame
            completed = True
    assert time.monotonic() - started < 4
    assert responses[cancel['requestId']]['ok']
    result = checked_probe(responses[request['requestId']], available=False)
    assert result['cancelled'] and result['execution']['status'] == 'cancelled', result
    assert_cleanup(children)
    mode.write_text('success')
    # An already completed probe cannot be cancelled, or interrupt a live GDB.
    client.reject(client.frame({'kind': 'cancel', 'targetRequestId': request['requestId']}), 'STALE_CONTEXT')


def timeout_probe(client, mode, marker):
    mode.write_text('block')
    marker.unlink(missing_ok=True)
    request = client.frame({'kind': 'probeRuntime'})
    started = time.monotonic()
    client.send(request)
    children = wait_marker(marker)
    response = client.recv(timeout=35)
    assert response.get('requestId') == request['requestId']
    result = checked_probe(response, available=False)
    assert result['cancelled'] is False and result['execution']['status'] == 'timeout', result
    assert time.monotonic() - started < 35
    assert_cleanup(children)
    mode.write_text('success')


def queued_stop(client, mode, marker):
    mode.write_text('block')
    marker.unlink(missing_ok=True)
    request = client.frame({'kind': 'probeRuntime'})
    client.send(request)
    children = wait_marker(marker)
    stop = client.frame({'kind': 'stop'})
    client.send(stop)
    # A stop is for the live session. It must wait until the isolated operation
    # finishes instead of signalling its debugger or forging probe cancellation.
    assert b'\n' not in client.pending and not client.selector.select(.1)
    mode.write_text('success')
    response = client.recv()
    assert response.get('requestId') == request['requestId'], response
    checked_probe(response, available=True)
    frames = client.finish([stop])
    assert frames[-1]['payload']['outcome'] == 'completed', frames
    assert client.checkpoint()['state']['phase'] == 'terminated'
    assert_cleanup(children)


def main():
    if len(sys.argv) != 2:
        return 2
    real_gdb = shutil.which('gdb')
    if not sys.platform.startswith('linux') or not real_gdb or not shutil.which('clang++'):
        return 77
    backend = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-gateway-') as directory:
        root = Path(directory)
        tools = root / 'tools'; tools.mkdir()
        mode, marker, invocations = root / 'mode', root / 'ready', root / 'invocations'
        mode.write_text('success')
        wrapper(tools / 'gdb', real_gdb, mode, marker, invocations)
        environment = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')}
        client = Client(backend, root, environment)
        live_pid = None
        try:
            assert client.good({'kind': 'capabilities'})['capabilities']['runtimeProbe'] == CAPABILITY
            for field, value in (('fixturePath', '/bin/sh'), ('gdbPath', '/bin/sh'), ('syscall', 59),
                    ('arguments', []), ('code', 'cc'), ('addressHex', '0x0'), ('timeoutMs', 0), ('profile', 'auto')):
                client.reject(client.frame({'kind': 'probeRuntime', field: value}), valid=False)
            assert not invocations.exists()
            client.reject(client.frame({'kind': 'cancel', 'targetRequestId': 'not-active'}), 'STALE_CONTEXT')
            checked_probe(client.query({'kind': 'probeRuntime'}), available=True)
            assert client.query({'kind': 'getState'})['error']['code'] == 'STALE_CONTEXT'
            cancel_probe(client, mode, marker)
            assert client.query({'kind': 'getState'})['error']['code'] == 'STALE_CONTEXT'
            for setting in ('fail', 'garbage'):
                mode.write_text(setting)
                probe = checked_probe(client.query({'kind': 'probeRuntime'}), available=False)
                assert not probe['cancelled'] and probe['evidence'] is None, probe
                assert probe['execution']['exitCode'] == (23 if setting == 'fail' else 0), probe
            mode.write_text('success')

            artifact = build(client)
            saved_frame, saved_response = launch_stopped(client, artifact)
            live_pid = client.observation['processInstanceId']
            assert 4096 <= client.observation['input']['deliveredBytes'] < 131072
            descriptor = os.open(f'/proc/{live_pid}/fd/0', os.O_RDONLY | os.O_NONBLOCK)
            try:
                assert os.read(descriptor, 4096) == b'q' * 4096
            finally:
                os.close(descriptor)
            before = live_evidence(client)
            checkpoint = client.checkpoint()
            checked_probe(client.query({'kind': 'probeRuntime'}), available=True)
            assert client.checkpoint() == checkpoint and live_evidence(client) == before
            cancel_probe(client, mode, marker, session_null=True)
            assert live_evidence(client) == before
            timeout_probe(client, mode, marker)
            assert live_evidence(client) == before
            client.send(saved_frame)
            assert client.recv() == saved_response
            # Probe cancellation must leave no deferred live execution interrupt.
            events = client.execute({'kind': 'step', 'stepKind': 'instruction'})
            assert events[-1]['payload']['outcome'] == 'completed'
            assert client.observation['stop'] != before['observation']['stop']

            old_session = client.session
            queued_stop(client, mode, marker)
            require_inferior_exited(live_pid)
            live_pid = None
            terminated = client.checkpoint()
            checked_probe(client.query({'kind': 'probeRuntime'}), available=True)
            assert client.checkpoint() == terminated

            launch_stopped(client, artifact)
            live_pid = client.observation['processInstanceId']
            stale = client.frame({'kind': 'probeRuntime'}); stale['session'] = old_session
            calls = invocations.read_text()
            client.reject(stale, 'STALE_CONTEXT')
            assert invocations.read_text() == calls
            request = client.frame({'kind': 'probeRuntime'}); request['session'] = None
            before = live_evidence(client)
            client.send(request)
            checked_probe(client.recv(), available=True)
            assert live_evidence(client) == before
            client.execute({'kind': 'stop'})
            require_inferior_exited(live_pid)
            live_pid = None
            # Each finished batch owns a private directory, including failures.
            for invocation in map(json.loads, invocations.read_text().splitlines()):
                assert not Path(invocation['cwd']).exists(), invocation
        finally:
            mode.write_text('success')
            client.close()
            if live_pid:
                require_inferior_exited(live_pid)
    print('runtime probe: verified real syscall/code execution, live isolation, retained audits, invalid contexts, cancel/timeout and child cleanup passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
