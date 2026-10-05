"""Inject MI faults around real GPR mutations without inventing write evidence."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile

import memory_edit_integration as memory_edits
import register_edit_integration as edits
from lifecycle_integration import require_inferior_exited
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []


class Client(edits.Client):
    def send(self, frame):
        if self.record_requests:
            TRAFFIC.append(('request', frame))
        return TransportClient.send(self, frame)

    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received', frame))
        return frame


def proxy(path, real_gdb, mode):
    path.write_text(f'#!{sys.executable}\nMODE = {mode!r}\nREAL = {real_gdb!r}\n' + r'''
import json, os, pathlib, re, subprocess, sys, threading
root = pathlib.Path(__file__).parent
child = subprocess.Popen([REAL, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
write_token = None
malformed_token = None
written = False
read_failed = False
metadata_count = 0
lock = threading.Lock()
def output(line):
    with lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
def fault():
    (root / 'fault').write_text(MODE)
def forward():
    global written, metadata_count
    for line in child.stdout:
        if line.startswith(b'~') and (root / 'arm').exists():
            text = json.loads(line[1:])
            prefix = 'PHANTOM_REGISTER_TARGET_V1:'
            if text.startswith(prefix):
                metadata_count += 1
                phase = {'initial-width': 1, 'write-width': 3, 'readback-width': 5}.get(MODE)
                if metadata_count == phase:
                    target = json.loads(text[len(prefix):])
                    target['bits'] = 32
                    line = b'~' + json.dumps(prefix + json.dumps(target, separators=(',', ':')) + '\n').encode() + b'\n'
                    fault()
        if malformed_token is not None and line.startswith(malformed_token + b'^done'):
            replacement = b'value="0x10000000000000000"' if MODE == 'before-high-bits' else b'value="<unavailable>"'
            line, count = re.subn(rb'value="[^"]*"', replacement, line, count=1)
            assert count == 1, line
            fault()
        if write_token is not None and line.startswith(write_token + b'^done'):
            written = True
            if MODE == 'write-death':
                fault()
                child.kill()
                os._exit(0)
            if MODE == 'ack-error':
                fault()
                line = write_token + b'^error,msg="injected register acknowledgement failure"\n'
        output(line)
reader = threading.Thread(target=forward, daemon=True)
reader.start()
try:
    for line in sys.stdin.buffer:
        match = re.match(rb'(\d+)(.*)', line.rstrip(b'\n'))
        token, command = match.groups()
        if (root / 'arm').exists():
            with (root / 'commands').open('ab') as file: file.write(line)
            if command.startswith(b'-data-write-register-values '):
                write_token = token
                with (root / 'writes').open('ab') as file: file.write(line)
                if MODE == 'write-rejected':
                    written = True
                    fault()
                    output(token + b'^error,msg="injected write rejection"\n')
                    continue
                if MODE == 'mismatch':
                    pieces = command.split()
                    pieces[-1] = b'0x000000000000002b'
                    line = token + b' '.join(pieces) + b'\n'
                    fault()
            if command.startswith(b'-data-list-register-values ') and not read_failed:
                initial = MODE in ('before-read', 'before-high-bits', 'before-death') and not written
                after = MODE in ('readback', 'malformed-readback') and written
                if initial or after:
                    read_failed = True
                    if MODE == 'before-death':
                        fault()
                        child.kill()
                        break
                    if MODE in ('before-high-bits', 'malformed-readback'):
                        malformed_token = token
                    else:
                        fault()
                        output(token + b'^error,msg="injected register read failure"\n')
                        continue
            if written and command == b'-stack-info-frame' and MODE == 'refresh-death':
                fault()
                child.kill()
                break
        child.stdin.write(line)
        child.stdin.flush()
finally:
    if child.poll() is None: child.terminate()
    try: child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
    reader.join(timeout=3)
''')
    path.chmod(0o700)


def scenario(executable, real_gdb, mode, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    proxy(tools / 'gdb', real_gdb, mode)
    old_path = os.environ.get('PATH', '')
    try:
        os.environ['PATH'] = str(tools) + os.pathsep + old_path
        client = Client(executable, workspace)
    finally:
        os.environ['PATH'] = old_path
    pid = None
    try:
        artifact = edits.build(client)
        client.launch_edit(artifact)
        before = edits.at_edit(client); pid = before['processInstanceId']
        stable = client.good({'kind': 'getState'})
        baseline = edits.registers(client, [*edits.REGISTERS, 'rip', 'rsp', 'rbp', 'eflags'])
        frame = client.frame(edits.command('rax', 7, 42))
        (tools / 'arm').touch()
        response = client.send(frame)
        if mode == 'initial-width':
            assert not response['ok'] and response['error']['code'] == 'UNSUPPORTED', response
            assert edits.audits(client)['total'] == 0 and not (tools / 'writes').exists()
            assert client.good({'kind': 'getState'}) == stable
            assert edits.registers(client, list(baseline)) == baseline
            assert (tools / 'fault').read_text() == mode
            client.execute({'kind': 'stop'})
            return
        assert response['ok'] and response['result']['kind'] == 'registerIntervention', response
        audit = response['result']['intervention']; report = audit['report']
        assert audit['profile'] == edits.PROFILE and audit['requestId'] == frame['requestId']
        assert audit['target'] == {'architecture': 'x86_64', 'register': 'rax', 'bits': 64,
            'threadId': before['threadId'], 'frameLevel': 0}
        assert report['register'] == 'rax' and report['bits'] == 64
        assert report['expectedValueHex'] == edits.canonical(7)
        assert report['replacementValueHex'] == edits.canonical(42)
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        attempted = not mode.startswith('before-') and mode != 'write-width'
        failed = mode in ('before-death', 'write-death', 'refresh-death')
        assert report['writeAttempted'] == attempted, report
        count = (2 if failed else 3) if attempted else (1 if failed else 0)
        events = [client.recv() for _ in range(count)]
        expected_kinds = (['branchCreated', 'state'] if failed else ['branchCreated', 'observation', 'state']) if attempted else (['state'] if failed else [])
        assert [event['payload']['kind'] for event in events] == expected_kinds, events
        assert all(event.get('causedByRequestId') == frame['requestId'] for event in events)
        if events:
            assert response['result']['throughSequence'] == events[-1]['sequence']
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed'
            assert audit['afterPoint'] is None and audit['afterStop'] is None
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None
            assert checkpoint['observation'] is None
            assert events[-1]['payload']['state'] == checkpoint['state']
            if attempted:
                assert audit['refreshError']
            require_inferior_exited(pid)
        elif attempted:
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None
            client.observation = events[1]['payload']['observation']
            assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
            assert checkpoint['observation'] == client.observation
            actual = 7 if mode == 'write-rejected' else 43 if mode == 'mismatch' else 42
            assert edits.registers(client, list(baseline)) == {**baseline, 'rax': actual}
            assert client.observation['input'] == before['input'] and client.observation['stdout'] == before['stdout']
        else:
            assert audit['contextStatus'] == 'unchanged' and audit['branchId'] is None
            assert checkpoint == stable
            assert edits.registers(client, list(baseline)) == baseline

        if attempted or mode == 'write-width':
            assert report['beforeValueHex'] == edits.canonical(7) and report['beforeMatchesExpected'] is True
        else:
            assert report['outcome'] == 'read-before-failed'
            assert report['beforeValueHex'] is None and report['afterValueHex'] is None
            assert report['beforeMatchesExpected'] is None
        if mode == 'write-width':
            assert report['outcome'] == 'write-rejected' and report['afterValueHex'] is None
            assert report['afterMatchesReplacement'] is None and report['afterMatchesBefore'] is None
        elif mode in ('ack-error', 'refresh-death'):
            assert report['outcome'] == 'verified' and report['afterValueHex'] == edits.canonical(42)
            assert report['afterMatchesReplacement'] is True and report['afterMatchesBefore'] is False
        elif mode in ('write-rejected', 'mismatch'):
            assert report['outcome'] == 'readback-mismatch', report
            assert report['afterValueHex'] == edits.canonical(7 if mode == 'write-rejected' else 43)
            assert report['afterMatchesReplacement'] is False
            assert report['afterMatchesBefore'] == (mode == 'write-rejected')
        elif attempted:
            assert report['outcome'] == 'unverified' and report['afterValueHex'] is None, report
            assert report['afterMatchesReplacement'] is None and report['afterMatchesBefore'] is None
        assert report['writeAcknowledged'] == (mode in ('mismatch', 'readback', 'malformed-readback', 'readback-width', 'refresh-death')), report
        assert report['errors'] or mode == 'refresh-death'
        assert report['debuggerAlive'] == (mode not in ('before-death', 'write-death'))
        assert (tools / 'fault').read_text() == mode
        writes = (tools / 'writes').read_bytes().splitlines() if (tools / 'writes').exists() else []
        assert len(writes) == int(attempted), writes
        # The retry deliberately retains an old/dead stop token, and even after
        # subsequent commands must return exactly the original immutable audit.
        assert client.send(frame) == response
        memory_edits.reject_frame(client, {**frame, 'command': edits.command('rax', 7, 43)}, 'INVALID_REQUEST')
        assert edits.audits(client)['items'] == [audit] and memory_edits.audits(client)['total'] == 0
        assert client.good({'kind': 'readRegisterIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert client.good({'kind': 'readIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert client.good({'kind': 'listInterventions', 'start': 0, 'count': 128})['items'] == [audit]
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        assert len(client.good({'kind': 'listBranches'})['branches']) == (2 if attempted else 1)
        remaining = (tools / 'writes').read_bytes().splitlines() if (tools / 'writes').exists() else []
        assert remaining == writes
        if not failed:
            client.execute({'kind': 'stop'})
    finally:
        client.close()
        if pid:
            require_inferior_exited(pid)


def main():
    if len(sys.argv) != 2:
        return 2
    real_gdb = shutil.which('gdb')
    if not sys.platform.startswith('linux') or not real_gdb or not shutil.which('clang++'):
        return 77
    for mode in ('initial-width', 'write-width', 'readback-width', 'before-read', 'before-high-bits', 'before-death',
            'ack-error', 'write-rejected', 'mismatch', 'readback', 'malformed-readback', 'write-death', 'refresh-death'):
        with tempfile.TemporaryDirectory(prefix='phantom-register-edit-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('register edit faults: failed/malformed reads, rejected writes, lost acknowledgements, real mismatches, debugger death and immutable retries passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
