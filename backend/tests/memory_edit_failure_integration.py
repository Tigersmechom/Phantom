"""Real GDB writes with injected MI failures: audit and live-context recovery."""
from __future__ import annotations
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path
import memory_edit_integration as edits
from service_integration import Client as TransportClient
from lifecycle_integration import require_inferior_exited

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
import os, pathlib, re, subprocess, sys, threading
root = pathlib.Path(__file__).parent
child = subprocess.Popen([REAL, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
write_token = None
written = False
read_failed = False
lock = threading.Lock()
def output(line):
    with lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
def forward():
    global written
    for line in child.stdout:
        if write_token is not None and line.startswith(write_token + b'^done'):
            written = True
            if MODE == 'write-death':
                (root / 'fault').write_text('write-death')
                child.kill()
                os._exit(0)
            if MODE in ('ack-error', 'partial'):
                (root / 'fault').write_text(MODE)
                line = write_token + b'^error,msg="injected write acknowledgement failure"\n'
        output(line)
reader = threading.Thread(target=forward, daemon=True)
reader.start()
try:
    for line in sys.stdin.buffer:
        match = re.match(rb'(\d+)(.*)', line.rstrip(b'\n'))
        token, command = match.groups()
        if (root / 'arm').exists():
            if command.startswith(b'-data-write-memory-bytes '):
                write_token = token
                with (root / 'writes').open('ab') as file: file.write(line)
                if MODE == 'partial':
                    pieces = command.split()
                    line = token + b' '.join([pieces[0], pieces[1], pieces[2][:4]]) + b'\n'
            if written and command.startswith(b'-data-read-memory-bytes ') and MODE == 'readback' and not read_failed:
                read_failed = True
                (root / 'fault').write_text('readback')
                output(token + b'^error,msg="injected readback failure"\n')
                continue
            if written and command == b'-stack-info-frame' and MODE == 'refresh-death':
                (root / 'fault').write_text('refresh-death')
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
        artifact = client.good({'kind': 'build', 'source': {'id': 'memory-edit-source', 'documents': [{
            'documentId': 'memory-edit', 'revisionId': 'memory-edit-1', 'path': 'memory-edit.cpp',
            'text': edits.SOURCE, 'sha256': hashlib.sha256(edits.SOURCE.encode()).hexdigest()}]},
            'configuration': {'revisionId': 'memory-edit-config', 'compiler': 'clang++',
                'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build'},
            'architecture': 'x86_64'})['artifact']
        client.launch_edit(artifact)
        before = edits.at_edit(client); pid = before['processInstanceId']
        address = int(edits.variable(client, 'counter')['addressHex'], 16)
        frame = client.frame(edits.write(address, edits.number(7), bytes.fromhex('11223344')))
        (tools / 'arm').touch()
        response = client.send(frame)
        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        audit = response['result']['intervention']; report = audit['report']
        assert report['writeAttempted'] and report['beforeBytesHex'] == '07000000', audit
        failed = mode in ('write-death', 'refresh-death')
        events = [client.recv() for _ in range(2 if failed else 3)]
        assert events[0]['payload']['kind'] == 'branchCreated'
        assert all(e.get('causedByRequestId') == frame['requestId'] for e in events)
        assert events[-1]['sequence'] == response['result']['throughSequence']
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed' and audit['refreshError'], audit
            assert audit['afterPoint'] is None and audit['afterStop'] is None
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None
            assert checkpoint['observation'] is None, checkpoint
            assert events[-1]['payload']['state'] == checkpoint['state']
            require_inferior_exited(pid)
        else:
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None, audit
            client.observation = events[1]['payload']['observation']
            assert checkpoint['observation'] == client.observation
            assert client.observation['stop'] != before['stop']
            assert edits.memory(client, address, 4).hex() == ('11220000' if mode == 'partial' else '11223344')
        if mode == 'partial':
            assert report['outcome'] == 'readback-mismatch' and report['afterBytesHex'] == '11220000', report
        elif mode == 'readback':
            assert report['outcome'] == 'unverified' and report['afterBytesHex'] is None, report
        elif mode == 'write-death':
            assert report['outcome'] == 'unverified' and report['afterBytesHex'] is None, report
        else:
            assert report['outcome'] == 'verified' and report['afterBytesHex'] == '11223344', report
        assert report['writeAcknowledged'] == (mode in ('readback', 'refresh-death')), report
        assert not report['rollbackAttempted'] and not report['atomic']
        assert (tools / 'fault').read_text() == mode
        assert client.send(frame) == response  # Even a dead debugger must not repeat the effect.
        assert len((tools / 'writes').read_bytes().splitlines()) == 1
        assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        branches = client.good({'kind': 'listBranches'})
        assert branches['currentBranchId'] == audit['branchId'] and len(branches['branches']) == 2
        if not failed: client.execute({'kind': 'stop'})
    finally:
        client.close()
        if pid: require_inferior_exited(pid)


def main():
    if len(sys.argv) != 2: return 2
    real_gdb = shutil.which('gdb')
    if not sys.platform.startswith('linux') or not real_gdb or not shutil.which('clang++'): return 77
    for mode in ('ack-error', 'partial', 'readback', 'write-death', 'refresh-death'):
        with tempfile.TemporaryDirectory(prefix='phantom-edit-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('memory edit failures: partial writes, error acknowledgements, missing readback, debugger death and dedup passed')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
