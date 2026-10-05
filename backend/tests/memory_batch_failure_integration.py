"""Real ordered memory batches retain partial effects and stop after faults."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import memory_batch_integration as batches
import memory_edit_integration as edits
from lifecycle_integration import require_inferior_exited
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []


class Client(batches.Client):
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
tokens = {}
write_count = 0
completed = 0
read_failed = False
reads_after_last = 0
lock = threading.Lock()
def output(line):
    with lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
def change(field, data):
    config = json.loads((root / 'ranges.json').read_text())
    descriptor = os.open('/proc/' + config['pid'] + '/mem', os.O_RDWR)
    try:
        payload = bytes.fromhex(data)
        assert os.pwrite(descriptor, payload, config[field]) == len(payload)
    finally:
        os.close(descriptor)
    (root / 'fault').write_text(MODE)
def forward():
    global completed
    for line in child.stdout:
        match = re.match(rb'(\d+)\^done', line)
        ordinal = tokens.get(match.group(1)) if match else None
        if ordinal is not None:
            completed = ordinal
            if ordinal == 1 and MODE == 'late-conflict':
                change('second', 'deadbeef')
            if ordinal == 3 and MODE == 'final-drift':
                change('first', 'cafebabe')
            if ordinal == 2 and MODE == 'write-death':
                (root / 'fault').write_text(MODE)
                child.kill()
                os._exit(0)
            if ordinal == 2 and MODE in ('ack-error', 'partial'):
                (root / 'fault').write_text(MODE)
                line = match.group(1) + b'^error,msg="injected second-write acknowledgement failure"\n'
        output(line)
reader = threading.Thread(target=forward, daemon=True)
reader.start()
try:
    for line in sys.stdin.buffer:
        match = re.match(rb'(\d+)(.*)', line.rstrip(b'\n'))
        token, command = match.groups()
        if (root / 'arm').exists():
            with (root / 'commands').open('ab') as file: file.write(line)
            if command.startswith(b'-data-write-memory-bytes '):
                write_count += 1
                tokens[token] = write_count
                with (root / 'writes').open('ab') as file: file.write(line)
                if write_count == 2 and MODE == 'partial':
                    pieces = command.split()
                    line = token + b' '.join([pieces[0], pieces[1], pieces[2][:4]]) + b'\n'
            if command.startswith(b'-data-read-memory-bytes '):
                if completed == 3:
                    reads_after_last += 1
                fail = MODE == 'readback' and completed == 2 or MODE == 'final-readback' and reads_after_last == 2
                if fail and not read_failed:
                    read_failed = True
                    (root / 'fault').write_text(MODE)
                    output(token + b'^error,msg="injected batch read failure"\n')
                    continue
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
        artifact = batches.build(client)
        client.launch_edit(artifact)
        before = edits.at_edit(client)
        pid = before['processInstanceId']
        address = edits.pointer(client, 'middle')
        initial = bytes(range(12))
        replacements = [bytes.fromhex(text) for text in ('10203040', '50607080', '90a0b0c0')]
        ranges = [batches.item(address + index * 4, initial[index * 4:index * 4 + 4], replacements[index])
                  for index in range(3)]
        (tools / 'ranges.json').write_text(json.dumps({'pid': pid, 'first': address, 'second': address + 4}))
        frame = client.frame(batches.command(ranges))
        (tools / 'arm').touch()
        response = client.send(frame)
        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        audit = response['result']['intervention']; report = audit['report']; items = report['items']
        assert audit['profile'] == batches.PROFILE and audit['requestId'] == frame['requestId']
        assert audit['beforePoint'] == before['point'] and audit['beforeStop'] == before['stop']
        assert report['preflightPassed'] and report['writeAttempted'] and report['byteCount'] == 12
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        assert len(audit['mappings']) == 3 and 'mapping' not in audit
        for index, part in enumerate(items):
            assert part['index'] == index and int(part['addressHex'], 16) == address + index * 4
            assert part['preflight'] == {'bytesHex': initial[index * 4:index * 4 + 4].hex(),
                                         'matchesExpected': True, 'error': None}, part
        assert items[0]['execution']['outcome'] == 'verified'
        assert items[0]['execution']['afterBytesHex'] == replacements[0].hex()

        failed = mode == 'write-death'
        final_failure = mode in ('final-drift', 'final-readback')
        expected_writes = 3 if final_failure else 1 if mode == 'late-conflict' else 2
        events = [client.recv() for _ in range(2 if failed else 3)]
        assert [event['payload']['kind'] for event in events] == (
            ['branchCreated', 'state'] if failed else ['branchCreated', 'observation', 'state']), events
        assert all(event.get('causedByRequestId') == frame['requestId'] for event in events)
        assert events[0]['payload']['parent'] == before['point']
        assert response['result']['throughSequence'] == events[-1]['sequence']
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed' and audit['refreshError']
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None
            assert checkpoint['observation'] is None and audit['afterPoint'] is None and audit['afterStop'] is None
            assert all(part['final'] is None for part in items), report
            require_inferior_exited(pid)
        else:
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None
            client.observation = events[1]['payload']['observation']
            assert checkpoint['observation'] == client.observation
            assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
            first = bytes.fromhex('cafebabe') if mode == 'final-drift' else replacements[0]
            second = bytes.fromhex('deadbeef') if mode == 'late-conflict' else (
                replacements[1][:2] + initial[6:8] if mode == 'partial' else replacements[1])
            third = replacements[2] if final_failure else initial[8:12]
            assert edits.memory(client, address, 12) == first + second + third
            for index, observed in enumerate((first, second, third)):
                final = items[index]['final']
                if mode == 'final-readback' and index == 0:
                    assert final['bytesHex'] is None and final['error'] and final['matchesReplacement'] is None
                else:
                    assert final == {'bytesHex': observed.hex(),
                        'matchesExpected': observed == initial[index * 4:index * 4 + 4],
                        'matchesReplacement': observed == replacements[index], 'error': None}, final

        assert report['outcome'] == ('verification-failed' if final_failure else 'interrupted'), report
        assert report['failureIndex'] == (0 if final_failure else 1), report
        if final_failure:
            assert all(part['execution']['outcome'] == 'verified' for part in items), items
        else:
            assert items[2]['execution'] is None, 'later edits must not execute after a fault'
            second = items[1]['execution']
            if mode == 'late-conflict':
                assert second['outcome'] == 'conflict' and not second['writeAttempted']
                assert second['beforeBytesHex'] == 'deadbeef'
            elif mode == 'partial':
                assert second['outcome'] == 'readback-mismatch' and second['afterBytesHex'] == '50600607'
            elif mode == 'ack-error':
                assert second['outcome'] == 'verified' and second['afterMatchesReplacement'] is True
                assert second['writeAcknowledged'] is False and second['errors']
            else:
                assert second['outcome'] == 'unverified' and second['afterBytesHex'] is None
                if mode == 'readback':
                    # Batch final reads can independently observe success but
                    # cannot overwrite the failed per-edit readback or resume.
                    assert items[1]['final']['matchesReplacement'] is True

        assert (tools / 'fault').read_text() == mode
        writes = (tools / 'writes').read_bytes().splitlines()
        assert len(writes) == expected_writes, writes
        for index, line in enumerate(writes):
            assert f' {hex(address + index * 4)} '.encode() in line, writes
        commands = (tools / 'commands').read_bytes().splitlines()
        first_write_index = next(index for index, line in enumerate(commands) if b'-data-write-memory-bytes ' in line)
        read_addresses = {line.split()[1] for line in commands[:first_write_index] if b'-data-read-memory-bytes ' in line}
        assert all(hex(address + index * 4).encode() in read_addresses for index in range(3)), commands

        assert client.send(frame) == response
        changed = {**frame, 'command': batches.command(list(reversed(ranges)))}
        edits.reject_frame(client, changed, 'INVALID_REQUEST')
        assert len((tools / 'writes').read_bytes().splitlines()) == expected_writes
        assert edits.audits(client)['items'] == [audit]
        assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        branches = client.good({'kind': 'listBranches'})
        assert branches['currentBranchId'] == audit['branchId'] and len(branches['branches']) == 2
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
    for mode in ('late-conflict', 'partial', 'ack-error', 'readback', 'write-death', 'final-drift', 'final-readback'):
        with tempfile.TemporaryDirectory(prefix='phantom-memory-batch-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('memory batch failures: preflight/recheck ordering, partial effects, stop-on-error, skipped ranges, final evidence, debugger loss and dedup passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
