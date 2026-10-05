"""Owned full-range protection, unchanged storage and once-only runtime audit."""
from __future__ import annotations

import array
import fcntl
import os
from pathlib import Path
import shutil
import sys
import tempfile
import termios
import time

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited
import runtime_allocation_integration as allocation
import runtime_helper_integration as runtime

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'linux-x86_64-owned-protection-v1'
PERMISSIONS = ('r--', 'rw-', 'r-x')
FLAGS = {'getpid', 'registersRestored', 'stackUnchanged', 'errnoUnchanged',
    'signalMaskUnchanged', 'signalPolicyRestored', 'codeUnchanged',
    'protectionApplied', 'bytesUnchanged', 'mappingDeltaVerified'}


class Client(allocation.Client):
    def send(self, *frames):
        if self.record_requests:
            TRAFFIC.extend(('request', frame) for frame in frames)
        return LifecycleClient.send(self, *frames)

    def recv(self, timeout=25):
        frame = LifecycleClient.recv(self, timeout)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command, expected_stop=None):
        if expected_stop is None and command['kind'] == 'protectRuntimeMemory':
            assert self.observation is not None
            expected_stop = self.observation['stop']
        return super().frame(command, expected_stop)

    def receive_mutation(self, frame):
        result = super().receive_mutation(frame)
        if frame['command']['kind'] != 'protectRuntimeMemory':
            return result
        response = result[1]['result']
        audit = response['intervention']; report = audit['report']; target = audit['target']
        assert response['kind'] == 'runtimeProtectionIntervention', response
        assert audit['profile'] == report['profile'] == PROFILE
        assert audit['action'] == report['action'] == 'protect'
        assert set(report) == {'profile', 'action', 'writeAttempted', 'executionAttempted',
            'debuggerAlive', 'cancelled', 'outcome', 'phase', 'evidence', 'error'}, report
        assert set(target) == {'allocationId', 'addressHex', 'byteCount',
            'expectedPermissions', 'replacementPermissions'}, target
        for key in ('allocationId', 'expectedPermissions', 'replacementPermissions'):
            assert target[key] == frame['command'][key]
        assert report['writeAttempted'] is True and report['executionAttempted'] is True
        if report['outcome'] == 'verified':
            evidence = report['evidence']
            assert set(evidence) == FLAGS | {'pid', 'pageSize', 'addressHex', 'byteCount',
                'registerCount', 'stackBytes', 'beforePermissions', 'afterPermissions'}, evidence
            assert all(evidence[key] is True for key in FLAGS), evidence
            assert evidence['beforePermissions'] == target['expectedPermissions']
            assert evidence['afterPermissions'] == target['replacementPermissions']
            assert evidence['addressHex'] == target['addressHex'] and evidence['byteCount'] == target['byteCount']
            assert type(evidence['pid']) is int and str(evidence['pid']) == audit['processInstanceId']
            page = evidence['pageSize']; address = int(evidence['addressHex'], 16)
            assert type(page) is int and 4096 <= page <= 1048576 and page & (page - 1) == 0
            assert 0 < address < (1 << 63) and address % page == 0
            assert type(evidence['byteCount']) is int and 0 < evidence['byteCount'] <= 1048576
            assert evidence['byteCount'] % page == 0
            assert type(evidence['registerCount']) is int and 32 <= evidence['registerCount'] <= 512
            assert type(evidence['stackBytes']) is int and 4096 <= evidence['stackBytes'] <= 1048576
            assert report['debuggerAlive'] is True and report['phase'] == 'verify' and report['error'] is None
        else:
            assert report['outcome'] == 'failed' and report['debuggerAlive'] is False, report
            assert report['evidence'] is None and report['error'], report
        return result


def protect(identifier, before='rw-', after='r--'):
    return {'kind': 'protectRuntimeMemory', 'profile': PROFILE, 'allocationId': identifier,
        'expectedPermissions': before, 'replacementPermissions': after}


def proc_bytes(item):
    with open(f"/proc/{item['processInstanceId']}/mem", 'rb', buffering=0) as memory:
        memory.seek(int(item['addressHex'], 16))
        data = memory.read(item['byteCount'])
    assert len(data) == item['byteCount']
    return data


def proc_maps(item):
    return Path(f"/proc/{item['processInstanceId']}/maps").read_text()


def map_regions(text):
    for line in text.splitlines():
        address, permissions, offset, device, inode, *path = line.split(maxsplit=5)
        start, end = (int(value, 16) for value in address.split('-'))
        yield start, end, (permissions, offset, device, inode, path[0] if path else '')


def outside(text, low, high):
    """Independent interval comparison allowing anonymous VMA split/merge."""
    regions = []
    for start, end, metadata in map_regions(text):
        pieces = [(start, end)] if end <= low or start >= high else [(start, min(end, low)), (max(start, high), end)]
        for begin, finish in pieces:
            if begin >= finish:
                continue
            anonymous = metadata[0][-1] == 'p' and int(metadata[1], 16) == 0 and metadata[2:] == ('00:00', '0', '')
            if anonymous and regions and regions[-1][1] == begin and regions[-1][2] == metadata:
                regions[-1] = (regions[-1][0], finish, metadata)
            else:
                regions.append((begin, finish, metadata))
    return regions


def assert_permissions(item, expected):
    low = int(item['addressHex'], 16); high = low + item['byteCount']; cursor = low
    for start, end, metadata in map_regions(proc_maps(item)):
        if end <= cursor:
            continue
        if cursor == high:
            break
        assert start <= cursor and metadata[0] == expected + 'p', (item, metadata)
        assert int(metadata[1], 16) == 0 and metadata[2:] == ('00:00', '0', '')
        cursor = min(end, high)
    assert cursor == high


def change(client, item, before, after):
    old = client.observation
    registers = runtime.registers(client)
    maps = proc_maps(item)
    stack = runtime.process_stack(item['processInstanceId'], maps)
    contents = proc_bytes(item)
    totals = allocation.entries(client)
    frame, response, events = client.mutation(protect(item['id'], before, after))
    audit = response['result']['intervention']
    assert audit['report']['outcome'] == 'verified' and audit['contextStatus'] == 'refreshed', audit
    current = allocation.entry(client, item['id'])
    assert current['permissions'] == after and current['lastProtectionInterventionId'] == audit['id']
    assert current['protectionAllowed'] and current['releaseAllowed']
    assert proc_bytes(current) == contents
    assert runtime.memory(client, current['addressHex'], current['byteCount']) == contents
    assert runtime.registers(client) == registers
    assert runtime.process_stack(item['processInstanceId'], maps) == stack
    for field in ('input', 'stdout', 'stderr', 'stack', 'location'):
        assert client.observation[field] == old[field], field
    low = int(item['addressHex'], 16)
    assert outside(maps, low, low + item['byteCount']) == outside(proc_maps(item), low, low + item['byteCount'])
    assert_permissions(current, after)
    latest = allocation.entries(client)
    assert latest['total'] == totals['total'] and latest['totalBytes'] == totals['totalBytes']
    return current, frame, response


def seed(client, item):
    expected = bytearray(item['byteCount'])
    # Trap instructions are only data here. Padding beyond requestedBytes is
    # also part of the owned page-rounded extent and must survive protection.
    for offset, value in ((0, bytes.fromhex('0f0bcc') + bytes(range(29))),
                          (4096 - 16, bytes(range(32))),
                          (item['byteCount'] - 32, bytes(range(255, 223, -1)))):
        client.mutation({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
            'addressHex': hex(int(item['addressHex'], 16) + offset),
            'expectedBytesHex': bytes(expected[offset:offset + len(value)]).hex(),
            'replacementBytesHex': value.hex()})
        expected[offset:offset + len(value)] = value
    assert proc_bytes(item) == expected
    return bytes(expected)


def successful(client, artifact):
    allocation.launch(client, artifact)
    original_maps = proc_maps({'processInstanceId': client.observation['processInstanceId']})
    neighbors = [allocation.new_allocation(client, 4097)[0] for _ in range(3)]
    item = neighbors[1]
    contents = seed(client, item)
    memory_ledger = client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})['items']
    current = 'rw-'
    saved = None
    # Euler cycle covers all six distinct transitions and all three actual
    # same-permission mprotect calls without resetting the process.
    for after in ('rw-', 'r--', 'r--', 'r-x', 'r-x', 'r--', 'rw-', 'r-x', 'rw-'):
        item, frame, response = change(client, item, current, after)
        if saved is None:
            saved = frame, response
        current = after
        assert proc_bytes(item) == contents
        for neighbor in (neighbors[0], neighbors[2]):
            assert_permissions(neighbor, 'rw-')
            assert proc_bytes(neighbor) == bytes(neighbor['byteCount'])
            assert allocation.entry(client, neighbor['id'])['protectionAllowed']
        if after != 'rw-':
            baseline = client.checkpoint(); count = runtime.ledger(client)['total']
            edit = {'addressHex': item['addressHex'], 'expectedBytesHex': contents[:1].hex(), 'replacementBytesHex': '01'}
            client.reject(client.frame({'kind': 'writeMemory', 'profile': 'native-private-memory-v1', **edit}))
            # Valid first range must not execute when a later range is RO/RX.
            writable = {'addressHex': neighbors[0]['addressHex'], 'expectedBytesHex': '00', 'replacementBytesHex': '01'}
            client.reject(client.frame({'kind': 'writeMemoryBatch', 'profile': 'native-private-memory-batch-v1',
                'edits': [writable, edit]}))
            assert client.checkpoint() == baseline and runtime.ledger(client)['total'] == count
            assert proc_bytes(neighbors[0]) == bytes(neighbors[0]['byteCount'])
    assert client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})['items'] == memory_ledger
    assert client.good({'kind': 'listRegisterInterventions', 'start': 0, 'count': 128})['items'] == []
    # Old receipts remain immutable after subsequent protection and release.
    newest = allocation.entry(client, item['id'])
    client.send(saved[0]); assert client.recv() == saved[1]
    assert allocation.entry(client, item['id']) == newest
    client.reject({**saved[0], 'command': protect(item['id'], 'rw-', 'r-x')})
    client.mutation({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': item['addressHex'], 'expectedBytesHex': contents[:1].hex(), 'replacementBytesHex': '90'})
    for target, permissions in ((neighbors[0], 'r--'), (item, 'r-x'), (neighbors[2], 'rw-')):
        target, _, _ = change(client, target, 'rw-', permissions)
        last = allocation.entry(client, target['id'])['lastProtectionInterventionId']
        client.mutation(allocation.release(target['id']))
        ended = allocation.entry(client, target['id'])
        assert ended['state'] == 'released' and ended['permissions'] == permissions
        assert ended['lastProtectionInterventionId'] == last
        client.reject(client.frame(protect(target['id'], permissions, 'rw-')), ('STALE_CONTEXT',))
    assert allocation.entries(client)['totalBytes'] == 0
    assert proc_maps(item) == original_maps
    client.send(saved[0]); assert client.recv() == saved[1]
    assert allocation.entry(client, item['id'])['state'] == 'released'
    assert client.good({'kind': 'readIntervention', 'interventionId': saved[1]['result']['intervention']['id']})['intervention'] == saved[1]['result']['intervention']
    allocation.at_after(client)
    client.execute({'kind': 'continue'})
    assert client.checkpoint()['state']['exit']['code'] == 0
    return saved[0]


def validation(client, artifact):
    allocation.launch(client, artifact)
    item, _, _ = allocation.new_allocation(client)
    baseline = client.checkpoint(); original = allocation.entry(client, item['id'])
    count = runtime.ledger(client)['total']
    for field in ('expectedPermissions', 'replacementPermissions'):
        for bad in ('rwx', '---', '--x', 'rw-p', 'R-X', '', None, True, 5, [], {}):
            client.reject(client.frame({**protect(item['id']), field: bad}), valid=False)
    for patch in ({'addressHex': item['addressHex']}, {'byteCount': 1}, {'offset': 0}, {'profile': allocation.PROFILE}):
        client.reject(client.frame({**protect(item['id']), **patch}), valid=False)
    for missing_field in ('expectedPermissions', 'replacementPermissions', 'allocationId'):
        command = protect(item['id']); del command[missing_field]
        client.reject(client.frame(command), valid=False)
    missing = client.frame(protect(item['id'])); del missing['expectedStop']
    client.reject(missing, valid=False)
    no_session = client.frame(protect(item['id'])); no_session['session'] = None
    client.reject(no_session, ('STALE_CONTEXT',))
    client.reject(client.frame(protect('allocation-missing')), ('STALE_CONTEXT',))
    client.reject(client.frame(protect(item['id'], 'r--', 'r-x')), ('STALE_CONTEXT',))
    assert client.checkpoint() == baseline and allocation.entry(client, item['id']) == original
    assert runtime.ledger(client)['total'] == count
    stale = client.frame(protect(item['id']))
    item, _, _ = change(client, item, 'rw-', 'r--')
    client.reject(stale, ('STALE_CONTEXT',))
    assert allocation.entry(client, item['id']) == item
    client.execute({'kind': 'stop'})
    client.reject(client.frame(protect(item['id'], 'r--', 'rw-'), expected_stop=item['authorityStop']), ('STALE_CONTEXT',))
    dead = allocation.entry(client, item['id'])
    assert dead['state'] == 'process-ended' and dead['permissions'] == 'r--'
    allocation.launch(client, artifact, profile='native')
    client.reject(client.frame(protect('allocation-1')), ('UNSUPPORTED', 'STALE_CONTEXT'))
    assert runtime.ledger(client)['total'] == 0
    client.execute({'kind': 'stop'})


def authority_and_aba(client, artifact):
    allocation.launch(client, artifact, mode='a')
    item, _, _ = allocation.new_allocation(client, 8192)
    item, saved, response = change(client, item, 'rw-', 'r-x')
    client.good({'kind': 'appendInput', 'id': 'protection-aba', 'text': f"{item['addressHex']} {item['byteCount']}\n"})
    assert allocation.entry(client, item['id'])['protectionAllowed']
    allocation.at_after(client)
    unknown = allocation.entry(client, item['id'])
    assert unknown['state'] == 'ownership-unknown' and unknown['permissions'] == 'r-x'
    assert_permissions(item, 'rw-')  # User munmap/MAP_FIXED produced a new object.
    assert proc_bytes(item) == bytes(item['byteCount'])
    for command in (protect(item['id'], 'r-x', 'rw-'), protect(item['id'], 'rw-', 'r-x'), allocation.release(item['id'])):
        client.reject(client.frame(command), ('STALE_CONTEXT',))
    client.good({'kind': 'readHistory', 'point': item['createdAt']})
    client.send(saved); assert client.recv() == response
    assert allocation.entry(client, item['id']) == unknown
    assert_permissions(item, 'rw-')
    client.execute({'kind': 'continue'})
    assert client.checkpoint()['state']['exit']['code'] == 0
    assert allocation.entry(client, item['id'])['state'] == 'process-ended'


def input_isolation(client, artifact):
    allocation.launch(client, artifact, mode='i')
    item, _, _ = allocation.new_allocation(client)
    descriptor = os.open(f"/proc/{item['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        capacity = fcntl.fcntl(descriptor, fcntl.F_SETPIPE_SZ, 4096)
        chunk = {'kind': 'appendInput', 'id': 'protect-final-chunk', 'text': 'q' * (2 * capacity)}
        assert client.good(chunk)['input']['deliveredBytes'] == capacity
        closed = client.good({'kind': 'closeInput'})['input']
        assert closed['eof'] == 'requested' and closed['status'] == 'reading'
        assert os.read(descriptor, capacity) == b'q' * capacity
        # The old Observation still predates appendInput/closeInput. Compare
        # the refreshed input with their returned DTO, not that old snapshot.
        _, protected, _ = client.mutation(protect(item['id'], 'rw-', 'r-x'))
        assert protected['result']['intervention']['report']['outcome'] == 'verified'
        client.mutation(allocation.release(item['id']))
        count = array.array('i', [0]); fcntl.ioctl(descriptor, termios.FIONREAD, count, True)
        assert count[0] == 0, 'protection helper exposed queued input'
        try:
            received = os.read(descriptor, 1)
        except BlockingIOError:
            pass
        else:
            raise AssertionError(('protection helper delivered bytes or EOF', received))
        assert client.observation['input'] == closed and client.good(chunk)['input'] == closed
        allocation.at_after(client)
        total = next(value for value in client.observation['stack'][0]['variables'] if value['name'] == 'total')
        assert total['value']['value']['decimal'] == str(capacity)
        assert client.observation['input']['status'] == 'complete' and os.read(descriptor, 1) == b''
        client.execute({'kind': 'continue'})
        assert client.checkpoint()['state']['exit']['code'] == 0
    finally:
        os.close(descriptor)


def denied_syscalls(client, artifact):
    # Even same->same is a real syscall and must not bypass seccomp policy.
    for after in ('rw-', 'r-x'):
        allocation.launch(client, artifact, mode='p')
        item, _, _ = allocation.new_allocation(client)
        frame, response, _ = client.mutation(protect(item['id'], 'rw-', after))
        audit = response['result']['intervention']
        assert audit['report']['outcome'] == 'failed' and audit['contextStatus'] == 'failed'
        dead = allocation.entry(client, item['id'])
        assert dead['state'] == 'process-ended' and dead['permissions'] == 'rw-'
        assert dead['lastProtectionInterventionId'] is None and allocation.entries(client)['totalBytes'] == 0
        require_inferior_exited(item['processInstanceId'])
        client.send(frame); assert client.recv() == response


def make_proxy(path, real_gdb):
    runtime.proxy(path, real_gdb)
    text = path.read_text().replace('_phantom_runtime_helper_execute', '_phantom_runtime_protection_execute')
    text = text.replace('PHANTOM_RUNTIME_HELPER_RESULT_V1:', 'PHANTOM_RUNTIME_PROTECTION_RESULT_V1:')
    # Only alter the trusted test proxy's read-only proc view. No target
    # syscall/personality mutation is necessary to exercise the preflight.
    old = '                prepare_token = token\n'
    new = old + r'''
                if mode == 'personality':
                    console = json.loads(command[len(b'-interpreter-exec console '):])
                    program = json.loads(console[len('python exec('):-1])
                    patch = "\n_original_proc = _phantom_runtime_helper_proc\n"
                    patch += "def _phantom_runtime_helper_proc(pid, name):\n return '00400000\\n' if name == 'personality' else _original_proc(pid, name)\n"
                    program = program.replace('\n_phantom_runtime_helper_prepare(', patch + '\n_phantom_runtime_helper_prepare(')
                    console = 'python exec(' + json.dumps(program) + ')'
                    line = token + b'-interpreter-exec console ' + json.dumps(console).encode() + b'\n'
                    fault()
'''
    assert old in text
    path.write_text(text.replace(old, new))


def fault_scenarios(executable, real_gdb, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    make_proxy(tools / 'gdb', real_gdb)
    client = Client(executable, workspace, {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')})
    try:
        artifact = runtime.build(client, source=allocation.SOURCE)
        for mode in ('prepare-cancel', 'ack-error', 'malformed-proof', 'refresh-death',
                     'signal-during', 'cancel', 'timeout', 'queued-stop', 'personality'):
            for name in ('arm', 'fault', 'release', 'commands', 'executions'):
                (tools / name).unlink(missing_ok=True)
            (tools / 'mode').write_text(mode)
            allocation.launch(client, artifact)
            item, _, _ = allocation.new_allocation(client)
            before = client.observation; registers = runtime.registers(client)
            marker = Path(f"/proc/{item['processInstanceId']}/cwd").resolve() / 'runtime-signal-handler-ran'
            marker.unlink(missing_ok=True)
            request = client.frame(protect(item['id'], 'rw-', 'r-x'))
            (tools / 'arm').touch()
            client.send(request)
            runtime.wait_fault(tools / 'fault')
            if mode == 'personality':
                response = client.recv()
                assert not response['ok'] and response['error']['code'] == 'UNSUPPORTED', response
                client.reject(client.frame(allocation.allocate()), ('UNSUPPORTED',))
                assert client.checkpoint()['observation'] == before and runtime.registers(client) == registers
                assert runtime.ledger(client)['total'] == 1 and not (tools / 'executions').exists()
                assert allocation.entry(client, item['id']) == item
                # Release removes memory without introducing R/X permissions.
                client.mutation(allocation.release(item['id']))
                assert allocation.entry(client, item['id'])['state'] == 'released'
                client.reject(client.frame(runtime.COMMAND), ('UNSUPPORTED',))
                (tools / 'arm').unlink()
                client.execute({'kind': 'stop'})
                continue
            control = None; started = time.monotonic()
            if mode in ('cancel', 'prepare-cancel', 'queued-stop'):
                control = client.frame({'kind': 'stop'} if mode == 'queued-stop' else
                    {'kind': 'cancel', 'targetRequestId': request['requestId']})
                client.send(control)
                if mode in ('prepare-cancel', 'queued-stop'):
                    time.sleep(.1)
                    (tools / 'release').touch()
            if mode == 'prepare-cancel':
                response = client.recv()
                assert response['requestId'] == request['requestId'] and response['error']['code'] == 'CANCELLED'
                accepted, completed = client.recv(), client.recv()
                assert accepted['ok'] and accepted['requestId'] == control['requestId']
                assert completed['payload']['requestId'] == control['requestId'] and completed['payload']['outcome'] == 'completed'
                assert client.checkpoint()['observation'] == before and runtime.registers(client) == registers
                assert not (tools / 'executions').exists() and allocation.entry(client, item['id']) == item
                assert_permissions(item, 'rw-')
                (tools / 'arm').unlink()
                change(client, item, 'rw-', 'r-x')
                client.mutation(allocation.release(item['id']))
                client.execute({'kind': 'stop'})
                continue
            _, response, _ = client.receive_mutation(request)
            audit = response['result']['intervention']
            if mode == 'queued-stop':
                assert audit['report']['outcome'] == 'verified' and not audit['report']['cancelled']
                client.finish([control])
                dead = allocation.entry(client, item['id'])
                assert dead['state'] == 'process-ended' and dead['permissions'] == 'r-x'
                assert dead['lastProtectionInterventionId'] == audit['id']
                assert client.checkpoint()['state']['phase'] == 'terminated'
            else:
                assert audit['contextStatus'] == 'failed' and audit['report']['cancelled'] is (mode == 'cancel')
                if control:
                    accepted, completed = client.recv(), client.recv()
                    assert accepted['ok'] and accepted['requestId'] == control['requestId']
                    assert completed['payload']['requestId'] == control['requestId'] and completed['payload']['outcome'] == 'completed'
                    assert time.monotonic() - started < 4
                if mode == 'timeout':
                    assert audit['report']['error']['code'] == 'TIMEOUT'
                    assert 5 < time.monotonic() - started < 15
                assert client.checkpoint()['state']['phase'] == 'failed'
                dead = allocation.entry(client, item['id'])
                assert dead['state'] == 'process-ended'
                assert dead['permissions'] == ('r-x' if mode == 'refresh-death' else 'rw-')
                assert dead['lastProtectionInterventionId'] == (audit['id'] if mode == 'refresh-death' else None)
            assert allocation.entries(client)['totalBytes'] == 0
            require_inferior_exited(item['processInstanceId'])
            assert not marker.exists(), 'signal handler ran during protection syscall'
            assert len((tools / 'executions').read_bytes().splitlines()) == 1
            client.send(request); assert client.recv() == response
            assert len((tools / 'executions').read_bytes().splitlines()) == 1
            assert client.good({'kind': 'readIntervention', 'interventionId': audit['id']})['intervention'] == audit
    finally:
        client.close()


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-protection-') as directory:
        client = Client(executable, Path(directory), dict(os.environ))
        try:
            native = runtime.build(client, runtime=False, source=allocation.SOURCE)
            allocation.launch(client, native)
            client.reject(client.frame(protect('allocation-1')), ('UNSUPPORTED',))
            assert runtime.ledger(client)['total'] == 0
            client.execute({'kind': 'stop'})
            artifact = runtime.build(client, source=allocation.SOURCE)
            old = successful(client, artifact)
            validation(client, artifact)
            client.reject(old, ('STALE_CONTEXT',))
            authority_and_aba(client, artifact)
            input_isolation(client, artifact)
            denied_syscalls(client, artifact)
        finally:
            client.close()
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-protection-faults-') as directory:
        fault_scenarios(executable, str(Path(shutil.which('gdb')).resolve()), Path(directory))
    print('runtime protection: all RW/RO/RX transitions, unchanged bytes/context, release, authority, ABA and once-only failures passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
