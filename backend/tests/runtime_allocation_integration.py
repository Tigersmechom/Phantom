"""Retained RW mappings, server-owned release authority and immutable audit."""
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
import runtime_helper_integration as runtime

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'linux-x86_64-retained-rw-v1'
FLAGS = {'getpid', 'allocated', 'released', 'zeroInitialized', 'registersRestored',
    'stackUnchanged', 'errnoUnchanged', 'signalMaskUnchanged', 'signalPolicyRestored',
    'codeUnchanged', 'mappingDeltaVerified'}
SOURCE = runtime.SOURCE.replace('volatile unsigned int counter = 7;', 'unsigned int counter = 7;').replace(
    '#include <sys/prctl.h>', '#include <sys/prctl.h>\n#include <sys/mman.h>').replace(
    '  counter = counter + 1;', r'''  if (mode == 'a') {
    unsigned long long address = 0;
    unsigned long count = 0;
    std::cin >> std::hex >> address >> std::dec >> count;
    if (!std::cin || !address || !count) return 111;
    void* target = reinterpret_cast<void*>(address);
    if (munmap(target, count)) return 112;
    if (mmap(target, count, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != target) return 113;
  }
  counter = counter + 1;''')


class Client(runtime.Client):
    def send(self, *frames):
        if self.record_requests:
            TRAFFIC.extend(('request', frame) for frame in frames)
        return LifecycleClient.send(self, *frames)

    def recv(self, timeout=25):
        frame = LifecycleClient.recv(self, timeout)
        TRAFFIC.append(('received', frame))
        return frame

    def frame(self, command, expected_stop=None):
        if expected_stop is None and command['kind'] in ('allocateRuntimeMemory', 'releaseRuntimeMemory',
                'writeScalarStorage', 'writeMemoryBatch', 'traceInstructions', 'seekRecording', 'reverseInstruction'):
            assert self.observation is not None
            expected_stop = self.observation['stop']
        return super().frame(command, expected_stop)

    def mutation(self, command):
        frame = self.frame(command)
        self.send(frame)
        return self.receive_mutation(frame)

    def receive_mutation(self, frame):
        response = self.recv()
        assert response['ok'] and response['requestId'] == frame['requestId'], response
        result = response['result']; audit = result['intervention']; report = audit['report']
        allocation = frame['command']['kind'] in ('allocateRuntimeMemory', 'releaseRuntimeMemory')
        if allocation:
            action = 'allocate' if frame['command']['kind'] == 'allocateRuntimeMemory' else 'release'
            assert result['kind'] == 'runtimeAllocationIntervention' and audit['profile'] == PROFILE
            assert audit['action'] == action and report['action'] == action and report['profile'] == PROFILE
            assert set(audit['target']) == {'allocationId', 'addressHex', 'requestedBytes', 'byteCount'}
            assert report['writeAttempted'] and report['executionAttempted'], report
            if report['outcome'] == 'verified':
                proof = report['evidence']
                assert set(proof) == FLAGS | {'pid', 'pageSize', 'addressHex', 'byteCount', 'registerCount', 'stackBytes'}, proof
                assert proof['allocated'] is (action == 'allocate')
                assert proof['released'] is (action == 'release')
                assert proof['zeroInitialized'] is (action == 'allocate')
                assert all(proof[key] is True for key in FLAGS - {'allocated', 'released', 'zeroInitialized'}), proof
                assert str(proof['pid']) == audit['processInstanceId']
                page = proof['pageSize']; address = int(proof['addressHex'], 16)
                assert type(page) is int and 4096 <= page <= 1048576 and page & (page - 1) == 0
                assert 0 < address < (1 << 63) and address % page == 0
                assert type(proof['registerCount']) is int and 32 <= proof['registerCount'] <= 512
                assert type(proof['stackBytes']) is int and 4096 <= proof['stackBytes'] <= 1048576
                assert type(proof['byteCount']) is int and proof['byteCount'] % page == 0
                assert audit['target']['addressHex'] == proof['addressHex'] and audit['target']['byteCount'] == proof['byteCount']
                assert report['error'] is None and report['phase'] == 'verify' and report['debuggerAlive']
            else:
                assert report['outcome'] == 'failed' and report['error'] and report['evidence'] is None, report
                assert report['debuggerAlive'] is False
        assert audit['requestId'] == frame['requestId']
        events = []
        if report['writeAttempted']:
            kinds = ['branchCreated', 'state'] if audit['contextStatus'] == 'failed' else ['branchCreated', 'observation', 'state']
            events = [self.recv() for _ in kinds]
            assert [event['payload']['kind'] for event in events] == kinds, events
            assert all(event['causedByRequestId'] == frame['requestId'] for event in events)
            assert events[0]['payload']['parent'] == audit['beforePoint']
            assert result['throughSequence'] == events[-1]['sequence']
            if audit['contextStatus'] == 'refreshed':
                assert audit['afterPoint'] == self.observation['point'] and audit['afterStop'] == self.observation['stop']
            else:
                assert audit['afterPoint'] is None and audit['afterStop'] is None and audit['refreshError']
                assert events[-1]['payload']['state']['phase'] == 'failed'
        return frame, response, events


def allocate(count=1):
    return {'kind': 'allocateRuntimeMemory', 'profile': PROFILE, 'byteCount': count}


def release(identifier):
    return {'kind': 'releaseRuntimeMemory', 'profile': PROFILE, 'allocationId': identifier}


def entries(client, start=0, count=128):
    result = client.good({'kind': 'listRuntimeAllocations', 'start': start, 'count': count})
    assert result['kind'] == 'runtimeAllocations' and result['start'] == start
    assert result['totalBytes'] >= 0 and len(result['items']) <= count
    return result


def entry(client, identifier):
    result = client.good({'kind': 'readRuntimeAllocation', 'allocationId': identifier})
    assert result['kind'] == 'runtimeAllocation'
    item = result['allocation']
    assert set(item) == {'id', 'processInstanceId', 'requestedBytes', 'byteCount', 'addressHex',
        'createdByInterventionId', 'createdAt', 'releasedByInterventionId', 'state',
        'invalidatedByRequestId', 'releaseAllowed', 'authorityStop'}, item
    assert item['id'] == identifier
    assert item['releaseAllowed'] is (item['state'] == 'owned')
    if item['releaseAllowed']:
        assert item['authorityStop'] == client.observation['stop'] and item['invalidatedByRequestId'] is None
    else:
        assert item['authorityStop'] is None
    return item


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1', 'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def launch(client, artifact, mode='n', profile='single-process-v1'):
    client.execute({'kind': 'launch', 'buildId': artifact['id'], 'input': {'id': 'allocation-input',
        'text': '', 'encoding': 'utf-8', 'closeAfterWrite': False}, 'argv': [mode], 'environment': {},
        'stopAtEntry': True, 'recordingProfile': 'native', 'processProfile': profile})
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1',
        'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True} for marker in ('HOLD', 'AFTER')]})
    assert all(item['verified'] for item in result['breakpoints'])
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('HOLD')['start']['line']
    assert entries(client)['total'] == 0


def at_after(client):
    for attempt in range(2):
        events = client.execute({'kind': 'continue'})
        assert events[-1]['payload']['outcome'] == 'completed', events
        line = client.observation['location']['start']['line']
        if line == location('AFTER')['start']['line']:
            return
        assert attempt == 0 and line == location('HOLD')['start']['line'], client.checkpoint()
    raise AssertionError('program did not reach AFTER')


def new_allocation(client, count=1):
    frame, response, _ = client.mutation(allocate(count))
    audit = response['result']['intervention']
    assert audit['contextStatus'] == 'refreshed' and audit['report']['outcome'] == 'verified', audit
    item = entry(client, audit['target']['allocationId'])
    assert item['state'] == 'owned' and item['requestedBytes'] == count
    page = audit['report']['evidence']['pageSize']
    assert item['byteCount'] == ((count + page - 1) // page) * page
    assert item['createdByInterventionId'] == audit['id'] and item['createdAt'] == audit['afterPoint']
    return item, frame, response


def successful(client, artifact):
    launch(client, artifact)
    before = client.observation
    registers = runtime.registers(client)
    maps = Path(f"/proc/{before['processInstanceId']}/maps").read_text()
    stack = runtime.process_stack(before['processInstanceId'], maps)
    item, saved, response = new_allocation(client, 4097)
    assert runtime.registers(client) == registers
    assert runtime.process_stack(item['processInstanceId'], maps) == stack
    for field in ('input', 'stdout', 'stderr', 'stack', 'location'):
        assert client.observation[field] == before[field], field
    assert runtime.memory(client, item['addressHex'], item['byteCount']) == bytes(item['byteCount'])
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readIntervention', 'interventionId': item['createdByInterventionId']})['intervention'] == response['result']['intervention']
    assert entry(client, item['id'])['releaseAllowed']

    # A passive byte edit must preserve ownership even though it creates a new
    # stop and branch. Released bytes need not remain zero.
    _, write, _ = client.mutation({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': item['addressHex'], 'expectedBytesHex': '00000000', 'replacementBytesHex': '12345678'})
    assert runtime.memory(client, item['addressHex'], 4) == bytes.fromhex('12345678')
    assert entry(client, item['id'])['releaseAllowed']
    rax = next(value for value in registers if value['name'] == 'rax')
    value = f"0x{int(rax['valueHex'], 16):016x}"
    _, register, _ = client.mutation({'kind': 'writeRegister', 'profile': 'native-x86_64-gpr-v1',
        'register': 'rax', 'expectedValueHex': value, 'replacementValueHex': value})
    assert entry(client, item['id'])['releaseAllowed']
    snapshot = client.good({'kind': 'inspectScalarStorage', 'locator': 'frame:0:counter'})['snapshot']
    _, scalar, _ = client.mutation({'kind': 'writeScalarStorage', 'profile': 'native-dwarf-scalar-v1',
        'snapshotId': snapshot['id'], 'value': {'kind': 'integer', 'decimal': '9', 'bits': 32, 'signed': False}})
    assert entry(client, item['id'])['releaseAllowed']
    other, _, _ = new_allocation(client, 1)
    assert entry(client, item['id'])['releaseAllowed']
    assert entries(client)['totalBytes'] == item['byteCount'] + other['byteCount']
    freed, freed_response, _ = client.mutation(release(item['id']))
    released = entry(client, item['id'])
    assert released['state'] == 'released' and released['releasedByInterventionId'] == freed_response['result']['intervention']['id']
    assert entries(client)['totalBytes'] == other['byteCount'] and entry(client, other['id'])['releaseAllowed']
    assert runtime.memory(client, other['addressHex'], other['byteCount']) == bytes(other['byteCount'])
    client.reject(client.frame(release(item['id'])), ('STALE_CONTEXT',))
    client.send(saved); assert client.recv() == response
    client.reject({**saved, 'command': allocate(4098)}, ('INVALID_REQUEST',))
    assert entry(client, item['id']) == released
    client.send(freed); assert client.recv() == freed_response
    assert client.good({'kind': 'listMemoryInterventions', 'start': 0, 'count': 128})['items'] == [write['result']['intervention'], scalar['result']['intervention']]
    assert client.good({'kind': 'listRegisterInterventions', 'start': 0, 'count': 128})['items'] == [register['result']['intervention']]
    assert len(runtime.ledger(client)['items']) == 6
    client.mutation(release(other['id']))
    assert entries(client)['totalBytes'] == 0
    assert Path(f"/proc/{item['processInstanceId']}/maps").read_text() == maps
    client.execute({'kind': 'stop'})
    assert entry(client, item['id'])['state'] == 'released'
    client.send(saved); assert client.recv() == response
    return saved


def validation(client, artifact):
    launch(client, artifact)
    before = client.checkpoint()
    for count in (0, -1, 65537, 1.5, True, '1', None):
        client.reject(client.frame(allocate(count)), valid=False)
    for patch in ({'addressHex': '0x1000'}, {'permissions': 'rwx'}, {'flags': 0x22}, {'profile': 'auto'}):
        client.reject(client.frame({**allocate(), **patch}), valid=False)
    missing = client.frame(allocate()); del missing['expectedStop']
    client.reject(missing, valid=False)
    no_session = client.frame(allocate()); no_session['session'] = None
    client.reject(no_session, ('STALE_CONTEXT',))
    no_session = client.frame({'kind': 'listRuntimeAllocations', 'start': 0, 'count': 64}); no_session['session'] = None
    client.reject(no_session, ('STALE_CONTEXT',))
    client.reject(client.frame(release('allocation-missing')), ('STALE_CONTEXT',))
    client.reject(client.frame({'kind': 'readRuntimeAllocation', 'allocationId': 'allocation-missing'}), ('HISTORY_EVICTED',))
    assert entries(client)['total'] == 0 and client.checkpoint() == before
    item, _, _ = new_allocation(client)
    for patch in ({'addressHex': item['addressHex']}, {'byteCount': item['byteCount']}, {'profile': 'auto'}):
        client.reject(client.frame({**release(item['id']), **patch}), valid=False)
    stale = client.frame(release(item['id'])); stale['expectedStop'] = before['observation']['stop']
    client.reject(stale, ('STALE_CONTEXT',))
    assert entry(client, item['id'])['releaseAllowed']
    client.execute({'kind': 'stop'})
    assert entry(client, item['id'])['state'] == 'process-ended' and entries(client)['totalBytes'] == 0
    launch(client, artifact, profile='native')
    client.reject(client.frame(allocate()), ('UNSUPPORTED',))
    assert entries(client)['total'] == 0
    client.execute({'kind': 'stop'})


def real_aba(client, artifact):
    launch(client, artifact, mode='a')
    item, saved, response = new_allocation(client, 8192)
    initial = runtime.memory(client, item['addressHex'], item['byteCount'])
    client.good({'kind': 'appendInput', 'id': 'aba-address', 'text': f"{item['addressHex']} {item['byteCount']}\n"})
    assert entry(client, item['id'])['releaseAllowed']
    at_after(client)
    unknown = entry(client, item['id'])
    assert unknown['state'] == 'ownership-unknown' and unknown['invalidatedByRequestId']
    # Both allocations contain identical zeros at the same virtual address;
    # the old release must fail because provenance was lost, not byte mismatch.
    assert runtime.memory(client, item['addressHex'], item['byteCount']) == initial
    client.reject(client.frame(release(item['id'])), ('STALE_CONTEXT',))
    assert runtime.memory(client, item['addressHex'], item['byteCount']) == initial
    client.mutation({'kind': 'writeMemory', 'profile': 'native-private-memory-v1',
        'addressHex': item['addressHex'], 'expectedBytesHex': '00', 'replacementBytesHex': '00'})
    assert entry(client, item['id']) == unknown
    client.good({'kind': 'readHistory', 'point': item['createdAt']})
    client.send(saved); assert client.recv() == response
    assert entry(client, item['id']) == unknown and entries(client)['totalBytes'] == item['byteCount']
    client.execute({'kind': 'continue'})
    assert client.checkpoint()['state']['exit']['code'] == 0
    assert entry(client, item['id'])['state'] == 'process-ended' and entries(client)['totalBytes'] == 0


def input_isolation(client, artifact):
    launch(client, artifact, mode='i')
    pid = client.observation['processInstanceId']
    descriptor = os.open(f'/proc/{pid}/fd/0', os.O_RDONLY | os.O_NONBLOCK)
    try:
        capacity = fcntl.fcntl(descriptor, fcntl.F_SETPIPE_SZ, 4096)
        chunk = {'kind': 'appendInput', 'id': 'retained-final-chunk', 'text': 'q' * (2 * capacity)}
        assert client.good(chunk)['input']['deliveredBytes'] == capacity
        closed = client.good({'kind': 'closeInput'})['input']
        assert closed['eof'] == 'requested' and closed['status'] == 'reading'
        assert os.read(descriptor, capacity) == b'q' * capacity
        item, _, _ = new_allocation(client)
        client.mutation(release(item['id']))
        count = array.array('i', [0]); fcntl.ioctl(descriptor, termios.FIONREAD, count, True)
        assert count[0] == 0, 'allocation helper exposed queued input'
        try:
            value = os.read(descriptor, 1)
        except BlockingIOError:
            pass
        else:
            raise AssertionError(('allocation helper delivered bytes or EOF', value))
        assert client.observation['input'] == closed and client.good(chunk)['input'] == closed
        at_after(client)
        total = next(value for value in client.observation['stack'][0]['variables'] if value['name'] == 'total')
        assert total['value']['value']['decimal'] == str(capacity)
        assert client.observation['input']['status'] == 'complete'
        assert os.read(descriptor, 1) == b''
        client.execute({'kind': 'continue'})
        assert client.checkpoint()['state']['exit']['code'] == 0
    finally:
        os.close(descriptor)


def revocation(client, artifact):
    commands = [{'kind': 'pause'}, {'kind': 'step', 'stepKind': 'instruction'},
        {'kind': 'traceInstructions', 'count': 1, 'registers': ['rip'], 'memoryRanges': []},
        {'kind': 'seekRecording', 'instruction': '0'}, {'kind': 'reverseInstruction'},
        {'kind': 'setBreakpoints', 'documentId': 'runtime-helper', 'revisionId': 'runtime-helper-1', 'breakpoints': []},
        {'kind': 'writeVariable', 'locator': 'frame:0:counter',
         'expected': {'availability': 'available', 'value': {'kind': 'integer', 'decimal': '7', 'bits': 32, 'signed': False}},
         'value': {'kind': 'integer', 'decimal': '8', 'bits': 32, 'signed': False}}]
    for command in commands:
        launch(client, artifact)
        item, saved, response = new_allocation(client)
        frame = client.frame(command)
        client.send(frame)
        if command['kind'] == 'setBreakpoints':
            assert client.recv()['ok']
        elif command['kind'] == 'writeVariable':
            rejected = client.recv()
            assert rejected['error']['code'] == 'UNSUPPORTED', rejected
        else:
            client.finish([frame])
        unknown = entry(client, item['id'])
        assert unknown['state'] == 'ownership-unknown' and unknown['invalidatedByRequestId'] == frame['requestId'], (command, unknown)
        client.reject(client.frame(release(item['id'])), ('STALE_CONTEXT',))
        client.send(saved); assert client.recv() == response
        assert entry(client, item['id']) == unknown
        client.execute({'kind': 'stop'})
    launch(client, artifact)
    item, _, _ = new_allocation(client)
    frame, _, _ = client.runtime(artifact)
    assert entry(client, item['id'])['invalidatedByRequestId'] == frame['requestId']
    client.execute({'kind': 'stop'})


def denied_syscalls(client, artifact):
    for mode in ('g', 'm', 'u'):
        launch(client, artifact, mode=mode)
        before = client.observation
        owned = None
        if mode == 'u':
            owned, _, _ = new_allocation(client)
        frame, response, _ = client.mutation(release(owned['id']) if owned else allocate())
        audit = response['result']['intervention']
        assert audit['report']['outcome'] == 'failed' and audit['contextStatus'] == 'failed'
        assert client.checkpoint()['state']['phase'] == 'failed'
        assert entries(client)['totalBytes'] == 0
        if owned:
            assert entry(client, owned['id'])['state'] == 'process-ended'
        else:
            assert entries(client)['items'] == []
        require_inferior_exited(before['processInstanceId'])
        client.send(frame); assert client.recv() == response
    # Retained RW storage never needs mprotect or executable permissions.
    launch(client, artifact, mode='p')
    owned, _, _ = new_allocation(client)
    client.mutation(release(owned['id']))
    client.execute({'kind': 'stop'})


def debugger_death(client, artifact):
    launch(client, artifact)
    item, original, response = new_allocation(client)
    client.kill_gdb()
    request = client.frame({'kind': 'readMemory', 'addressHex': item['addressHex'], 'byteCount': 1})
    client.send(request)
    failure = client.recv()
    assert not failure['ok'] and failure['requestId'] == request['requestId']
    failed = client.recv()
    assert failed['payload']['kind'] == 'state' and failed['payload']['state']['phase'] == 'failed'
    assert entry(client, item['id'])['state'] == 'process-ended'
    assert entries(client)['totalBytes'] == 0
    client.send(original); assert client.recv() == response
    assert entry(client, item['id'])['state'] == 'process-ended'
    require_inferior_exited(item['processInstanceId'])


def quotas(client, artifact):
    launch(client, artifact)
    small = [new_allocation(client, 1)[0] for _ in range(64)]
    assert entries(client)['total'] == 64 and entries(client)['totalBytes'] == sum(item['byteCount'] for item in small)
    client.reject(client.frame(allocate()), ('LIMIT_EXCEEDED',))
    client.mutation(release(small[0]['id']))
    client.reject(client.frame(allocate()), ('LIMIT_EXCEEDED',))
    assert entries(client, 63, 1)['items'][0]['id'] == small[-1]['id']
    assert entries(client, 64, 1)['items'] == [] and not entries(client, 9007199254740991, 1)['hasMore']
    client.execute({'kind': 'stop'})
    assert entries(client)['totalBytes'] == 0
    launch(client, artifact)
    large = [new_allocation(client, 65536)[0] for _ in range(16)]
    assert entries(client)['totalBytes'] == 1048576
    client.reject(client.frame(allocate()), ('LIMIT_EXCEEDED',))
    client.mutation(release(large[0]['id']))
    new_allocation(client, 65536)
    client.execute({'kind': 'pause'})
    assert all(item['state'] in ('ownership-unknown', 'released') for item in entries(client)['items'])
    assert entries(client)['totalBytes'] == 1048576
    client.reject(client.frame(allocate()), ('LIMIT_EXCEEDED',))
    client.execute({'kind': 'stop'})


def fault_scenarios(executable, real_gdb, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    runtime.proxy(tools / 'gdb', real_gdb)
    text = (tools / 'gdb').read_text().replace('_phantom_runtime_helper_execute', '_phantom_runtime_allocation_execute')
    text = text.replace('PHANTOM_RUNTIME_HELPER_RESULT_V1:', 'PHANTOM_RUNTIME_ALLOCATION_RESULT_V1:')
    (tools / 'gdb').write_text(text)
    client = Client(executable, workspace, {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ.get('PATH', '')})
    try:
        artifact = runtime.build(client, source=SOURCE)
        for action, mode in [('allocate', name) for name in ('prepare-cancel', 'ack-error', 'malformed-proof',
                'refresh-death', 'signal-during', 'cancel', 'timeout')] + [
                ('release', name) for name in ('prepare-cancel', 'ack-error', 'refresh-death', 'cancel')]:
            for name in ('arm', 'fault', 'release', 'commands', 'executions'):
                (tools / name).unlink(missing_ok=True)
            (tools / 'mode').write_text(mode)
            launch(client, artifact)
            original = None
            if action == 'release':
                original, _, _ = new_allocation(client)
            before = client.observation
            registers = runtime.registers(client)
            marker = Path(f"/proc/{before['processInstanceId']}/cwd").resolve() / 'runtime-signal-handler-ran'
            marker.unlink(missing_ok=True)
            request = client.frame(release(original['id']) if original else allocate())
            (tools / 'arm').touch()
            client.send(request)
            runtime.wait_fault(tools / 'fault')
            control = None
            started = time.monotonic()
            if mode in ('cancel', 'prepare-cancel'):
                control = client.frame({'kind': 'cancel', 'targetRequestId': request['requestId']})
                client.send(control)
                if mode == 'prepare-cancel':
                    time.sleep(.1)
                    (tools / 'release').touch()
            if mode == 'prepare-cancel':
                response = client.recv()
                assert response['requestId'] == request['requestId'] and response['error']['code'] == 'CANCELLED'
                accepted, completed = client.recv(), client.recv()
                assert accepted['ok'] and accepted['requestId'] == control['requestId']
                assert completed['payload']['requestId'] == control['requestId'] and completed['payload']['outcome'] == 'completed'
                assert client.checkpoint()['observation'] == before and runtime.registers(client) == registers
                assert not (tools / 'executions').exists()
                if original:
                    assert entry(client, original['id'])['releaseAllowed']
                else:
                    assert entries(client)['total'] == 0
                (tools / 'arm').unlink()
                if original:
                    client.mutation(release(original['id']))
                else:
                    new_allocation(client)
                client.execute({'kind': 'stop'})
                continue
            _, response, _ = client.receive_mutation(request)
            audit = response['result']['intervention']
            assert audit['contextStatus'] == 'failed' and audit['report']['cancelled'] == (mode == 'cancel')
            assert (tools / 'fault').read_text() == mode
            if control:
                accepted, completed = client.recv(), client.recv()
                assert accepted['ok'] and accepted['requestId'] == control['requestId']
                assert completed['payload']['requestId'] == control['requestId'] and completed['payload']['outcome'] == 'completed'
                assert time.monotonic() - started < 4
            if mode == 'timeout':
                assert audit['report']['error']['code'] == 'TIMEOUT'
                assert 5 < time.monotonic() - started < 15
            assert client.checkpoint()['state']['phase'] == 'failed'
            assert client.checkpoint()['observation'] is None
            assert entries(client)['totalBytes'] == 0
            if original:
                expected_state = 'released' if mode == 'refresh-death' else 'process-ended'
                assert entry(client, original['id'])['state'] == expected_state
            elif mode == 'refresh-death':
                item = entry(client, audit['target']['allocationId'])
                assert item['state'] == 'process-ended' and item['createdAt'] is None
            else:
                assert entries(client)['items'] == []
            require_inferior_exited(before['processInstanceId'])
            assert not marker.exists(), 'signal handler ran during allocation syscall'
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
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-allocation-') as directory:
        client = Client(executable, Path(directory), dict(os.environ))
        try:
            native = runtime.build(client, runtime=False, source=SOURCE)
            launch(client, native)
            client.reject(client.frame(allocate()), ('UNSUPPORTED',))
            assert entries(client)['total'] == 0
            client.execute({'kind': 'stop'})
            artifact = runtime.build(client, source=SOURCE)
            old = successful(client, artifact)
            validation(client, artifact)
            client.reject(old, ('STALE_CONTEXT',))
            real_aba(client, artifact)
            input_isolation(client, artifact)
            revocation(client, artifact)
            denied_syscalls(client, artifact)
            debugger_death(client, artifact)
            quotas(client, artifact)
        finally:
            client.close()
    with tempfile.TemporaryDirectory(prefix='phantom-runtime-allocation-faults-') as directory:
        fault_scenarios(executable, str(Path(shutil.which('gdb')).resolve()), Path(directory))
    print('runtime allocation: retained bytes, release authority, passive edits, real mmap ABA, quotas and immutable retry passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
