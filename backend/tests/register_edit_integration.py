"""Checked native GPR edits: actual execution, shared audit quota and I/O isolation."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile

import memory_edit_integration as memory_edits
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
PROFILE = 'native-x86_64-gpr-v1'
REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', *[f'r{i}' for i in range(8, 16)]]
SOURCE = r'''#include <unistd.h>
#include <pthread.h>
#include <atomic>
static std::atomic<bool> threadReady{false};
static void* worker(void*) {
  threadReady.store(true);
  for (;;) pause();
  return nullptr;
}
int main(int argc, char** argv) {
  volatile unsigned int counter = 7;
  volatile unsigned long long result = 0;
  int typed = 3;
  if (argc > 1 && argv[1][0] == 'w') {
    char input = 0;
    if (read(0, &input, 1) != 1) return 90;
  }
  pthread_t thread{};
  if (argc > 1 && argv[1][0] == 't') {
    if (pthread_create(&thread, nullptr, worker, nullptr)) return 91;
    while (!threadReady.load()) {}
  }
  if (write(1, "kept\n", 5) != 5) return 92;
  asm volatile("movq $7, %%rax" : : : "rax", "memory");
  asm volatile("movq %%rax, %0" : "=m"(result) : : "memory"); // EDIT
  counter = counter + 1;
  if (write(1, "done\n", 5) != 5) return 93;
  asm volatile("nop" : : : "memory"); // AFTER
  return result == 42 && counter == 44 ? 0 : 94;
}
'''


class Client(memory_edits.Client):
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
        if command['kind'] in ('writeRegister', 'inspectScalarStorage', 'writeScalarStorageBatch') and self.observation is not None:
            frame['expectedStop'] = self.observation['stop']
        return frame

    def edit_register(self, command):
        frame = self.frame(command)
        response = self.send(frame)
        assert response['ok'] and response['requestId'] == frame['requestId'], response
        result = response['result']
        assert result['kind'] == 'registerIntervention', result
        audit = result['intervention']; report = audit['report']
        assert audit['requestId'] == frame['requestId'] and audit['profile'] == PROFILE
        assert audit['target'] == {'architecture': 'x86_64', 'register': command['register'],
            'bits': 64, 'threadId': self.observation['threadId'], 'frameLevel': 0}, audit
        assert report['register'] == command['register'] and report['bits'] == 64
        assert report['expectedValueHex'] == command['expectedValueHex']
        assert report['replacementValueHex'] == command['replacementValueHex']
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        events = []
        if report['writeAttempted']:
            events = [self.recv() for _ in range(3)]
            assert [e['payload']['kind'] for e in events] == ['branchCreated', 'observation', 'state'], events
            assert all(e.get('causedByRequestId') == frame['requestId'] for e in events), events
            assert events[0]['payload']['parent'] == audit['beforePoint']
            assert events[0]['payload']['branchId'] == audit['branchId']
            self.observation = events[1]['payload']['observation']
            assert self.observation['reason'] == 'mutation'
            assert self.observation['point'] == audit['afterPoint']
            assert self.observation['stop'] == audit['afterStop']
            assert events[2]['payload']['state']['live'] == {'point': audit['afterPoint'], 'stop': audit['afterStop']}
            assert result['throughSequence'] == events[-1]['sequence']
        else:
            assert audit['branchId'] is None and audit['afterPoint'] is None and audit['afterStop'] is None
            assert audit['contextStatus'] == 'unchanged'
        return frame, response, events


def canonical(value):
    return f'0x{value:016x}'


def command(register, expected, replacement):
    return {'kind': 'writeRegister', 'profile': PROFILE, 'register': register,
        'expectedValueHex': canonical(expected), 'replacementValueHex': canonical(replacement)}


def build(client):
    result = client.good({'kind': 'build', 'source': {'id': 'register-edit-source', 'documents': [{
        'documentId': 'register-edit', 'revisionId': 'register-edit-1', 'path': 'register-edit.cpp',
        'text': SOURCE, 'sha256': hashlib.sha256(SOURCE.encode()).hexdigest()}]},
        'configuration': {'revisionId': 'register-edit-config', 'compiler': 'clang++',
            'flags': ['-std=c++20', '-g', '-O0', '-pthread'], 'outputDirectory': '.phantom/build',
            'addressProfile': 'fixed-executable'}, 'architecture': 'x86_64'})
    assert result['success'], result
    return result['artifact']


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if text.endswith('// ' + marker))
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line - 1])
    return {'documentId': 'register-edit', 'revisionId': 'register-edit-1',
        'range': {'start': offset, 'end': offset},
        'start': {'line': line, 'column': 1}, 'end': {'line': line, 'column': 1}}


def at_edit(client):
    result = client.good({'kind': 'setBreakpoints', 'documentId': 'register-edit', 'revisionId': 'register-edit-1',
        'breakpoints': [{'id': marker, 'range': location(marker), 'enabled': True} for marker in ('EDIT', 'AFTER')]})
    assert all(bp['verified'] for bp in result['breakpoints']), result
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('EDIT')['start']['line']
    assert registers(client, ['rax']) == {'rax': 7}
    return client.observation


def registers(client, names):
    result = client.good({'kind': 'readRegisters', 'registers': names})
    assert [item['name'] for item in result['registers']] == names
    assert all(item['available'] for item in result['registers']), result
    return {item['name']: int(item['valueHex'], 16) for item in result['registers']}


def audits(client, start=0, count=128):
    result = client.good({'kind': 'listRegisterInterventions', 'start': start, 'count': count})
    assert result['kind'] == 'registerInterventions' and result['start'] == start, result
    return result


def value(client, name):
    return int(memory_edits.variable(client, name)['value']['value']['decimal'])


def verify_native(client, artifact):
    client.launch_edit(artifact)
    entry = client.observation
    before = at_edit(client)
    stable = client.good({'kind': 'getState'})
    address = int(memory_edits.variable(client, 'counter')['addressHex'], 16)
    capture = client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': hex(address), 'byteCount': 4}]})['capture']
    output = memory_edits.journal(client, before['point'])
    baseline = registers(client, [*REGISTERS, 'rip', 'rsp', 'rbp', 'eflags'])
    valid = command('rax', 7, 42)
    # All shapes that might accidentally become GDB expressions are rejected.
    for patch in ({'register': name} for name in ('eax', 'ax', 'al', 'ah', 'rsp', 'rbp', 'rip', 'eflags',
            'xmm0', 'orig_rax', 'fs_base', '$rax', 'RAX', 'rax\n-exec-continue', '')):
        client.bad({**valid, **patch})
    for patch in ({'profile': 'auto'}, {'expectedValueHex': '0x7'}, {'replacementValueHex': '0X000000000000002a'},
            {'replacementValueHex': '0x000000000000002A'}, {'replacementValueHex': '0x10000000000000000'},
            {'replacementValueHex': '000000000000002a'}, {'replacementValueHex': '-1'},
            {'replacementValueHex': 42}, {'replacementValueHex': '0x000000000000002a;continue'},
            {'threadId': '1'}, {'frameLevel': 1}, {'expression': '$rax = 42'}):
        client.bad({**valid, **patch})
    for field in ('profile', 'register', 'expectedValueHex', 'replacementValueHex'):
        invalid = valid.copy(); del invalid[field]
        client.bad(invalid)
    missing = client.frame(valid); del missing['expectedStop']
    memory_edits.reject_frame(client, missing, 'INVALID_REQUEST', valid=False)
    stale = client.frame(valid); stale['expectedStop'] = entry['stop']
    memory_edits.reject_frame(client, stale, 'STALE_CONTEXT')
    no_session = client.frame(valid); no_session['session'] = None
    memory_edits.reject_frame(client, no_session, 'STALE_CONTEXT')
    assert audits(client)['total'] == 0 and memory_edits.audits(client)['total'] == 0
    assert client.good({'kind': 'getState'}) == stable
    assert registers(client, list(baseline)) == baseline

    conflict_frame, conflict, _ = client.edit_register(command('rax', 8, 8))
    report = conflict['result']['intervention']['report']
    assert report['outcome'] == 'conflict' and report['beforeValueHex'] == canonical(7)
    assert report['beforeMatchesExpected'] is False and report['afterValueHex'] is None
    assert not report['writeAttempted'] and not report['writeAcknowledged']
    assert client.send(conflict_frame) == conflict
    noop_frame, noop, _ = client.edit_register(command('rax', 7, 7))
    assert noop['result']['intervention']['report']['outcome'] == 'unchanged'
    assert client.send(noop_frame) == noop
    assert client.good({'kind': 'getState'}) == stable

    successful_frame, successful, _ = client.edit_register(valid)
    audit = successful['result']['intervention']; report = audit['report']
    first = client.observation
    assert report['outcome'] == 'verified' and report['writeAcknowledged'] and report['debuggerAlive']
    assert report['beforeValueHex'] == canonical(7) and report['afterValueHex'] == canonical(42)
    assert report['beforeMatchesExpected'] and report['afterMatchesReplacement'] and not report['afterMatchesBefore']
    assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None
    assert first['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
    assert first['input'] == before['input'] and first['stdout'] == before['stdout'] and first['stderr'] == before['stderr']
    assert first['processInstanceId'] == before['processInstanceId']
    assert registers(client, list(baseline)) == {**baseline, 'rax': 42}
    assert client.send(successful_frame) == successful
    assert client.good({'kind': 'getState'})['throughSequence'] == successful['result']['throughSequence']
    memory_edits.reject_frame(client, {**successful_frame, 'command': command('rax', 7, 43)}, 'INVALID_REQUEST')
    memory_edits.reject_frame(client, {**successful_frame, 'command': {'kind': 'getState'}}, 'INVALID_REQUEST')
    assert audits(client)['total'] == 3 and memory_edits.audits(client)['total'] == 0
    assert audits(client, 1, 1)['items'] == [noop['result']['intervention']]
    assert audits(client, 1, 1)['hasMore']
    assert audits(client, 9007199254740991, 1)['items'] == []
    client.bad({'kind': 'readRegisterIntervention', 'interventionId': 'missing'}, ('HISTORY_EVICTED',))
    client.bad({'kind': 'readMemoryIntervention', 'interventionId': audit['id']}, ('HISTORY_EVICTED',))
    assert client.good({'kind': 'readRegisterIntervention', 'interventionId': audit['id']})['intervention'] == audit
    branch = client.good({'kind': 'listBranches'})
    assert branch['branches'][-1] == {'id': audit['branchId'], 'parent': before['point'], 'interventionId': audit['id']}
    assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
    assert client.good({'kind': 'readMemoryCapture', 'captureId': capture['id']})['capture'] == capture
    assert memory_edits.journal(client, before['point']) == output

    # Every supported register accepts all 64 bits. Restore after each edit so
    # the subsequent real execution keeps valid callee-saved state and pointers.
    for name in REGISTERS:
        previous = registers(client, [name])[name]
        replacement = 0xffffffffffffffff if previous != 0xffffffffffffffff else 0
        previous_regs = registers(client, list(baseline))
        _, changed, _ = client.edit_register(command(name, previous, replacement))
        assert changed['result']['intervention']['report']['afterValueHex'] == canonical(replacement)
        assert registers(client, list(baseline)) == {**previous_regs, name: replacement}
        _, restored, _ = client.edit_register(command(name, replacement, previous))
        assert restored['result']['intervention']['report']['outcome'] == 'verified'
        assert registers(client, list(baseline)) == previous_regs

    # Memory and register mutations share branch identity and request-ID ledger,
    # while their paginated public histories remain independently typed.
    register_tip = client.observation
    memory_frame, memory_response, _ = client.edit(memory_edits.write(address, memory_edits.number(7), memory_edits.number(43)))
    memory_audit = memory_response['result']['intervention']
    assert memory_audit['id'] != audit['id'] and memory_audit['beforePoint'] == register_tip['point']
    assert memory_edits.audits(client)['items'] == [memory_audit]
    assert audits(client)['total'] == 31
    combined = client.good({'kind': 'listInterventions', 'start': 0, 'count': 128})
    assert combined['kind'] == 'interventions' and combined['total'] == 32 and not combined['hasMore']
    assert combined['items'] == [*audits(client)['items'], memory_audit]
    assert client.good({'kind': 'listInterventions', 'start': 30, 'count': 1})['hasMore']
    assert client.good({'kind': 'listInterventions', 'start': 31, 'count': 1})['items'] == [memory_audit]
    assert client.good({'kind': 'listInterventions', 'start': 9007199254740991, 'count': 1})['items'] == []
    for item in (audit, memory_audit):
        queried = client.good({'kind': 'readIntervention', 'interventionId': item['id']})
        assert queried['kind'] == 'intervention' and queried['intervention'] == item
    client.bad({'kind': 'readIntervention', 'interventionId': 'missing'}, ('HISTORY_EVICTED',))
    assert client.good({'kind': 'listBranches'})['branches'][-1]['parent'] == register_tip['point']
    client.bad({'kind': 'readRegisterIntervention', 'interventionId': memory_audit['id']}, ('HISTORY_EVICTED',))
    memory_edits.reject_frame(client, {**memory_frame, 'command': valid}, 'INVALID_REQUEST')
    assert client.send(successful_frame) == successful
    assert registers(client, ['rax']) == {'rax': 42}
    assert client.good({'kind': 'readHistory', 'point': first['point']})['observation'] == first
    client.execute({'kind': 'continue'})
    assert client.observation['location']['start']['line'] == location('AFTER')['start']['line']
    assert value(client, 'result') == 42 and value(client, 'counter') == 44
    physical = memory_edits.journal(client, before['point'])
    assert physical['selectedThroughByte'] == 5 and physical['totalBytes'] == 10
    assert b''.join(base64.b64decode(segment['bytesBase64']) for segment in physical['segments']) == b'kept\ndone\n'
    client.execute({'kind': 'continue'})
    state = client.good({'kind': 'getState'})['state']
    assert state['phase'] == 'terminated' and state['exit']['code'] == 0, state
    assert client.send(successful_frame) == successful and client.send(memory_frame) == memory_response
    assert client.good({'kind': 'readRegisterIntervention', 'interventionId': audit['id']})['intervention'] == audit
    previous_session = client.session
    client.launch_edit(artifact)
    assert audits(client)['total'] == 0 and memory_edits.audits(client)['total'] == 0
    client.bad({'kind': 'readRegisterIntervention', 'interventionId': audit['id']}, ('HISTORY_EVICTED',))
    stale_audit = client.frame({'kind': 'readRegisterIntervention', 'interventionId': audit['id']})
    stale_audit['session'] = previous_session
    memory_edits.reject_frame(client, stale_audit, 'STALE_CONTEXT')
    memory_edits.reject_frame(client, successful_frame, 'STALE_CONTEXT')
    client.execute({'kind': 'stop'})


def verify_limits(client, artifact):
    client.launch_edit(artifact)
    at_edit(client)
    address = int(memory_edits.variable(client, 'counter')['addressHex'], 16)
    saved_register = saved_memory = None
    for index in range(128):
        if index % 2:
            frame, response, _ = client.edit_register(command('rax', 7, 7))
            saved_register = saved_register or (frame, response)
        else:
            frame, response, _ = client.edit(memory_edits.write(address, memory_edits.number(7), memory_edits.number(7)))
            saved_memory = saved_memory or (frame, response)
    stable = client.good({'kind': 'getState'})
    assert audits(client)['total'] == 64 and memory_edits.audits(client)['total'] == 64
    combined = client.good({'kind': 'listInterventions', 'start': 0, 'count': 128})
    assert combined['total'] == 128 and len(combined['items']) == 128 and not combined['hasMore']
    assert len({item['id'] for item in combined['items']}) == 128
    assert combined['items'][0::2] == memory_edits.audits(client)['items']
    assert combined['items'][1::2] == audits(client)['items']
    for listing in (audits(client), memory_edits.audits(client)):
        assert not listing['hasMore'] and len(listing['items']) == 64
    assert audits(client, 63, 1)['items'] == audits(client)['items'][-1:]
    assert not audits(client, 63, 1)['hasMore'] and audits(client, 64, 1)['items'] == []
    client.bad(command('rax', 7, 42), ('LIMIT_EXCEEDED',))
    client.bad(memory_edits.write(address, memory_edits.number(7), memory_edits.number(43)), ('LIMIT_EXCEEDED',))
    assert client.send(saved_register[0]) == saved_register[1]
    assert client.send(saved_memory[0]) == saved_memory[1]
    assert client.good({'kind': 'getState'}) == stable
    assert registers(client, ['rax']) == {'rax': 7} and value(client, 'counter') == 7
    assert len(client.good({'kind': 'listBranches'})['branches']) == 1
    client.execute({'kind': 'stop'})


def verify_input_is_not_fed(client, artifact):
    client.launch_edit(artifact, text='q' * 131072)
    before = at_edit(client)
    delivered = before['input']['deliveredBytes']
    assert 4096 <= delivered < 131072, before['input']
    descriptor = os.open(f"/proc/{before['processInstanceId']}/fd/0", os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert os.read(descriptor, 4096) == b'q' * 4096
        _, response, _ = client.edit_register(command('rax', 7, 42))
    finally:
        os.close(descriptor)
    assert response['result']['intervention']['report']['outcome'] == 'verified'
    assert client.observation['input'] == before['input']
    assert client.observation['stdout'] == before['stdout']
    client.execute({'kind': 'stop'})


def verify_mixed_reservations(client, artifact):
    # A typed batch reserves 64 KiB, versus 32 KiB for a GPR edit. The shared
    # byte budget must refuse the next register entry before the count limit.
    client.launch_edit(artifact)
    at_edit(client)
    snapshot = client.good({'kind': 'inspectScalarStorage', 'locator': 'frame:0:typed'})['snapshot']
    assert snapshot['storage']['value']['decimal'] == '3', snapshot
    typed = {'kind': 'writeScalarStorageBatch', 'profile': 'native-dwarf-scalar-batch-v1',
        'edits': [{'profile': snapshot['profile'], 'snapshotId': snapshot['id'], 'value': snapshot['storage']['value']}]}
    first = None
    for _ in range(63):
        frame = client.frame(typed); frame['expectedStop'] = client.observation['stop']
        response = client.send(frame)
        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        assert response['result']['intervention']['report']['outcome'] == 'unchanged', response
        first = first or (frame, response)
    saved, result, _ = client.edit_register(command('rax', 7, 7))
    # Exactly one 32 KiB slot remains: another 64 KiB batch must already fail.
    frame = client.frame(typed); frame['expectedStop'] = client.observation['stop']
    memory_edits.reject_frame(client, frame, 'LIMIT_EXCEEDED')
    client.edit_register(command('rax', 7, 7))
    assert client.good({'kind': 'listInterventions', 'start': 0, 'count': 128})['total'] == 65
    assert audits(client)['total'] == 2 and memory_edits.audits(client)['total'] == 63
    client.bad(command('rax', 7, 42), ('LIMIT_EXCEEDED',))
    assert client.send(first[0]) == first[1] and client.send(saved) == result
    assert registers(client, ['rax']) == {'rax': 7}
    assert len(client.good({'kind': 'listBranches'})['branches']) == 1
    client.execute({'kind': 'stop'})


def verify_unsupported(client, artifact):
    client.launch_edit(artifact, argv=('t',))
    before = at_edit(client)
    client.bad(command('rax', 7, 42), ('UNSUPPORTED',))
    assert audits(client)['total'] == 0 and registers(client, ['rax']) == {'rax': 7}
    assert client.good({'kind': 'getState'})['observation'] == before
    client.execute({'kind': 'stop'})

    client.launch_edit(artifact, argv=('w',))
    events = client.execute({'kind': 'continue'})
    assert events[-1]['payload']['outcome'] == 'waiting', events
    waiting = client.good({'kind': 'getState'})
    client.bad(command('rax', 7, 42), ('STALE_CONTEXT',))
    assert audits(client)['total'] == 0 and client.good({'kind': 'getState'}) == waiting
    client.execute({'kind': 'stop'})

    client.launch_edit(artifact, recording=True)
    recording = client.good({'kind': 'readRecording'})
    stable = client.good({'kind': 'getState'})
    client.bad(command('rax', 7, 42), ('UNSUPPORTED',))
    assert audits(client)['total'] == 0
    assert client.good({'kind': 'getState'}) == stable and client.good({'kind': 'readRecording'}) == recording
    client.execute({'kind': 'stop'})


def main():
    if len(sys.argv) != 2:
        return 2
    if not sys.platform.startswith('linux') or not shutil.which('gdb') or not shutil.which('clang++'):
        return 77
    with tempfile.TemporaryDirectory(prefix='phantom-register-edits-') as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            for query in ({'kind': 'listRegisterInterventions', 'start': 0, 'count': 1},
                    {'kind': 'readRegisterIntervention', 'interventionId': 'missing'},
                    {'kind': 'listInterventions', 'start': 0, 'count': 1},
                    {'kind': 'readIntervention', 'interventionId': 'missing'}):
                client.bad(query, ('STALE_CONTEXT',))
            artifact = build(client)
            verify_native(client, artifact)
            verify_limits(client, artifact)
            verify_mixed_reservations(client, artifact)
            verify_input_is_not_fed(client, artifact)
            verify_unsupported(client, artifact)
        finally:
            client.close()
    print('register edits: all GPRs, actual execution, shared branches/quota, immutable audits, idempotency, guards and input isolation passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
