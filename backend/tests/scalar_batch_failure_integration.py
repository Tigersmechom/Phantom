"""Typed batch provenance tracks each actual phase through real GDB faults."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import float_storage_integration as floats
import memory_batch_failure_integration as faults
import scalar_batch_integration as batches
import scalar_storage_integration as scalars
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
    faults.proxy(path, real_gdb, mode)
    if mode not in ('initial-metadata', 'metadata-drift'):
        return
    script = path.read_text()
    hook = r'''
        if line.startswith(b'~') and (root / 'arm').exists() and not (root / 'fault').exists():
            text = json.loads(line[1:])
            prefix = 'PHANTOM_SCALAR_STORAGE_V1:'
            if text.startswith(prefix):
                target = json.loads(text[len(prefix):])
                phase = MODE == 'initial-metadata' and completed == 0 or MODE == 'metadata-drift' and completed == 1
                if phase and target['locator'] == 'frame:0:doubleValue':
                    target['addressHex'] = hex(int(target['addressHex'], 16) + 1)
                    text = prefix + json.dumps(target, separators=(',', ':')) + '\n'
                    line = b'~' + json.dumps(text).encode() + b'\n'
                    (root / 'fault').write_text(MODE)
'''
    # Add a response-only metadata perturbation; inferior bytes remain real.
    anchor = '    for line in child.stdout:\n'
    assert script.count(anchor) == 1
    path.write_text(script.replace(anchor, anchor + hook))


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
        client.launch_scalar(artifact)
        before = batches.at_ready(client)
        pid = before['processInstanceId']
        snapshots = [batches.inspect(client, 'scalar'),
                     batches.inspect(client, 'doubleValue', profile=floats.PROFILE),
                     batches.inspect(client, 'flag')]
        original = [scalars.integer(7), floats.floating('4004000000000000'), scalars.boolean(False)]
        desired = [scalars.integer(42), floats.floating('7ff0000000000123'), scalars.boolean(True)]
        assert [snapshot['storage']['value'] for snapshot in snapshots] == original
        addresses = [int(snapshot['target']['addressHex'], 16) for snapshot in snapshots]
        (tools / 'ranges.json').write_text(json.dumps({'pid': pid, 'first': addresses[0], 'second': addresses[1]}))
        frame = client.frame(batches.command([batches.item(snapshot, value) for snapshot, value in zip(snapshots, desired)]))
        stable = client.good({'kind': 'getState'})
        (tools / 'arm').touch()
        response = client.send(frame)
        if mode == 'initial-metadata':
            assert not response['ok'] and response['error']['code'] == 'STALE_CONTEXT', response
            assert scalars.audits(client)['total'] == 0 and not (tools / 'writes').exists()
            assert client.good({'kind': 'getState'}) == stable
            for snapshot in snapshots:
                assert scalars.memory(client, snapshot['target']['addressHex'], snapshot['target']['scalar']['byteSize']).hex() == snapshot['storage']['bytesHex']
            assert (tools / 'fault').read_text() == mode
            client.execute({'kind': 'stop'})
            return

        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        audit = response['result']['intervention']; report = audit['report']; items = report['items']; origins = audit['scalars']
        assert audit['profile'] == batches.PROFILE and audit['requestId'] == frame['requestId']
        assert report['preflightPassed'] and report['writeAttempted'] and report['byteCount'] == 13
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        for index, (origin, snapshot, value) in enumerate(zip(origins, snapshots, desired)):
            assert origin['index'] == index and origin['profile'] == snapshot['profile']
            assert origin['snapshotId'] == snapshot['id'] and origin['target'] == snapshot['target']
            assert origin['locator'] == snapshot['target']['locator'] and origin['requestedValue'] == value
            assert origin['preflightValue'] == original[index]
            assert items[index]['preflight']['matchesExpected'] is True
        assert origins[0]['beforeValue'] == original[0] and origins[0]['afterValue'] == desired[0]

        failed = mode == 'write-death'
        final_failure = mode in ('final-drift', 'final-readback')
        expected_writes = 3 if final_failure else 1 if mode in ('late-conflict', 'metadata-drift') else 2
        events = [client.recv() for _ in range(2 if failed else 3)]
        assert [event['payload']['kind'] for event in events] == (
            ['branchCreated', 'state'] if failed else ['branchCreated', 'observation', 'state']), events
        assert all(event.get('causedByRequestId') == frame['requestId'] for event in events)
        assert response['result']['throughSequence'] == events[-1]['sequence']
        assert events[0]['payload']['parent'] == before['point']
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed' and audit['refreshError']
            assert audit['afterPoint'] is None and audit['afterStop'] is None
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None
            assert checkpoint['observation'] is None
            assert all(origin['finalValue'] is None for origin in origins)
            assert all(part['final'] is None for part in items)
            require_inferior_exited(pid)
        else:
            client.observation = events[1]['payload']['observation']
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None
            assert checkpoint['observation'] == client.observation
            assert client.observation['stop']['stateRevision'] == before['stop']['stateRevision'] + 1
            first_bits = bytes.fromhex('cafebabe') if mode == 'final-drift' else (42).to_bytes(4, 'little')
            second_bits = bytes.fromhex(
                'deadbeef00000440' if mode == 'late-conflict' else
                '0000000000000440' if mode == 'metadata-drift' else
                '2301000000000440' if mode == 'partial' else '230100000000f07f')
            third_bits = bytes([final_failure])
            observed = [first_bits, second_bits, third_bits]
            actual_values = [scalars.integer(int.from_bytes(first_bits, 'little', signed=True)),
                floats.floating(second_bits[::-1].hex()), scalars.boolean(final_failure)]
            for index, (snapshot, raw, value) in enumerate(zip(snapshots, observed, actual_values)):
                assert scalars.memory(client, snapshot['target']['addressHex'], len(raw)) == raw
                if mode == 'final-readback' and index == 0:
                    assert origins[index]['finalValue'] is None and items[index]['final']['error']
                else:
                    assert origins[index]['finalValue'] == value, origins[index]
                    assert items[index]['final']['bytesHex'] == raw.hex()

        assert report['outcome'] == ('verification-failed' if final_failure else 'interrupted'), report
        assert report['failureIndex'] == (0 if final_failure else 1), report
        if final_failure:
            assert all(part['execution']['outcome'] == 'verified' for part in items)
            assert [origin['beforeValue'] for origin in origins] == original
            assert [origin['afterValue'] for origin in origins] == desired
        else:
            assert items[2]['execution'] is None and origins[2]['beforeValue'] is None and origins[2]['afterValue'] is None
            assert origins[1]['beforeValue'] == (
                floats.floating('40040000efbeadde') if mode == 'late-conflict' else original[1])
            if mode == 'metadata-drift':
                assert items[1]['execution']['outcome'] == 'write-rejected'
                assert not items[1]['execution']['writeAttempted'] and items[1]['execution']['errors']
                assert origins[1]['afterValue'] is None
            elif mode == 'late-conflict':
                assert items[1]['execution']['outcome'] == 'conflict' and not items[1]['execution']['writeAttempted']
                assert origins[1]['afterValue'] is None
            elif mode == 'partial':
                assert items[1]['execution']['outcome'] == 'readback-mismatch'
                assert origins[1]['afterValue'] == floats.floating('4004000000000123')
            elif mode == 'ack-error':
                assert items[1]['execution']['outcome'] == 'verified' and not items[1]['execution']['writeAcknowledged']
                assert origins[1]['afterValue'] == desired[1]
            else:
                assert items[1]['execution']['outcome'] == 'unverified' and origins[1]['afterValue'] is None
                if mode == 'readback':
                    assert origins[1]['finalValue'] == desired[1]
                    assert items[1]['final']['matchesReplacement'] is True
        assert (tools / 'fault').read_text() == mode
        assert len((tools / 'writes').read_bytes().splitlines()) == expected_writes
        assert client.send(frame) == response
        changed = {**frame, 'command': batches.command(list(reversed(frame['command']['edits'])))}
        scalars.reject_frame(client, changed, 'INVALID_REQUEST')
        assert len((tools / 'writes').read_bytes().splitlines()) == expected_writes
        assert scalars.audits(client)['items'] == [audit]
        assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        for snapshot in snapshots:
            scalars.read_snapshot(client, snapshot)
        assert len(client.good({'kind': 'listBranches'})['branches']) == 2
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
    for mode in ('initial-metadata', 'metadata-drift', 'late-conflict', 'partial', 'ack-error',
                 'readback', 'write-death', 'final-drift', 'final-readback'):
        with tempfile.TemporaryDirectory(prefix='phantom-scalar-batch-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('scalar batch failures: metadata revalidation, exact per-phase values, partial effects, skipped edits, final reads, death and replay passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
