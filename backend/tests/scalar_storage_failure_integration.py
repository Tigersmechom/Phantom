"""Typed storage provenance survives real writes with injected GDB failures."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile

import memory_edit_failure_integration as faults
import scalar_storage_integration as scalars
from lifecycle_integration import require_inferior_exited
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []


class Client(scalars.Client):
    def send(self, frame):
        if self.record_requests:
            TRAFFIC.append(('request', frame))
        return TransportClient.send(self, frame)

    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received', frame))
        return frame


def scenario(executable, real_gdb, mode, workspace):
    tools = workspace / 'tools'
    tools.mkdir()
    faults.proxy(tools / 'gdb', real_gdb, mode)
    old_path = os.environ.get('PATH', '')
    try:
        os.environ['PATH'] = str(tools) + os.pathsep + old_path
        client = Client(executable, workspace)
    finally:
        os.environ['PATH'] = old_path
    pid = None
    try:
        artifact = scalars.build(client)
        client.launch_scalar(artifact, text='q' * 131072 if mode == 'ack-error' else '')
        before = scalars.at_ready(client)
        pid = before['processInstanceId']
        if mode == 'ack-error':
            # Free pipe capacity so accidental input feeding during scalar
            # inspection, revalidation, readback or refresh becomes visible.
            descriptor = os.open(f'/proc/{pid}/fd/0', os.O_RDONLY | os.O_NONBLOCK)
            try:
                assert os.read(descriptor, 4096) == b'q' * 4096
            finally:
                os.close(descriptor)
        snapshot = scalars.inspect(client, 'scalar')
        assert snapshot['storage']['value'] == scalars.integer(7), snapshot
        address = snapshot['target']['addressHex']
        desired = scalars.integer(int.from_bytes(bytes.fromhex('11223344'), 'little'))
        frame = client.frame(scalars.write(snapshot, desired))
        (tools / 'arm').touch()
        response = client.send(frame)
        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        audit = response['result']['intervention']
        report = audit['report']
        assert audit['profile'] == scalars.PROFILE and audit['requestId'] == frame['requestId'], audit
        assert audit['beforePoint'] == snapshot['point'] and audit['beforeStop'] == snapshot['stop'], audit
        assert report['writeAttempted'] and report['beforeBytesHex'] == '07000000', report
        assert report['expectedBytesHex'] == snapshot['storage']['bytesHex'], report
        assert report['replacementBytesHex'] == '11223344', report
        assert report['addressHex'] == address and report['byteCount'] == 4, report
        origin = audit['scalar']
        assert origin['target'] == snapshot['target'] and origin['snapshotId'] == snapshot['id'], origin
        assert origin['locator'] == 'frame:0:scalar' and origin['requestedValue'] == desired, origin
        assert origin['beforeValue'] == scalars.integer(7), origin

        failed = mode in ('write-death', 'refresh-death')
        events = [client.recv() for _ in range(2 if failed else 3)]
        expected_events = ['branchCreated', 'state'] if failed else ['branchCreated', 'observation', 'state']
        assert [event['payload']['kind'] for event in events] == expected_events, events
        assert all(event.get('causedByRequestId') == frame['requestId'] for event in events), events
        assert events[0]['payload']['parent'] == before['point'], events
        assert events[-1]['sequence'] == response['result']['throughSequence'], response
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed' and audit['refreshError'], audit
            assert audit['afterPoint'] is None and audit['afterStop'] is None, audit
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None, checkpoint
            assert checkpoint['observation'] is None, checkpoint
            assert events[-1]['payload']['state'] == checkpoint['state'], events
            require_inferior_exited(pid)
        else:
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None, audit
            client.observation = events[1]['payload']['observation']
            assert checkpoint['observation'] == client.observation, checkpoint
            assert client.observation['stop'] != before['stop'], client.observation
            assert client.observation['input'] == before['input'], client.observation['input']
            expected_bytes = '11220000' if mode == 'partial' else '11223344'
            assert scalars.memory(client, address, 4).hex() == expected_bytes

        if mode == 'partial':
            assert report['outcome'] == 'readback-mismatch' and report['afterBytesHex'] == '11220000', report
            assert origin['afterValue'] == scalars.integer(0x2211), origin
            assert origin['afterValue'] != origin['requestedValue'], origin
        elif mode in ('readback', 'write-death'):
            assert report['outcome'] == 'unverified' and report['afterBytesHex'] is None, report
            # A later snapshot can read the changed value, but cannot replace
            # the missing readback evidence of this intervention.
            assert origin['afterValue'] is None, origin
        else:
            assert report['outcome'] == 'verified' and report['afterBytesHex'] == '11223344', report
            assert origin['afterValue'] == desired, origin
        assert report['writeAcknowledged'] == (mode in ('readback', 'refresh-death')), report
        assert not report['rollbackAttempted'] and not report['atomic'], report
        if mode in ('ack-error', 'partial'):
            assert any(error['phase'] == 'write' for error in report['errors']), report
        if mode == 'readback':
            assert any(error['phase'] == 'read-after' for error in report['errors']), report
        assert (tools / 'fault').read_text() == mode

        # Replay the original request, including its now-stale expectedStop;
        # neither dead GDB nor a later stop may cause a second mutation.
        assert client.send(frame) == response
        assert len((tools / 'writes').read_bytes().splitlines()) == 1
        changed = {**frame, 'command': scalars.write(snapshot, scalars.integer(23))}
        scalars.reject_frame(client, changed, 'INVALID_REQUEST')
        assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert scalars.audits(client)['items'] == [audit]
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
        scalars.read_snapshot(client, snapshot)
        branches = client.good({'kind': 'listBranches'})
        assert branches['currentBranchId'] == audit['branchId'] and len(branches['branches']) == 2, branches

        if mode == 'ack-error':
            # The audit embeds the target and request independently of the
            # evictable inspection cache. Cached response replay must continue
            # to work when the snapshot authorizing the original write is gone.
            for _ in range(128):
                client.good({'kind': 'captureMemory', 'ranges': [{'addressHex': address, 'byteCount': 4}]})
            client.bad({'kind': 'readScalarStorage', 'snapshotId': snapshot['id']}, ('HISTORY_EVICTED',))
            client.bad(scalars.write(snapshot, scalars.integer(23)), ('HISTORY_EVICTED',))
            assert client.send(frame) == response
            assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
            assert len((tools / 'writes').read_bytes().splitlines()) == 1
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
    for mode in ('ack-error', 'partial', 'readback', 'write-death', 'refresh-death'):
        with tempfile.TemporaryDirectory(prefix='phantom-scalar-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('scalar storage failures: typed evidence, partial writes, missing readback, debugger death, audit retention and dedup passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
