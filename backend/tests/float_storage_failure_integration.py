"""Exact IEEE intervention evidence survives partial writes and debugger loss."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile

import float_storage_integration as floats
import memory_edit_failure_integration as faults
import scalar_storage_integration as scalars
from lifecycle_integration import require_inferior_exited
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []


class Client(floats.Client):
    def send(self, frame):
        if self.record_requests:
            TRAFFIC.append(('request', frame))
        return TransportClient.send(self, frame)

    def recv(self):
        frame = TransportClient.recv(self)
        TRAFFIC.append(('received', frame))
        return frame


def scenario(executable, real_gdb, mode, workspace):
    tools = workspace / 'tools'; tools.mkdir()
    faults.proxy(tools / 'gdb', real_gdb, mode)
    old_path = os.environ.get('PATH', '')
    try:
        os.environ['PATH'] = str(tools) + os.pathsep + old_path
        client = Client(executable, workspace)
    finally:
        os.environ['PATH'] = old_path
    pid = None
    try:
        artifact = floats.build(client)
        client.launch_scalar(artifact)
        before = floats.at_ready(client)
        pid = before['processInstanceId']
        snapshot = floats.inspect(client, 'doubleValue')
        original = floats.floating('4004000000000000')
        desired = floats.floating('7ff0000000000123')  # signaling NaN, payload 0x123
        assert snapshot['storage']['value'] == original, snapshot
        address = snapshot['target']['addressHex']
        frame = client.frame(floats.write(snapshot, desired))
        (tools / 'arm').touch()
        response = client.send(frame)
        assert response['ok'] and response['result']['kind'] == 'memoryIntervention', response
        audit = response['result']['intervention']; report = audit['report']; origin = audit['scalar']
        assert audit['profile'] == floats.PROFILE and audit['requestId'] == frame['requestId']
        assert audit['beforePoint'] == snapshot['point'] and audit['beforeStop'] == snapshot['stop']
        assert report['writeAttempted'] and report['beforeBytesHex'] == '0000000000000440', report
        assert report['expectedBytesHex'] == snapshot['storage']['bytesHex']
        assert report['replacementBytesHex'] == '230100000000f07f', report
        assert report['byteCount'] == 8 and report['addressHex'] == address
        assert origin['snapshotId'] == snapshot['id'] and origin['target'] == snapshot['target']
        assert origin['locator'] == 'frame:0:doubleValue' and origin['requestedValue'] == desired
        assert origin['beforeValue'] == original

        failed = mode in ('write-death', 'refresh-death')
        events = [client.recv() for _ in range(2 if failed else 3)]
        assert [event['payload']['kind'] for event in events] == (
            ['branchCreated', 'state'] if failed else ['branchCreated', 'observation', 'state']), events
        assert all(event.get('causedByRequestId') == frame['requestId'] for event in events), events
        assert events[0]['payload']['parent'] == before['point']
        assert events[-1]['sequence'] == response['result']['throughSequence']
        checkpoint = client.good({'kind': 'getState'})
        if failed:
            assert audit['contextStatus'] == 'failed' and audit['refreshError'], audit
            assert audit['afterPoint'] is None and audit['afterStop'] is None
            assert checkpoint['state']['phase'] == 'failed' and checkpoint['state']['live'] is None
            assert checkpoint['observation'] is None
            require_inferior_exited(pid)
        else:
            assert audit['contextStatus'] == 'refreshed' and audit['refreshError'] is None
            client.observation = events[1]['payload']['observation']
            assert checkpoint['observation'] == client.observation
            assert client.observation['stop'] != before['stop']
            expected_bytes = '2301000000000440' if mode == 'partial' else '230100000000f07f'
            assert scalars.memory(client, address, 8).hex() == expected_bytes
            # Fresh observation/inspection may format a signaling NaN but
            # cannot quiet or otherwise rewrite its storage representation.
            fresh = floats.inspect(client, 'doubleValue')
            assert fresh['storage']['value'] == floats.floating(bytes.fromhex(expected_bytes)[::-1].hex())
            assert scalars.memory(client, address, 8).hex() == expected_bytes

        if mode == 'partial':
            assert report['outcome'] == 'readback-mismatch' and report['afterBytesHex'] == '2301000000000440'
            assert origin['afterValue'] == floats.floating('4004000000000123'), origin
            assert origin['afterValue'] != desired
        elif mode in ('readback', 'write-death'):
            assert report['outcome'] == 'unverified' and report['afterBytesHex'] is None
            assert origin['afterValue'] is None, origin
        else:
            assert report['outcome'] == 'verified' and report['afterBytesHex'] == '230100000000f07f'
            assert origin['afterValue'] == desired, origin
        assert report['writeAcknowledged'] == (mode in ('readback', 'refresh-death'))
        assert report['atomic'] is False and report['rollbackAttempted'] is False
        if mode in ('ack-error', 'partial'):
            assert any(error['phase'] == 'write' for error in report['errors']), report
        if mode == 'readback':
            assert any(error['phase'] == 'read-after' for error in report['errors']), report
        assert (tools / 'fault').read_text() == mode

        assert client.send(frame) == response
        assert len((tools / 'writes').read_bytes().splitlines()) == 1
        changed = {**frame, 'command': floats.write(snapshot, floats.floating('8000000000000000'))}
        scalars.reject_frame(client, changed, 'INVALID_REQUEST')
        scalars.read_snapshot(client, snapshot)
        assert client.good({'kind': 'readMemoryIntervention', 'interventionId': audit['id']})['intervention'] == audit
        assert scalars.audits(client)['items'] == [audit]
        assert client.good({'kind': 'readHistory', 'point': before['point']})['observation'] == before
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
        with tempfile.TemporaryDirectory(prefix='phantom-float-failure-') as directory:
            scenario(sys.argv[1], real_gdb, mode, Path(directory))
    print('float storage failures: actual IEEE readback, partial writes, preserved signaling NaNs, debugger death and replay passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
