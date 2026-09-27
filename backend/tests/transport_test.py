#!/usr/bin/env python3
"""Exercise the standalone NDJSON transport without starting GDB.

The transport is deliberately tested as a byte stream: frames can be split at
arbitrary boundaries, an overlong physical line must be discarded through its
newline, and EOF without a final newline is a valid final frame.  The test
only depends on the executable path and Python's standard library.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from typing import Iterable, NoReturn


def fail(message: str, detail: object = None) -> NoReturn:
    if detail is not None:
        message += ": " + repr(detail)
    raise AssertionError(message)


def start(executable: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [executable, "--stdio", "--workspace", tempfile.mkdtemp(prefix="phantom-transport-")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def read_lines(process: subprocess.Popen[bytes], expected: int, timeout: float = 8.0) -> list[dict]:
    if process.stdout is None:
        fail("stdout pipe is missing")
    result: list[dict] = []
    buffer = b""
    descriptor = process.stdout.fileno()
    deadline = time.monotonic() + timeout
    while len(result) < expected:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("timed out reading transport responses", result)
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            fail("timed out reading transport responses", result)
        chunk = os.read(descriptor, 65536)
        if not chunk:
            fail("transport closed before expected responses", {"responses": result, "returncode": process.poll()})
        buffer += chunk
        while b"\n" in buffer and len(result) < expected:
            line, buffer = buffer.split(b"\n", 1)
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                fail("transport emitted invalid JSON", {"line": line, "error": str(error)})
            if not isinstance(value, dict):
                fail("transport response is not an object", value)
            result.append(value)
    return result


def finish(process: subprocess.Popen[bytes], timeout: float = 8.0) -> tuple[int, bytes]:
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
        fail("backend did not terminate", process.returncode)
    stderr = process.stderr.read() if process.stderr else b""
    return code, stderr


def connect_frame() -> bytes:
    return b'{"supportedProtocolVersions":[1]}'


def assert_connect(response: dict) -> None:
    if response.get("kind") != "connectResult" or response.get("ok") is not True:
        fail("connect response is not successful", response)
    if response.get("protocolVersion") != 1:
        fail("unexpected protocol version", response)


def test_optional_connect_and_malformed_resync(executable: str) -> None:
    process = start(executable)
    assert process.stdin is not None
    # A valid connect frame has no ``kind`` field.  The malformed line after it
    # must produce one error, and its following valid connect must still be
    # recognized (the reader cannot lose synchronization).
    process.stdin.write(connect_frame() + b"\n")
    process.stdin.write(b"not-json\r\n")
    process.stdin.write(b'{"kind":"connect","supportedProtocolVersions":[1]}\r\n')
    process.stdin.close()
    responses = read_lines(process, 3)
    assert_connect(responses[0])
    if responses[1].get("kind") != "error" or responses[1].get("error", {}).get("code") != "INVALID_REQUEST":
        fail("malformed frame was not rejected", responses[1])
    assert_connect(responses[2])
    code, stderr = finish(process)
    if code != 0 or stderr:
        fail("normal EOF did not drain transport", {"code": code, "stderr": stderr})


def test_oversized_line_discards_suffix(executable: str) -> None:
    process = start(executable)
    assert process.stdin is not None
    # The limit is 16 MiB.  Keep a complete, otherwise valid request suffix on
    # the same physical line: it must never be parsed as an independent frame.
    suffix = json.dumps(
        {
            "protocolVersion": 1,
            "requestId": "tail",
            "workspace": {"id": "workspace-local", "revisionId": "workspace-0"},
            "session": None,
            "command": {"kind": "capabilities"},
        },
        separators=(",", ":"),
    ).encode()
    overlong = (b"x" * (16 * 1024 * 1024)) + suffix + b"\n"
    process.stdin.write(overlong)
    process.stdin.write(connect_frame() + b"\n")
    process.stdin.close()
    responses = read_lines(process, 2, timeout=15.0)
    if responses[0].get("kind") != "error" or responses[0].get("error", {}).get("code") != "LIMIT_EXCEEDED":
        fail("overlong frame did not produce LIMIT_EXCEEDED", responses[0])
    assert_connect(responses[1])
    code, stderr = finish(process, timeout=10.0)
    remaining = process.stdout.read() if process.stdout else b""
    if code != 0 or stderr:
        fail("overlong-frame recovery failed", {"code": code, "stderr": stderr})
    if remaining:
        fail("overlong suffix was executed instead of discarded", remaining)


def test_final_frame_without_newline(executable: str) -> None:
    process = start(executable)
    assert process.stdin is not None
    process.stdin.write(connect_frame())
    process.stdin.close()
    responses = read_lines(process, 1)
    assert_connect(responses[0])
    code, stderr = finish(process)
    if code != 0 or stderr:
        fail("EOF without newline was not accepted", {"code": code, "stderr": stderr})


def test_bounded_queue_and_order(executable: str) -> None:
    process = start(executable)
    assert process.stdin is not None
    # Invalid requests are cheap but exercise queue backpressure.  More than
    # one queue window must remain ordered and must not make the reader allocate
    # an unbounded DOM backlog.
    count = 128
    process.stdin.write(b"{}\n" * count)
    process.stdin.close()
    responses = read_lines(process, count, timeout=15.0)
    if any(item.get("kind") != "error" for item in responses):
        fail("bounded queue test received a non-error response", responses)
    code, stderr = finish(process, timeout=10.0)
    if code != 0 or stderr:
        fail("bounded queue transport failed", {"code": code, "stderr": stderr})


def test_sigterm_wakes_reader(executable: str) -> None:
    process = start(executable)
    # Leave stdin open and idle.  poll() must be interrupted by SIGTERM, and
    # cleanup must not wait for another byte from the client.
    time.sleep(0.05)  # allow the child to install sigaction before signalling
    process.send_signal(signal.SIGTERM)
    try:
        code = process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
        fail("SIGTERM did not wake an idle reader")
    if code != 128 + signal.SIGTERM:
        fail("unexpected SIGTERM exit status", code)


def main(argv: Iterable[str]) -> int:
    args = list(argv)
    if len(args) != 1:
        print("usage: transport_test.py BACKEND", file=sys.stderr)
        return 2
    executable = args[0]
    for test in (
        test_optional_connect_and_malformed_resync,
        test_oversized_line_discards_suffix,
        test_final_frame_without_newline,
        test_bounded_queue_and_order,
        test_sigterm_wakes_reader,
    ):
        test(executable)
    print("transport framing, bounded queue, EOF, resynchronization and SIGTERM tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
