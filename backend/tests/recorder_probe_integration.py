"""Probe gateway isolation and cancellation at the real NDJSON boundary.

The rr substitute is deliberate: it makes child-process readiness and cleanup
deterministic without requiring privileged performance-counter access. GDB and
the shipped scalar probe remain real, as does the separate live debug session.
"""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited

TRAFFIC: list[tuple[str, dict]] = []


class Client(LifecycleClient):
    def __init__(self, executable: str, workspace: Path, environment: dict[str, str]) -> None:
        self.record_requests = True
        self.process = subprocess.Popen(
            [executable, "--stdio", "--workspace", str(workspace)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
        self.selector = selectors.DefaultSelector()
        assert self.process.stdout
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.pending = b""
        self.sequence = 0
        self.session = None
        self.observation = None
        self.counter = 0
        self.send({"kind": "connect", "supportedProtocolVersions": [1]})
        connected = self.recv()
        assert connected["ok"], connected
        self.workspace = connected["workspace"]

    def send(self, *frames: dict) -> None:
        if self.record_requests:
            TRAFFIC.extend(("request", frame) for frame in frames)
        super().send(*frames)

    def recv(self, timeout: float = 12) -> dict:
        frame = super().recv(timeout)
        TRAFFIC.append(("received", frame))
        return frame


def fake_rr(path: Path, mode: Path, marker: Path, invocations: Path) -> None:
    path.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, pathlib, subprocess, sys, time\n"
        f"mode_path = pathlib.Path({str(mode)!r})\n"
        f"marker = pathlib.Path({str(marker)!r})\n"
        f"invocations = pathlib.Path({str(invocations)!r})\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('rr deterministic integration substitute'); sys.exit(0)\n"
        "with invocations.open('a') as log: log.write(sys.argv[1] + '\\n')\n"
        "if sys.argv[1] == 'record':\n"
        "    mode = mode_path.read_text()\n"
        "    if mode == 'block':\n"
        "        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "        marker.write_text(json.dumps({'parent': os.getpid(), 'child': child.pid}))\n"
        "        time.sleep(60)\n"
        "    if mode == 'fail':\n"
        "        print('intentional incomplete-record failure', file=sys.stderr); sys.exit(23)\n"
        "    trace = pathlib.Path(sys.argv[3]); trace.mkdir()\n"
        "    (trace / 'fixture-data').write_bytes(b'fixture')\n"
        "print('phantom-recorder-probe-ok')\n"
    )
    path.chmod(0o700)


def checked_probe(response: dict) -> dict:
    assert response["ok"] and response["result"]["kind"] == "recorderProbe", response
    result = response["result"]["probe"]
    assert result["scope"] == "isolated-scalar-fixture", result
    assert isinstance(result["elapsedMs"], int) and result["elapsedMs"] >= 0, result
    assert "perfEventParanoid" in result["environment"], result
    assert result["gdbRecordFull"]["mode"] == "synchronous-all-stop", result
    if result["gdbRecordFull"]["available"]:
        assert all(result["gdbRecordFull"][key] for key in ("memoryRestored", "pcRestored", "forwardReplay")), result
    else:
        assert isinstance(result["gdbRecordFull"]["reason"], str), result
    return result


def cancel_probe(client: Client, mode: Path, marker: Path, *, session_null: bool = False) -> None:
    mode.write_text("block")
    marker.unlink(missing_ok=True)
    request = client.frame({"kind": "probeRecorders"})
    if session_null:
        request["session"] = None
    client.send(request)
    deadline = time.monotonic() + 8
    children = None
    while children is None:
        assert time.monotonic() < deadline, "isolated recorder child did not reach blocking phase"
        if marker.exists():
            try:
                children = json.loads(marker.read_text())
            except json.JSONDecodeError:
                pass  # The marker's producer may still be completing its write.
        time.sleep(0.01)
    cancel = client.frame({"kind": "cancel", "targetRequestId": request["requestId"]})
    cancel["session"] = request["session"]
    started = time.monotonic()
    client.send(cancel)
    responses = {}
    terminal = False
    while len(responses) != 2 or not terminal:
        frame = client.recv(timeout=3)
        if "requestId" in frame:
            assert frame["requestId"] in (request["requestId"], cancel["requestId"]), frame
            assert frame["requestId"] not in responses, frame
            responses[frame["requestId"]] = frame
        else:
            # Cancelling a probe must not publish any live execution transition.
            assert frame.get("payload", {}).get("kind") == "commandFinished", frame
            assert frame["payload"]["requestId"] == cancel["requestId"], frame
            assert frame["payload"]["outcome"] == "completed", frame
            terminal = True
    assert time.monotonic() - started < 3, responses
    assert responses[cancel["requestId"]]["ok"], responses
    cancelled = checked_probe(responses[request["requestId"]])
    assert cancelled["cancelled"] is True and cancelled["rr"]["available"] is False, cancelled
    assert cancelled["rr"]["record"]["status"] == "cancelled", cancelled
    assert cancelled["rr"]["replay"]["attempted"] is False, cancelled
    for pid in children.values():
        require_inferior_exited(str(pid))
    marker.unlink()
    mode.write_text("success")


def build(client: Client) -> dict:
    source = "int main() {\n  int value = 3;\n  value += 7;\n  return value;\n}\n"
    response = client.query({
        "kind": "build", "architecture": "x86_64",
        "source": {"id": "probe-session-source", "documents": [{
            "documentId": "main", "revisionId": "main-1", "path": "main.cpp",
            "text": source, "sha256": hashlib.sha256(source.encode()).hexdigest()}]},
        "configuration": {"revisionId": "probe-session-config", "compiler": "clang++",
                          "flags": ["-std=c++20", "-g", "-O0"],
                          "outputDirectory": ".phantom/probe-session-build"},
    })
    assert response["ok"] and response["result"]["success"], response
    return response["result"]["artifact"]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: recorder_probe_integration.py BACKEND", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux") or not shutil.which("gdb") or not shutil.which("clang++"):
        print("Linux, GDB and clang++ required; recorder probe integration skipped")
        return 77
    backend = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="phantom-recorder-gateway-") as directory:
        root = Path(directory)
        tools = root / "tools"
        tools.mkdir()
        mode, marker, invocations = root / "mode", root / "ready", root / "invocations"
        mode.write_text("success")
        fake_rr(tools / "rr", mode, marker, invocations)
        environment = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}
        paranoid = Path("/proc/sys/kernel/perf_event_paranoid")
        paranoid_before = paranoid.read_text() if paranoid.exists() else None
        client = Client(backend, root, environment)
        try:
            # The command cannot become an arbitrary recorder/executable launcher.
            client.record_requests = False
            client.send(client.frame({"kind": "probeRecorders", "fixturePath": "/bin/sh"}))
            client.record_requests = True
            invalid = client.recv()
            assert not invalid["ok"] and invalid["error"]["code"] == "INVALID_REQUEST", invalid
            assert not invocations.exists()

            success = checked_probe(client.query({"kind": "probeRecorders"}))
            assert success["rr"]["available"] is True and success["cancelled"] is False, success
            assert invocations.read_text().splitlines() == ["record", "replay"]
            assert client.query({"kind": "getState"})["error"]["code"] == "STALE_CONTEXT"
            cancel_probe(client, mode, marker)
            assert client.query({"kind": "getState"})["error"]["code"] == "STALE_CONTEXT"

            # No recording failure may replay an incomplete trace.
            invocations.write_text("")
            mode.write_text("fail")
            failed = checked_probe(client.query({"kind": "probeRecorders"}))
            assert failed["rr"]["available"] is False, failed
            assert failed["rr"]["record"]["exitCode"] == 23, failed
            assert failed["rr"]["replay"]["attempted"] is False, failed
            assert invocations.read_text().splitlines() == ["record"]
            mode.write_text("success")

            client.launch(build(client))
            before = client.checkpoint()
            session = client.session
            checked_probe(client.query({"kind": "probeRecorders"}))
            after = client.checkpoint()
            assert after == before and client.session == session, (before, after)
            cancel_probe(client, mode, marker, session_null=True)
            after_cancel = client.checkpoint()
            assert after_cancel["state"] == before["state"], (before, after_cancel)
            assert after_cancel["observation"] == before["observation"], (before, after_cancel)
            assert client.session == session
            # In particular, cancellation must not leave an interrupt in GDB.
            stepped = client.execute({"kind": "step", "stepKind": "instruction"})
            assert stepped[-1]["payload"]["outcome"] == "completed", stepped
            assert client.checkpoint()["state"]["phase"] == "stopped"
            assert client.observation["stop"] != before["observation"]["stop"]
            client.execute({"kind": "stop"})
            if paranoid_before is not None:
                assert paranoid.read_text() == paranoid_before
        finally:
            client.close()
    print("recorder probe: isolated execution, verified evidence, failure, cancellation and live-session preservation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
