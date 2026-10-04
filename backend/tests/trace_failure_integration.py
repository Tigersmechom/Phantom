"""Instruction-trace failure checkpoints and preservation of final I/O.

A transparent GDB proxy kills its real debugger at an exact MI boundary:
the first stack snapshot after an instruction has executed. No timing race
is needed to reach the formerly broken partial-final-snapshot path.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

from lifecycle_integration import Client as LifecycleClient, require_inferior_exited


SOURCE = """#include <unistd.h>
int main() {
  write(1, "kept\\n", 5);
  volatile unsigned long cell = 0;
  for (;;) ++cell;
}
"""


class Client(LifecycleClient):
    def frame(self, command: dict, expected_stop: dict | None = None) -> dict:
        if command["kind"] == "traceInstructions" and expected_stop is None:
            assert self.observation is not None
            expected_stop = self.observation["stop"]
        return super().frame(command, expected_stop)


def build(client: Client) -> dict:
    response = client.query({"kind": "build", "source": {"id": "trace-failure-source", "documents": [{
        "documentId": "main", "revisionId": "main-1", "path": "main.cpp", "text": SOURCE,
        "sha256": hashlib.sha256(SOURCE.encode()).hexdigest()}]}, "configuration": {
        "revisionId": "trace-failure-config", "compiler": "clang++", "flags": ["-g", "-O0"],
        "outputDirectory": ".phantom/build"}, "architecture": "x86_64"})
    assert response["ok"] and response["result"]["success"], response
    return response["result"]["artifact"]


def proxy(path: Path, real_gdb: str, marker: Path) -> None:
    # Keep a separate real GDB child so the proxy can kill it before forwarding
    # the selected command; every other byte of MI traffic passes unchanged.
    # The child stays in the proxy/backend process group for failure cleanup.
    path.write_text(
        f"#!{sys.executable}\n"
        "import os, re, subprocess, sys, threading\n"
        f"child = subprocess.Popen([{real_gdb!r}, *sys.argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)\n"
        "def forward():\n"
        "    try:\n"
        "        for line in child.stdout:\n"
        "            sys.stdout.buffer.write(line)\n"
        "            sys.stdout.buffer.flush()\n"
        "    except BrokenPipeError:\n"
        "        pass\n"
        "reader = threading.Thread(target=forward, daemon=True)\n"
        "reader.start()\n"
        "stepped = False\n"
        "try:\n"
        "    for line in sys.stdin.buffer:\n"
        "        command = re.sub(rb'^\\d+', b'', line)\n"
        "        if command.startswith(b'-exec-step-instruction'):\n"
        "            stepped = True\n"
        "        if stepped and command.startswith(b'-stack-list-frames'):\n"
        f"            with open({str(marker)!r}, 'wb') as output: output.write(command)\n"
        "            child.kill()\n"
        "            break\n"
        "        child.stdin.write(line)\n"
        "        child.stdin.flush()\n"
        "finally:\n"
        "    if child.poll() is None:\n"
        "        child.terminate()\n"
        "    try:\n"
        "        child.wait(timeout=3)\n"
        "    except subprocess.TimeoutExpired:\n"
        "        child.kill()\n"
        "        child.wait()\n"
        "    reader.join(timeout=3)\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def final_snapshot_failure(executable: str, real_gdb: str, workspace: Path) -> None:
    tools = workspace / "audit-tools"
    tools.mkdir()
    marker = workspace / "killed-final-snapshot"
    proxy(tools / "gdb", real_gdb, marker)
    original_path = os.environ.get("PATH", "")
    try:
        os.environ["PATH"] = str(tools) + os.pathsep + original_path
        client = Client(executable, workspace)
    finally:
        os.environ["PATH"] = original_path
    inferior = None
    try:
        artifact = build(client)
        client.launch(artifact)
        before = client.observation
        assert before is not None
        inferior = before["processInstanceId"]
        events = client.execute({"kind": "traceInstructions", "count": 1, "memoryRanges": []})
        assert marker.read_bytes().startswith(b"-stack-list-frames"), "proxy did not reach the intended MI boundary"
        payloads = [frame["payload"] for frame in events if "payload" in frame]
        assert [payload["kind"] for payload in payloads] == [
            "state", "instructionTraceRecorded", "commandFinished"], payloads
        assert payloads[0]["state"]["phase"] == "failed" and payloads[0]["state"]["live"] is None, payloads
        assert payloads[-1]["outcome"] == "failed" and payloads[-1].get("error"), payloads
        checkpoint = client.checkpoint()
        assert checkpoint["state"]["phase"] == "failed" and checkpoint["state"]["live"] is None, checkpoint
        assert checkpoint["observation"] == before, checkpoint
        history = client.query({"kind": "readHistory", "point": before["point"]})
        assert history["ok"] and history["result"]["observation"] == before, history
        recorded = payloads[1]
        trace = client.query({"kind": "readInstructionTrace", "traceId": recorded["traceId"], "start": 0, "count": 64})
        assert trace["ok"], trace
        saved = trace["result"]["trace"]
        assert saved["afterPoint"] is None and saved["afterStop"] is None, saved
        assert saved["executedInstructions"] == 1 and saved["status"] == "failed", saved
        require_inferior_exited(inferior)
    finally:
        client.close()
        if inferior is not None:
            require_inferior_exited(inferior)


def retained_output_on_stop(executable: str, workspace: Path) -> None:
    client = Client(executable, workspace)
    inferior = None
    try:
        artifact = build(client)
        client.execute({"kind": "launch", "buildId": artifact["id"],
                        "input": {"id": "queued-input", "text": "future ", "encoding": "utf-8", "closeAfterWrite": False},
                        "argv": [], "environment": {}, "stopAtEntry": True})
        client.execute({"kind": "step", "stepKind": "over"})
        before = client.observation
        assert before is not None and before["stdout"]["text"] == "kept\n", before
        assert before["input"]["deliveredBytes"] == 7, before
        inferior = before["processInstanceId"]
        trace = client.frame({"kind": "traceInstructions", "count": 256, "memoryRanges": []})
        stop = client.frame({"kind": "stop"})
        client.send(trace, stop)
        frames = client.finish([trace, stop])
        terminal = [frame["payload"] for frame in frames if frame.get("payload", {}).get("kind") == "commandFinished"]
        assert len(terminal) == 2 and all(payload["outcome"] == "completed" for payload in terminal), frames
        after = client.checkpoint()
        assert after["state"]["phase"] == "terminated" and after["state"]["live"] is None, after
        observed = after["observation"]
        assert observed["stdout"]["text"] == "kept\n" and observed["stdout"]["totalBytes"] == 5, observed
        assert observed["input"]["submitted"] == before["input"]["submitted"], observed
        assert observed["input"]["revision"] == before["input"]["revision"], observed
        assert observed["input"]["deliveredBytes"] == before["input"]["deliveredBytes"], observed
        history = client.query({"kind": "readHistory", "point": before["point"]})
        assert history["ok"] and history["result"]["observation"] == before, history
        require_inferior_exited(inferior)
    finally:
        client.close()
        if inferior is not None:
            require_inferior_exited(inferior)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: trace_failure_integration.py BACKEND", file=sys.stderr)
        return 2
    real_gdb = shutil.which("gdb")
    if not sys.platform.startswith("linux") or not real_gdb or not shutil.which("clang++"):
        return 77
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="phantom-trace-failures-") as directory:
        root = Path(directory)
        failed = root / "fatal"
        stopped = root / "stopped"
        failed.mkdir()
        stopped.mkdir()
        final_snapshot_failure(executable, str(Path(real_gdb).resolve()), failed)
        retained_output_on_stop(executable, stopped)
    print("trace failure: deterministic final-snapshot debugger death and retained I/O on Stop passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
