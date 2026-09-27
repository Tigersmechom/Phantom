"""Regression checks for control races and fatal debugger state transitions."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class Client:
    def __init__(self, executable: str, workspace: Path) -> None:
        self.process = subprocess.Popen(
            [executable, "--stdio", "--workspace", str(workspace)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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

    def frame(self, command: dict, expected_stop: dict | None = None) -> dict:
        self.counter += 1
        frame = {"protocolVersion": 1, "requestId": f"request-{self.counter}",
                 "workspace": self.workspace, "session": self.session, "command": command}
        if expected_stop is None and command["kind"] in ("step", "continue", "readVariables", "writeVariable", "readMemory"):
            assert self.observation is not None
            expected_stop = self.observation["stop"]
        if expected_stop is not None:
            frame["expectedStop"] = expected_stop
        return frame

    def send(self, *frames: dict) -> None:
        assert self.process.stdin
        self.process.stdin.write(b"".join(json.dumps(f).encode() + b"\n" for f in frames))
        self.process.stdin.flush()

    def recv(self, timeout: float = 12) -> dict:
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and self.selector.select(remaining), "backend response deadline expired"
            assert self.process.stdout
            chunk = os.read(self.process.stdout.fileno(), 65536)
            assert chunk, f"backend exited unexpectedly: {self.process.poll()}"
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        frame = json.loads(line)
        if frame.get("result", {}).get("kind") == "launchAccepted":
            self.session = frame["session"]
            self.sequence = 0
        if "sequence" in frame:
            assert frame["sequence"] == self.sequence + 1, frame
            self.sequence = frame["sequence"]
        if frame.get("payload", {}).get("kind") == "observation":
            self.observation = frame["payload"]["observation"]
            for stream in ("stdout", "stderr"):
                assert set(self.observation[stream]) == {"text", "totalBytes", "retainedFromByte", "truncated"}, self.observation
        return frame

    def query(self, command: dict) -> dict:
        frame = self.frame(command)
        self.send(frame)
        result = self.recv()
        assert result.get("requestId") == frame["requestId"], result
        return result

    def finish(self, requests: list[dict]) -> list[dict]:
        expected = {f["requestId"] for f in requests}
        completed = set()
        responses = set()
        frames = []
        while completed != expected:
            frame = self.recv()
            frames.append(frame)
            assert frame.get("ok", True), frame
            if "requestId" in frame:
                assert frame.get("ok"), frame
                responses.add(frame["requestId"])
            payload = frame.get("payload", {})
            if payload.get("kind") == "commandFinished":
                assert payload["requestId"] not in completed, frames
                completed.add(payload["requestId"])
        assert responses == expected, frames
        return frames

    def execute(self, command: dict) -> list[dict]:
        request = self.frame(command)
        self.send(request)
        return self.finish([request])

    def launch(self, artifact: dict) -> None:
        self.execute({"kind": "launch", "buildId": artifact["id"],
                      "input": {"id": "input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                      "argv": [], "environment": {}, "stopAtEntry": True})

    def checkpoint(self) -> dict:
        response = self.query({"kind": "getState"})
        assert response["ok"], response
        return response["result"]

    def kill_gdb(self) -> None:
        children = {pid for task in Path(f"/proc/{self.process.pid}/task").iterdir()
                    for pid in (task / "children").read_text().split()}
        debuggers = [int(pid) for pid in children if Path(f"/proc/{pid}/comm").read_text().strip() == "gdb"]
        assert len(debuggers) == 1, children
        os.kill(debuggers[0], signal.SIGKILL)

    def close(self) -> None:
        self.selector.close()
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        assert self.process.returncode == 0, self.process.stderr.read() if self.process.stderr else ""


def require_inferior_exited(pid: str) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            status = Path(f"/proc/{pid}/status").read_text()
        except FileNotFoundError:
            return
        state = next(line for line in status.splitlines() if line.startswith("State:"))
        # Orphans may briefly await reaping by container PID 1; they must no
        # longer be running or stopped under ptrace after debugger failure.
        if "Z (zombie)" in state:
            return
        time.sleep(0.02)
    raise AssertionError(f"inferior {pid} survived debugger cleanup")


def check_build_shutdown(executable: str) -> None:
    with tempfile.TemporaryDirectory(prefix="phantom-build-cancel-") as directory:
        workspace = Path(directory)
        marker = workspace / "compiler-started"
        compiler = workspace / "slow-compiler"
        compiler.write_text("#!/usr/bin/python3\nimport os, time\n"
                            + f"with open({str(marker)!r}, 'a') as output: output.write(str(os.getpid()) + '\\n')\n"
                            + "time.sleep(60)\n")
        compiler.chmod(0o700)
        client = Client(executable, workspace)
        try:
            text = "int main() { return 0; }\n"
            build_command = {"kind": "build", "source": {"id": "source", "documents": [
                {"documentId": "main", "revisionId": "rev", "path": "main.cpp", "text": text,
                 "sha256": hashlib.sha256(text.encode()).hexdigest()}]},
                "configuration": {"revisionId": "config", "compiler": str(compiler), "flags": [],
                                  "outputDirectory": ".phantom/test-build"}, "architecture": "x86_64"}
            cancelled_build = client.frame(build_command)
            cancel = client.frame({"kind": "cancel", "targetRequestId": cancelled_build["requestId"]})
            client.send(cancelled_build, cancel)
            frames = [client.recv() for _ in range(3)]
            assert frames[0]["requestId"] == cancelled_build["requestId"] and frames[0]["error"]["code"] == "CANCELLED", frames
            assert frames[1]["requestId"] == cancel["requestId"] and frames[1]["ok"], frames
            assert frames[2]["payload"]["outcome"] == "completed", frames
            marker.unlink(missing_ok=True)

            active_build = client.frame(build_command)
            client.send(active_build)
            deadline = time.monotonic() + 5
            while not marker.exists():
                assert time.monotonic() < deadline, "compiler did not start"
                time.sleep(0.01)
            queued_build = client.frame(build_command)
            client.send(queued_build)
            assert client.process.stdin
            client.process.stdin.close()
            frames = [client.recv(timeout=5) for _ in range(2)]
            assert {f["requestId"]: f["error"]["code"] for f in frames} == {
                active_build["requestId"]: "CANCELLED", queued_build["requestId"]: "CANCELLED"}, frames
            client.process.wait(timeout=5)
            assert len(marker.read_text().splitlines()) == 1, "queued compiler started after EOF"
            require_inferior_exited(marker.read_text().strip())
        finally:
            client.close()


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    if not shutil.which("gdb"):
        return 77
    with tempfile.TemporaryDirectory(prefix="phantom-lifecycle-") as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            text = ('#include <unistd.h>\n'
                    'int main() {\n'
                    '  write(1, "out-marker\\n", 11);\n'
                    '  write(2, "err-marker\\n", 11);\n'
                    '  volatile unsigned long counter = 0;\n'
                    '  while (true) counter = counter + 1;\n'
                    '}\n')
            built = client.query({"kind": "build", "source": {"id": "source", "documents": [
                {"documentId": "main", "revisionId": "rev-1", "path": "main.cpp", "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}]},
                "configuration": {"revisionId": "config", "compiler": "clang++", "flags": ["-std=c++20", "-g", "-O0"],
                                  "outputDirectory": ".phantom/test-build"}, "architecture": "x86_64"})
            assert built["ok"] and built["result"]["success"], built
            artifact = built["result"]["artifact"]

            # Cancel can arrive in the same write as the first launch, before
            # the worker has established a session or spawned GDB.
            launch = client.frame({"kind": "launch", "buildId": artifact["id"],
                "input": {"id": "input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                "argv": [], "environment": {}, "stopAtEntry": True})
            cancel = client.frame({"kind": "cancel", "targetRequestId": launch["requestId"]})
            client.send(launch, cancel)
            frames = [client.recv() for _ in range(3)]
            assert frames[0]["requestId"] == launch["requestId"] and frames[0]["error"]["code"] == "CANCELLED", frames
            assert frames[1]["requestId"] == cancel["requestId"] and frames[1]["ok"], frames
            assert frames[2]["payload"]["requestId"] == cancel["requestId"] and frames[2]["payload"]["outcome"] == "completed", frames
            no_session = client.query({"kind": "getState"})
            assert not no_session["ok"] and no_session["error"]["code"] == "STALE_CONTEXT", no_session
            assert no_session["session"] is None, no_session

            # A pause at an existing stop completes without inventing another
            # observation or waiting for a GDB async record that will not come.
            client.launch(artifact)
            before = client.checkpoint()
            paused = client.execute({"kind": "pause"})
            assert len(paused) == 2 and paused[-1]["payload"]["outcome"] == "completed", paused
            after = client.checkpoint()
            assert before["observation"] == after["observation"], after
            assert before["state"] == after["state"], after
            client.execute({"kind": "step", "stepKind": "over"})
            client.execute({"kind": "step", "stepKind": "over"})
            client.execute({"kind": "stop"})
            assert client.observation["stdout"]["text"] == "out-marker\n", client.observation
            assert client.observation["stderr"]["text"] == "err-marker\n", client.observation
            assert client.checkpoint()["state"]["live"] is None

            # Both requests share a transport write and the original expected
            # stop. The control acknowledgement must survive its own effect
            # invalidating that stop (or terminating the session altogether).
            for control_kind in ("stop", "cancel", "pause", "cancel"):
                client.launch(artifact)
                expected_stop = client.observation["stop"]
                resume = client.frame({"kind": "continue"}, expected_stop)
                command = {"kind": control_kind}
                if control_kind == "cancel":
                    command["targetRequestId"] = resume["requestId"]
                control = client.frame(command, expected_stop)
                client.send(resume, control)
                frames = client.finish([resume, control])
                finished = {f["payload"]["requestId"]: f["payload"]["outcome"] for f in frames
                            if f.get("payload", {}).get("kind") == "commandFinished"}
                assert finished[resume["requestId"]] == ("cancelled" if control_kind == "cancel" else "completed"), frames
                assert finished[control["requestId"]] == "completed", frames
                checkpoint = client.checkpoint()
                assert checkpoint["state"]["phase"] == ("terminated" if control_kind == "stop" else "stopped"), checkpoint
                observations = [f for f in frames if f.get("payload", {}).get("kind") == "observation"]
                assert len(observations) == 1, frames
                if control_kind != "stop":
                    assert client.observation["stack"], client.observation
                    client.execute({"kind": "stop"})

            # Applying pause after cancel must not erase the cancellation
            # outcome. Both controls still receive their own single terminal
            # acknowledgement, regardless of their order in the same write.
            for control_order in (("cancel", "pause"), ("pause", "cancel")):
                client.launch(artifact)
                expected_stop = client.observation["stop"]
                resume = client.frame({"kind": "continue"}, expected_stop)
                controls = [client.frame(
                    {"kind": kind, **({"targetRequestId": resume["requestId"]} if kind == "cancel" else {})},
                    expected_stop) for kind in control_order]
                client.send(resume, *controls)
                frames = client.finish([resume, *controls])
                finished = {f["payload"]["requestId"]: f["payload"]["outcome"] for f in frames
                            if f.get("payload", {}).get("kind") == "commandFinished"}
                assert finished == {resume["requestId"]: "cancelled",
                                    **{control["requestId"]: "completed" for control in controls}}, frames
                assert len([f for f in frames if f.get("payload", {}).get("kind") == "observation"]) == 1, frames
                assert client.checkpoint()["state"]["phase"] == "stopped"
                print(f"Control priority {' -> '.join(control_order)}: " + json.dumps(finished, sort_keys=True))
                client.execute({"kind": "stop"})

            # Reject a stale stop identity before issuing the interrupt,
            # even when the rejected control is adjacent to a valid cancel.
            client.launch(artifact)
            resume = client.frame({"kind": "continue"}, client.observation["stop"])
            stale = client.frame({"kind": "pause"}, {"stopId": "expired", "stateRevision": 99999})
            cancel = client.frame({"kind": "cancel", "targetRequestId": resume["requestId"]}, client.observation["stop"])
            client.send(resume, stale, cancel)
            frames = [client.recv() for _ in range(7)]
            rejected = [f for f in frames if f.get("requestId") == stale["requestId"]]
            assert len(rejected) == 1 and rejected[0]["error"]["code"] == "STALE_CONTEXT", frames
            terminal = [f["payload"] for f in frames if f.get("payload", {}).get("kind") == "commandFinished"]
            assert {f["requestId"]: f["outcome"] for f in terminal} == {
                resume["requestId"]: "cancelled", cancel["requestId"]: "completed"}, frames
            client.execute({"kind": "stop"})

            client.launch(artifact)
            inferior_pid = client.observation["processInstanceId"]
            client.kill_gdb()
            execution = client.execute({"kind": "continue"})
            assert execution[-1]["payload"]["outcome"] == "failed", execution
            assert [f["payload"]["kind"] for f in execution if "payload" in f] == ["state", "commandFinished"], execution
            assert client.checkpoint()["state"]["phase"] == "failed"
            require_inferior_exited(inferior_pid)

            # A read can be the first operation that detects debugger death.
            # Its failure must invalidate live state, and reconnect/getState
            # must agree rather than advertising a phantom stopped process.
            client.launch(artifact)
            inferior_pid = client.observation["processInstanceId"]
            client.kill_gdb()
            failed = client.query({"kind": "readMemory", "addressHex": "0x0", "byteCount": 1})
            assert not failed["ok"], failed
            event = client.recv()
            assert event["payload"]["kind"] == "state", event
            assert event["payload"]["state"]["phase"] == "failed", event
            checkpoint = client.checkpoint()
            assert checkpoint["state"]["phase"] == "failed" and checkpoint["state"]["live"] is None, checkpoint

            require_inferior_exited(inferior_pid)

            # Replacing a session first disposes its prior GDB instance. If
            # the replacement cannot launch, the prior state is no longer live.
            client.launch(artifact)
            Path(artifact["binaryPath"]).unlink()
            request = client.frame({"kind": "launch", "buildId": artifact["id"],
                "input": {"id": "input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                "argv": [], "environment": {}, "stopAtEntry": True})
            client.send(request)
            failed = client.recv()
            assert not failed["ok"], failed
            event = client.recv()
            assert event["payload"]["kind"] == "state" and event["payload"]["state"]["phase"] == "failed", event
            checkpoint = client.checkpoint()
            assert checkpoint["state"]["phase"] == "failed" and checkpoint["state"]["live"] is None, checkpoint
        finally:
            client.close()
    check_build_shutdown(sys.argv[1])
    print("Lifecycle integration checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
