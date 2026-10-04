"""Real opt-in record-full navigation through the public NDJSON contract."""
from __future__ import annotations

import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from service_integration import Client as TransportClient

TRAFFIC: list[tuple[str, dict]] = []
SOURCE = (Path(__file__).resolve().parents[1] / "fixtures/recording-test.cpp").read_text()
LIVE = {"step", "continue", "readRecording", "seekRecording", "reverseInstruction",
        "appendInput", "closeInput", "traceInstructions", "readRegisters", "readMemory"}


class Client(TransportClient):
    def __init__(self, executable, workspace):
        super().__init__(executable, workspace)
        self.record_requests = True
        self.counter = 0
        connected = self.send({"kind": "connect", "supportedProtocolVersions": [1]})
        assert connected["ok"], connected
        self.workspace = connected["workspace"]
        self.session = None
        self.observation = None

    def send(self, frame):
        if self.record_requests:
            TRAFFIC.append(("request", frame))
        return super().send(frame)

    def recv(self):
        frame = super().recv()
        TRAFFIC.append(("received", frame))
        return frame

    def frame(self, command):
        self.counter += 1
        frame = {"protocolVersion": 1, "requestId": f"recording-{self.counter}",
                 "workspace": self.workspace, "session": self.session, "command": command}
        if command["kind"] in LIVE:
            frame["expectedStop"] = self.observation["stop"]
        return frame

    def good(self, command):
        response = self.send(self.frame(command))
        assert response["ok"], response
        return response["result"]

    def bad(self, command, codes=("INVALID_REQUEST", "LIMIT_EXCEEDED")):
        self.record_requests = False
        try:
            response = self.send(self.frame(command))
        finally:
            self.record_requests = True
        assert not response["ok"] and response["error"]["code"] in codes, response
        return response

    def execute(self, command, outcome="completed"):
        request = self.frame(command)
        response = self.send(request)
        assert response["ok"] and response["result"]["kind"] == ("launchAccepted" if command["kind"] == "launch" else "accepted"), response
        if command["kind"] == "launch":
            self.session = response["session"]
        events = []
        while True:
            event = self.recv()
            assert event.get("causedByRequestId") == request["requestId"], event
            events.append(event)
            payload = event["payload"]
            if payload["kind"] == "observation":
                self.observation = payload["observation"]
            if payload["kind"] == "commandFinished":
                assert payload["outcome"] == outcome, events
                return events

    def launch_command(self, artifact, mode="s", limit=256, profile="gdb-record-full"):
        command = {"kind": "launch", "buildId": artifact["id"],
                "input": {"id": "recorded-input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                "argv": [mode], "environment": {}, "stopAtEntry": True,
                "recordingProfile": profile}
        if profile == "gdb-record-full":
            command["maxRecordedInstructions"] = limit
        return command

    def launch(self, artifact, **kwargs):
        self.execute(self.launch_command(artifact, **kwargs))

    def breakpoint(self, marker=None):
        ranges = [] if marker is None else [{"id": "recording-breakpoint", "range": location(marker), "enabled": True}]
        result = self.good({"kind": "setBreakpoints", "documentId": "recording", "revisionId": "recording-1",
                            "breakpoints": ranges})
        assert all(item["verified"] for item in result["breakpoints"]), result

    def to_marker(self, marker):
        self.breakpoint(marker)
        self.execute({"kind": "continue"})
        assert self.observation["location"]["start"]["line"] == location(marker)["start"]["line"], self.observation
        self.breakpoint()


def location(marker):
    line = next(i for i, text in enumerate(SOURCE.splitlines(), 1) if marker in text)
    offset = sum(len(text) + 1 for text in SOURCE.splitlines()[:line-1])
    return {"documentId": "recording", "revisionId": "recording-1", "range": {"start": offset, "end": offset},
            "start": {"line": line, "column": 1}, "end": {"line": line, "column": 1}}


def value(observation):
    item = next(variable for frame in observation["stack"] for variable in frame["variables"] if variable["name"] == "value")
    return int(item["value"]["value"]["decimal"])


def cursor(observation):
    recording = observation["recording"]
    assert recording["available"], recording
    return recording["currentInstruction"]


def main():
    if len(sys.argv) != 2:
        return 2
    compiler = shutil.which("clang++") or shutil.which("g++")
    if not sys.platform.startswith("linux") or not shutil.which("gdb") or not compiler:
        return 77
    with tempfile.TemporaryDirectory(prefix="phantom-recording-protocol-") as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            artifact = client.good({"kind": "build", "architecture": "x86_64", "source": {
                "id": "recording-source", "documents": [{"documentId": "recording", "revisionId": "recording-1",
                "path": "recording.cpp", "text": SOURCE, "sha256": hashlib.sha256(SOURCE.encode()).hexdigest()}]},
                "configuration": {"revisionId": "recording-config", "compiler": compiler,
                "flags": ["-std=c++20", "-g", "-O0"], "outputDirectory": ".phantom/build",
                "addressProfile": "fixed-executable"}})["artifact"]
            invalid = client.launch_command(artifact)
            invalid["input"]["closeAfterWrite"] = False
            client.bad(invalid)
            invalid = client.launch_command(artifact, limit=0)
            client.bad(invalid)
            invalid["maxRecordedInstructions"] = 1000001
            client.bad(invalid)
            client.launch(artifact)
            entry = client.observation
            assert cursor(entry) == "0", entry
            client.execute({"kind": "seekRecording", "instruction": "0"})
            status = client.good({"kind": "readRecording"})
            assert status["recording"] == client.observation["recording"]
            assert status["point"] == client.observation["point"] and status["stop"] == client.observation["stop"]
            client.bad({"kind": "appendInput", "id": "late-input", "text": "12 "}, ("UNSUPPORTED",))
            client.bad({"kind": "closeInput"}, ("UNSUPPORTED",))
            for instruction in ["-1", "0x10", "1\n-exec-continue", "18446744073709551616", 1]:
                client.bad({"kind": "seekRecording", "instruction": instruction})

            client.to_marker("value = 1;  // RECORD_SEQUENCE")
            checkpoints = [client.observation]
            assert value(checkpoints[0]) == 0
            for expected in (1, 2, 0):
                client.execute({"kind": "step", "stepKind": "over"})
                assert value(client.observation) == expected, client.observation
                checkpoints.append(client.observation)
            last = checkpoints[-1]
            client.execute({"kind": "reverseInstruction"})
            assert value(client.observation) == 2 and cursor(client.observation) == cursor(checkpoints[2])
            assert client.observation["reason"] == "reverse-step", client.observation
            stale = client.frame({"kind": "readRecording"})
            stale["expectedStop"] = last["stop"]
            rejected = client.send(stale)
            assert not rejected["ok"] and rejected["error"]["code"] == "STALE_CONTEXT", rejected
            for checkpoint in checkpoints:
                client.execute({"kind": "seekRecording", "instruction": cursor(checkpoint)})
                assert value(client.observation) == value(checkpoint)
                assert client.observation["reason"] == "recording-seek"
                assert client.observation["point"]["eventOrdinal"] > last["point"]["eventOrdinal"]
                assert client.good({"kind": "readHistory", "point": checkpoint["point"]})["observation"] == checkpoint
            unchanged = client.observation
            events = client.execute({"kind": "seekRecording", "instruction": str(int(cursor(last)) + 1)}, "failed")
            assert not any(event["payload"]["kind"] == "observation" for event in events)
            assert client.good({"kind": "getState"})["observation"] == unchanged

            client.launch(artifact, limit=4)
            client.execute({"kind": "traceInstructions", "count": 32, "memoryRanges": []})
            recording = client.observation["recording"]
            assert recording["evicted"] and recording["recordedInstructions"] == 4, recording
            earliest = recording["earliestSeekableInstruction"]
            unchanged = client.observation
            client.execute({"kind": "seekRecording", "instruction": str(int(earliest)-1)}, "failed")
            assert client.good({"kind": "getState"})["observation"] == unchanged
            client.execute({"kind": "seekRecording", "instruction": earliest})
            client.execute({"kind": "reverseInstruction"}, "failed")
            assert client.good({"kind": "getState"})["state"]["phase"] == "stopped"

            client.launch(artifact, mode="u")
            client.to_marker('asm volatile("ud2")')
            before_error = cursor(client.observation)
            # Current GDB rejects UD2 in its record decoder. On a future
            # decoder it may instead record it and stop with SIGILL.
            request = client.frame({"kind": "step", "stepKind": "instruction"})
            response = client.send(request)
            assert response["ok"], response
            events = []
            while True:
                event = client.recv(); events.append(event)
                if event["payload"]["kind"] == "observation":
                    client.observation = event["payload"]["observation"]
                if event["payload"]["kind"] == "commandFinished":
                    break
            assert events[-1]["payload"]["outcome"] in ("failed", "completed"), events
            assert client.good({"kind": "getState"})["state"]["phase"] == "stopped", events
            assert client.observation["recording"]["available"], events
            client.execute({"kind": "seekRecording", "instruction": str(int(before_error)-1)})

            client.launch(artifact, mode="o")
            client.to_marker("RECORD_OUTPUT_BEGIN")
            before_output = client.observation
            client.to_marker("value = static_cast<int>(result);")
            after_output = client.observation
            expected_bytes = b"o\x00\xff\n"
            def journal(point):
                result = client.good({"kind": "readOutputJournal", "stream": "stdout", "fromByte": 0,
                                      "byteCount": 64, "point": point})
                actual = b"".join(base64.b64decode(segment["bytesBase64"]) for segment in result["segments"])
                assert actual == expected_bytes and result["totalBytes"] == 4 and result["consistent"], result
                return result
            assert journal(before_output["point"])["selectedThroughByte"] == 0
            assert journal(after_output["point"])["selectedThroughByte"] == 4
            for checkpoint in (before_output, after_output, before_output, after_output):
                client.execute({"kind": "seekRecording", "instruction": cursor(checkpoint)})
                assert journal(client.observation["point"])["selectedThroughByte"] == checkpoint["outputCursor"]["stdoutThroughByte"]
                assert client.observation["stdout"]["totalBytes"] == 4
            assert client.good({"kind": "readHistory", "point": before_output["point"]})["observation"] == before_output
            # Instruction 1 was recorded between entry and the first explicit
            # checkpoint, but no output prefix was observed at that cursor.
            # Physical journal bytes remain known; their historical boundary
            # must stay unknown instead of being assigned the present total.
            assert int(cursor(before_output)) > 1
            client.execute({"kind": "seekRecording", "instruction": "1"})
            assert client.observation["outputCursor"] == {
                "source": "unknown", "stdoutThroughByte": None, "stderrThroughByte": None}, client.observation
            assert journal(client.observation["point"])["selectedThroughByte"] is None
            assert client.observation["stdout"]["totalBytes"] == 4
            client.execute({"kind": "seekRecording", "instruction": cursor(after_output)})

            # A control frame racing a recorder request terminates exactly
            # once and keeps a queryable checkpoint after cancellation.
            move = client.frame({"kind": "seekRecording", "instruction": cursor(before_output)})
            cancel = client.frame({"kind": "cancel", "targetRequestId": move["requestId"]})
            TRAFFIC.extend([("request", move), ("request", cancel)])
            client.send_many([move, cancel])
            terminals = {}
            while len(terminals) < 2:
                event = client.recv()
                if "requestId" in event:
                    assert event["ok"], event
                payload = event.get("payload", {})
                if payload.get("kind") == "observation":
                    client.observation = payload["observation"]
                if payload.get("kind") == "commandFinished":
                    assert payload["requestId"] not in terminals
                    terminals[payload["requestId"]] = payload
            assert terminals[move["requestId"]]["outcome"] == "cancelled", terminals
            assert client.good({"kind": "getState"})["state"]["phase"] == "stopped"
            journal(before_output["point"])

            client.launch(artifact, profile="native")
            native = client.observation
            status = client.good({"kind": "readRecording"})
            assert not status["recording"]["available"], status
            events = client.execute({"kind": "reverseInstruction"}, "failed")
            assert events[-1]["payload"]["error"]["code"] == "UNSUPPORTED", events
            assert client.good({"kind": "getState"})["observation"] == native
            client.execute({"kind": "step", "stepKind": "instruction"})
        finally:
            client.close()
    print("recording gateways: reverse/seek, immutable history, eviction, actual failure stops, external output, input policy, cancellation and native isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
