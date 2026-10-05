"""Headless build → GDB launch → step → variables → history smoke test.

This intentionally speaks the same NDJSON boundary as the frontend.  It
keeps the fixture small while checking identity propagation and that every
long-running command emits its terminal commandFinished event.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str, value=None) -> None:
    if value is not None:
        message += ": " + json.dumps(value, ensure_ascii=False)
    raise AssertionError(message)


def require_keys(value: dict, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label} keys do not match frontend DTO", {"expected": sorted(expected), "actual": sorted(actual)})


class Client:
    def __init__(self, executable: str, workspace: Path) -> None:
        self.process = subprocess.Popen(
            [executable, "--stdio", "--workspace", str(workspace)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def send(self, frame: dict) -> dict:
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.process.stdin.write(json.dumps(frame, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        return self.recv()

    def send_many(self, frames: list[dict]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write("".join(json.dumps(frame, separators=(",", ":")) + "\n" for frame in frames))
        self.process.stdin.flush()

    def recv(self) -> dict:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            fail("backend closed stdout", {"returncode": self.process.poll(), "stderr": stderr})
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            fail("backend emitted invalid JSON", {"line": line, "error": str(error)})

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: service_integration.py BACKEND", file=sys.stderr)
        return 2
    if shutil.which("gdb") is None:
        print("GDB is unavailable; integration test skipped")
        return 77

    with tempfile.TemporaryDirectory(prefix="phantom-service-test-") as directory:
        workspace = Path(directory)
        client = Client(sys.argv[1], workspace)
        try:
            connect = client.send({"kind": "connect", "supportedProtocolVersions": [1]})
            if not connect.get("ok"):
                fail("connect failed", connect)
            require_keys(
                connect,
                {"kind", "ok", "protocolVersion", "workspace", "session", "state", "observation", "capabilities", "throughSequence"},
                "connectResult",
            )
            caps = connect.get("capabilities", {})
            require_keys(
                caps,
                {
                    "protocolVersion", "backendName", "backendVersion", "architectures", "stepKinds",
                    "sourceBreakpoints", "conditionalBreakpoints", "hitCountBreakpoints", "variableWrite",
                    "inputTracking", "interactiveInput", "expressionGroups", "history", "restore", "asm", "memoryRead", "memoryMap",
                    "eventReplay", "limits", "addressProfiles", "addressPolicies", "processInspection",
                    "registerRead", "instructionTrace", "memoryCapture", "memoryMapDiff", "outputJournal", "moduleInspection", "moduleSymbols", "variableLayout", "vtableInspection", "memoryWrite", "scalarStorage", "scalarStorageProfiles", "interventionBranches", "recorderProbe", "recordingProfiles", "recordingCursor",
                },
                "BackendCapabilitiesDTO",
            )
            if caps.get("backendName") != "phantom-linux":
                fail("unexpected backend capability identity", caps)
            if caps.get("sourceBreakpoints") is not True:
                fail("source breakpoints are not advertised", caps)
            require_keys(
                caps["limits"],
                {"maxOutputBytes", "maxHistoryBytes", "maxResidentSnapshots", "maxVariablesPerPage",
                 "maxStringBytes", "maxMemoryReadBytes", "maxInstructionsPerRequest", "maxTraceInstructions",
                 "maxTraceMemoryBytes", "maxCaptureBytes", "maxInspectionStoreBytes", "maxOutputJournalBytesPerStream", "maxOutputJournalReadBytes", "maxRecordedInstructions", "maxMemoryWriteBytes", "maxMemoryInterventions", "maxInterventionStoreBytes",
                 "commandTimeoutMs", "replayTimeoutMs"},
                "ResourceLimitsDTO",
            )
            if caps["addressProfiles"] != ["native", "fixed-executable"] or \
                    caps["addressPolicies"] != ["native", "disable-aslr", "require-fixed"] or \
                    caps["processInspection"] != "linux-procfs" or \
                    caps["instructionTrace"] != "instruction-boundaries" or \
                    any(caps[field] is not True for field in ("registerRead", "memoryCapture", "memoryMapDiff")):
                fail("inspection capability values do not match the native gateway", caps)
            if any(type(value) is not int or value <= 0 for value in caps["limits"].values()):
                fail("resource limits must be positive integers", caps["limits"])

            common = {
                "protocolVersion": 1,
                "workspace": {"id": "workspace-local", "revisionId": "workspace-0"},
                "session": None,
            }
            no_session = client.send({**common, "requestId": "state-before-launch",
                                      "command": {"kind": "getState"}})
            if no_session.get("ok") or no_session.get("error", {}).get("code") != "STALE_CONTEXT":
                fail("getState before launch must return a v1 error instead of a null state result", no_session)
            source_text = (
                "int add(int a, int b) { return a + b; } // 😀\n"
                "int main() {\n"
                "  int value = add(2, 3);\n"
                "  value += 1;\n"
                "  return value;\n"
                "}\n"
            )
            document = {
                "documentId": "main",
                "revisionId": "rev-1",
                "path": "main.cpp",
                "text": source_text,
                "sha256": hashlib.sha256(source_text.encode()).hexdigest(),
            }
            helper_text = "int unused_helper() { return 0; }\n"
            helper_document = {
                "documentId": "helper",
                "revisionId": "rev-helper",
                "path": "helper.cpp",
                "text": helper_text,
                "sha256": hashlib.sha256(helper_text.encode()).hexdigest(),
            }
            configuration = {
                "revisionId": "config-1",
                "compiler": "clang++",
                "flags": ["-std=c++20", "-g", "-O0"],
                "outputDirectory": ".phantom/test-build",
            }
            build = client.send(
                {
                    **common,
                    "requestId": "build-1",
                    "command": {
                        "kind": "build",
                        "source": {"id": "source-1", "documents": [document, helper_document]},
                        "configuration": configuration,
                        "architecture": "x86_64",
                    },
                }
            )
            if not build.get("ok") or not build.get("result", {}).get("success"):
                fail("build failed", build)
            artifact = build["result"]["artifact"]
            require_keys(
                artifact,
                {"id", "sourceBundleId", "configurationRevisionId", "architecture", "targetTriple", "compiler",
                 "command", "binaryPath", "binarySha256", "debugSymbolsAvailable", "addressProfile", "elf"},
                "BuildArtifactDTO",
            )
            if artifact["addressProfile"] != "native" or artifact["elf"].get("available") is not True:
                fail("native artifact did not expose ELF evidence", artifact)
            require_keys(
                artifact["elf"],
                {"available", "format", "class", "endianness", "elfType", "elfTypeValue", "architecture",
                 "machine", "entryAddressHex", "programHeaders", "buildId"},
                "ElfInspectionDTO",
            )
            if artifact["elf"]["class"] != 64 or artifact["elf"]["architecture"] != "x86_64" or \
                    artifact["elf"]["elfType"] not in ("ET_DYN", "ET_EXEC"):
                fail("artifact contains unsupported executable metadata", artifact["elf"])
            if not Path(artifact["binaryPath"]).is_file():
                fail("build artifact is missing", artifact)

            launch_request = {
                **common,
                "requestId": "launch-1",
                "command": {
                    "kind": "launch",
                    "buildId": artifact["id"],
                    "input": {"id": "input-1", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                    "argv": [],
                    "environment": {},
                    "stopAtEntry": True,
                },
            }
            launch = client.send(launch_request)
            if not launch.get("ok") or launch.get("result", {}).get("kind") != "launchAccepted":
                fail("launch was not accepted", launch)
            event_frames = [client.recv() for _ in range(3)]
            if [frame.get("payload", {}).get("kind") for frame in event_frames] != [
                "observation", "state", "commandFinished"
            ]:
                fail("launch event sequence is incomplete", event_frames)
            observation = event_frames[0]["payload"]["observation"]
            require_keys(
                observation,
                {"id", "point", "stop", "processInstanceId", "buildId", "sourceBundleId", "reason", "location", "threadId", "stack", "input", "stdout", "stderr", "expressions", "coverage", "memoryMap", "executionLayout", "outputCursor", "osEvidenceScope"},
                "StopObservationDTO",
            )
            layout = observation["executionLayout"]
            require_keys(
                layout,
                {"addressPolicy", "elfType", "aslr", "addresses", "processStartTimeTicks", "runFingerprint",
                 "allocatorDeterminism", "replayVerified"},
                "ExecutionLayoutDTO",
            )
            require_keys(layout["aslr"],
                         {"requestedDisabled", "verifiedDisabled", "evidence", "personalityMaskHex"}, "AslrEvidenceDTO")
            if layout["addressPolicy"] != "disable-aslr" or layout["aslr"]["requestedDisabled"] is not True or \
                    layout["elfType"] != artifact["elf"]["elfType"] or \
                    layout["allocatorDeterminism"] != "not-established" or layout["replayVerified"] is not False:
                fail("launch layout overstates address guarantees or loses the requested policy", layout)
            if layout["aslr"]["evidence"] == "unavailable":
                if layout["aslr"]["verifiedDisabled"] is not None or layout["aslr"]["personalityMaskHex"] is not None:
                    fail("unavailable ASLR evidence must be null", layout)
            elif layout["aslr"]["evidence"] != "linux-proc-personality" or \
                    type(layout["aslr"]["verifiedDisabled"]) is not bool or \
                    not isinstance(layout["aslr"]["personalityMaskHex"], str):
                fail("verified ASLR evidence has an invalid shape", layout)
            require_keys(event_frames[1]["payload"]["state"], {"session", "phase", "processInstanceId", "buildId", "live", "exit"}, "DebugSessionStateDTO")
            require_keys(
                event_frames[2]["payload"],
                {"kind", "requestId", "outcome"},
                "CommandFinishedEventDTO",
            )
            require_keys(event_frames[0], {"protocolVersion", "workspace", "session", "processInstanceId", "sequence", "payload", "causedByRequestId"}, "BackendEventDTO")
            if observation["sourceBundleId"] != "source-1":
                fail("source identity was not preserved", observation)
            location = observation.get("location")
            if not location or location["documentId"] != "main" or location["revisionId"] != "rev-1":
                fail("GDB location was not mapped to submitted source", location)
            expected_main_offset = len("int add(int a, int b) { return a + b; } // 😀\nint main() {\n".encode("utf-16-le")) // 2
            if location["range"]["start"] != expected_main_offset or location["range"]["end"] != expected_main_offset:
                fail("Unicode before GDB location produced an invalid UTF-16 offset", location)
            if observation["input"]["submitted"]["id"] != "input-1":
                fail("submitted input identity was lost", observation["input"])

            session = launch["session"]
            line_three_prefix = "int add(int a, int b) { return a + b; } // 😀\nint main() {\n"
            line_three_offset = len(line_three_prefix.encode("utf-16-le")) // 2
            breakpoints = client.send(
                {
                    **common,
                    "requestId": "breakpoints-1",
                    "session": session,
                    "command": {
                        "kind": "setBreakpoints",
                        "documentId": "main",
                        "revisionId": "rev-1",
                        "breakpoints": [
                            {
                                "id": "bp-1",
                                "range": {
                                    "documentId": "main",
                                    "revisionId": "rev-1",
                                    "range": {"start": line_three_offset, "end": line_three_offset},
                                    "start": {"line": 3, "column": 1},
                                    "end": {"line": 3, "column": 1},
                                },
                                "enabled": True,
                            }
                        ],
                    },
                }
            )
            if not breakpoints.get("ok") or not breakpoints.get("result", {}).get("breakpoints", [{}])[0].get("verified"):
                fail("source breakpoint was not verified", breakpoints)
            step = client.send(
                {
                    **common,
                    "requestId": "step-1",
                    "session": session,
                    "expectedStop": observation["stop"],
                    "command": {"kind": "step", "stepKind": "over"},
                }
            )
            if not step.get("ok") or step.get("result", {}).get("kind") != "accepted":
                fail("step was not accepted", step)
            step_events = [client.recv() for _ in range(3)]
            if [frame.get("payload", {}).get("kind") for frame in step_events] != [
                "observation", "state", "commandFinished"
            ]:
                fail("step event sequence is incomplete", step_events)
            step_observation = step_events[0]["payload"]["observation"]

            variables = client.send(
                {
                    **common,
                    "requestId": "variables-1",
                    "session": session,
                    "expectedStop": step_observation["stop"],
                    "command": {"kind": "readVariables", "reference": "frame:0", "start": 0, "count": 16},
                }
            )
            if not variables.get("ok") or not isinstance(variables.get("result", {}).get("variables"), list):
                fail("variables response has the wrong shape", variables)

            stale_session = {"id": session["id"], "generation": session["generation"] + 1}
            stale_read = client.send(
                {
                    **common,
                    "requestId": "variables-stale-session",
                    "session": stale_session,
                    "expectedStop": step_observation["stop"],
                    "command": {"kind": "readVariables", "reference": "frame:0", "start": 0, "count": 1},
                }
            )
            if stale_read.get("ok") or stale_read.get("error", {}).get("code") != "STALE_CONTEXT":
                fail("stale session was accepted", stale_read)

            state = client.send(
                {
                    **common,
                    "requestId": "state-1",
                    "session": session,
                    "command": {"kind": "getState"},
                }
            )
            if not state.get("ok") or state.get("result", {}).get("state", {}).get("phase") != "stopped":
                fail("getState did not return the current stopped state", state)

            replay = client.send(
                {
                    **common,
                    "requestId": "replay-1",
                    "session": session,
                    "command": {"kind": "replayEvents", "afterSequence": 0},
                }
            )
            if not replay.get("ok") or len(replay.get("result", {}).get("events", [])) < 3:
                fail("event replay did not retain the launch/step checkpoint", replay)

            history = client.send(
                {
                    **common,
                    "requestId": "history-1",
                    "session": session,
                    "command": {"kind": "listHistory", "branchId": "main", "afterOrdinal": None, "limit": 16},
                }
            )
            items = history.get("result", {}).get("items", [])
            if not history.get("ok") or len(items) < 2:
                fail("history did not retain launch and step", history)
            first_page = client.send({
                **common, "requestId": "history-page-1", "session": session,
                "command": {"kind": "listHistory", "branchId": "main", "afterOrdinal": None, "limit": 1},
            })
            if not first_page.get("ok") or len(first_page["result"]["items"]) != 1 or not first_page["result"]["hasMore"]:
                fail("history pagination did not report a remaining page", first_page)

            stop = client.send(
                {
                    **common,
                    "requestId": "stop-1",
                    "session": session,
                    "command": {"kind": "stop"},
                }
            )
            if not stop.get("ok") or stop.get("result", {}).get("kind") != "accepted":
                fail("stop was not accepted", stop)
            stop_events = [client.recv() for _ in range(3)]
            if stop_events[-1].get("payload", {}).get("kind") != "commandFinished":
                fail("stop did not finish", stop_events)

            # Put a long-running execution and its control frame in the same
            # stdin write. The reader must wait for the worker to publish the
            # active request, then interrupt that request rather than letting
            # pause sit behind a blocked continue in the serialized queue.
            loop_text = "int main() { for (;;) {} }\n"
            loop_document = {**document, "path": "loop.cpp", "documentId": "loop", "revisionId": "rev-loop",
                             "text": loop_text, "sha256": hashlib.sha256(loop_text.encode()).hexdigest()}
            loop_build = client.send(
                {
                    **common,
                    "requestId": "build-loop",
                    "command": {
                        "kind": "build",
                        "source": {"id": "source-loop", "documents": [loop_document]},
                        "configuration": {**configuration, "revisionId": "config-loop"},
                        "architecture": "x86_64",
                    },
                }
            )
            if not loop_build.get("ok") or not loop_build["result"].get("success"):
                fail("loop fixture build failed", loop_build)
            loop_launch = client.send(
                {
                    **common,
                    "requestId": "launch-loop",
                    "command": {
                        "kind": "launch",
                        "buildId": loop_build["result"]["artifact"]["id"],
                        "input": {"id": "input-loop", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                        "argv": [], "environment": {}, "stopAtEntry": True,
                    },
                }
            )
            loop_launch_events = [client.recv() for _ in range(3)]
            loop_session = loop_launch["session"]
            loop_stop_ref = loop_launch_events[0]["payload"]["observation"]["stop"]
            # A source-level step on a loop whose body and condition share one
            # line has no different line at which GDB can complete `next`.
            # The backend must interrupt that attempt, preserve a live stopped
            # checkpoint, and report the step as incomplete instead of killing
            # the session after the general command timeout.
            same_line_step = client.send({
                **common, "requestId": "step-same-line", "session": loop_session,
                "expectedStop": loop_stop_ref,
                "command": {"kind": "step", "stepKind": "over"},
            })
            if not same_line_step.get("ok") or same_line_step.get("result", {}).get("kind") != "accepted":
                fail("same-line step was not accepted", same_line_step)
            same_line_events = [client.recv() for _ in range(3)]
            if [frame.get("payload", {}).get("kind") for frame in same_line_events] != [
                    "observation", "state", "commandFinished"]:
                fail("same-line step event sequence is incomplete", same_line_events)
            same_line_observation = same_line_events[0]["payload"]["observation"]
            same_line_finished = same_line_events[-1]["payload"]
            if same_line_observation.get("reason") != "step-timeout" or \
                    same_line_finished.get("outcome") != "failed" or \
                    same_line_finished.get("error", {}).get("code") != "STEP_TIMEOUT":
                fail("same-line step was not surfaced as an incomplete stopped checkpoint", same_line_events)
            if same_line_events[1]["payload"]["state"].get("phase") != "stopped":
                fail("same-line step invalidated the live session", same_line_events[1])
            loop_stop_ref = same_line_observation["stop"]
            client.send_many(
                [
                    {**common, "requestId": "continue-loop", "session": loop_session, "expectedStop": loop_stop_ref, "command": {"kind": "continue"}},
                    {**common, "requestId": "pause-loop", "session": loop_session, "command": {"kind": "pause"}},
                ]
            )
            continue_ack = client.recv()
            if not continue_ack.get("ok") or continue_ack.get("result", {}).get("kind") != "accepted":
                fail("same-packet continue was not accepted", continue_ack)
            loop_events = [client.recv() for _ in range(3)]
            if loop_events[-1].get("payload", {}).get("kind") != "commandFinished":
                fail("same-packet pause did not finish the continue", loop_events)
            pause_ack = client.recv()
            pause_finished = client.recv()
            if not pause_ack.get("ok") or pause_ack.get("result", {}).get("kind") != "accepted" or \
                    pause_finished.get("payload", {}).get("kind") != "commandFinished":
                fail("same-packet pause acknowledgement was malformed", {"ack": pause_ack, "finished": pause_finished})
            loop_stop = client.send(
                {**common, "requestId": "stop-loop", "session": loop_session, "command": {"kind": "stop"}}
            )
            if not loop_stop.get("ok"):
                fail("loop cleanup stop was not accepted", loop_stop)
            [client.recv() for _ in range(3)]

            # A second session exercises the binary pipe transport. The
            # backend promises bytes written to stdin, not extraction events,
            # and keeps stdout/stderr as separate bounded snapshots.
            io_text = (
                "#include <iostream>\n"
                "#include <cstdlib>\n"
                "int main() { int value = 0; std::cin >> value; const char* tag = std::getenv(\"PHANTOM_ENV\"); "
                "std::cout << value + 1 << \":\" << (tag ? tag : \"missing\") << \"\\n\"; "
                "std::cerr << \"diagnostic\\n\"; }\n"
            )
            io_document = {**document, "text": io_text, "sha256": hashlib.sha256(io_text.encode()).hexdigest()}
            io_build = client.send(
                {
                    **common,
                    "requestId": "build-io",
                    "command": {
                        "kind": "build",
                        "source": {"id": "source-io", "documents": [io_document]},
                        "configuration": {**configuration, "revisionId": "config-io"},
                        "architecture": "x86_64",
                    },
                }
            )
            if not io_build.get("ok") or not io_build["result"].get("success"):
                fail("IO fixture build failed", io_build)
            io_launch = client.send(
                {
                    **common,
                    "requestId": "launch-io",
                    "command": {
                        "kind": "launch",
                        "buildId": io_build["result"]["artifact"]["id"],
                        # No trailing newline is valid pipe input. The feeder
                        # closes stdin after the exact bytes are delivered.
                        "input": {"id": "input-io", "text": "41", "encoding": "utf-8", "closeAfterWrite": True},
                        "argv": [],
                        # PATH is intentionally target-only: GDB must still
                        # start using the backend environment, while the
                        # inferior receives both requested variables.
                        "environment": {"PATH": "/phantom/no-such-bin", "PHANTOM_ENV": "hello world"},
                        "stopAtEntry": True,
                    },
                }
            )
            io_events = [client.recv() for _ in range(3)]
            if [frame.get("sequence") for frame in io_events] != [1, 2, 3]:
                fail("new session did not reset its event sequence", io_events)
            io_observation = io_events[0]["payload"]["observation"]
            if io_observation["input"]["tracking"] != "transport-only" or io_observation["input"]["deliveredBytes"] != 2:
                fail("pipe input accounting is incorrect", io_observation["input"])
            io_continue = client.send(
                {
                    **common,
                    "requestId": "continue-io",
                    "session": io_launch["session"],
                    "expectedStop": io_observation["stop"],
                    "command": {"kind": "continue"},
                }
            )
            if not io_continue.get("ok"):
                fail("IO fixture continue failed", io_continue)
            io_exit_events = [client.recv() for _ in range(3)]
            io_exit = io_exit_events[0]["payload"]["observation"]
            if io_exit["reason"] != "exit" or io_exit["stdout"]["text"] != "42:hello world\n":
                fail("pipe output/EOF result is incorrect", io_exit)
            if io_exit["stderr"]["text"] != "diagnostic\n":
                fail("stdout and stderr were not captured separately", io_exit)
            if "exited" in io_exit or "exitCode" in io_exit:
                fail("internal GDB stop fields leaked into the v1 observation DTO", io_exit)
            io_exit_state = io_exit_events[1]["payload"]["state"]
            if io_exit_state.get("phase") != "terminated" or io_exit_state.get("live") is not None or set(io_exit_state.get("exit", {})) != {"code", "signal"}:
                fail("terminated state did not expose an exit record", io_exit_state)

            # Pipes have no terminal MAX_CANON line limit. A long payload is
            # accepted, delivered byte-for-byte, and still gets deterministic
            # EOF after the entry stop.
            too_long = client.send(
                {
                    **common,
                    "requestId": "launch-io-too-long",
                    "command": {
                        "kind": "launch",
                        "buildId": io_build["result"]["artifact"]["id"],
                        "input": {"id": "input-too-long", "text": "x" * 4096, "encoding": "utf-8", "closeAfterWrite": True},
                        "argv": [],
                        "environment": {},
                        "stopAtEntry": True,
                    },
                }
            )
            if not too_long.get("ok"):
                fail("overlong pipe input was rejected", too_long)
            too_long_events = [client.recv() for _ in range(3)]
            too_long_observation = too_long_events[0]["payload"]["observation"]
            if too_long_observation["input"]["deliveredBytes"] != 4096:
                fail("long pipe input was not fully delivered", too_long_observation["input"])
        finally:
            client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
