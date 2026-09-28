"""Public-protocol acceptance checks for native interactive C++ stdin.

Every input wait ends its execution request. Appending bytes does not execute
code: the client must issue the next Step/Continue using the same stop token.
Transport exposure is tested independently of semantic extraction tracking.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import time
from pathlib import Path

from service_integration import Client, fail


SOURCE = r'''#include <iostream>
#include <string>
#include <unistd.h>

// A user function name must not be mistaken for a standard-input operation.
void getline() {
  int descriptors[2];
  if (pipe(descriptors) != 0) return;
  char character;
  read(descriptors[0], &character, 1);
  close(descriptors[0]);
  close(descriptors[1]);
}

int nested_input() {
  int nested = 0;
  std::cin >> nested;
  nested += 1; // nested-after-read
  return nested;
}

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "integer";
  if (mode == "integer") {
    int x = 0;
    std::cin >> x;
    std::cout << "x=" << x << "\n"; // integer-after-read
  } else if (mode == "double") {
    int first = 0, second = 0;
    std::cin >> first;
    std::cout << "first=" << first << "\n";
    std::cin >> second;
    std::cout << "second=" << second << "\n";
  } else if (mode == "getline") {
    std::string text;
    std::getline(std::cin, text);
    std::cout << "line=[" << text << "]\n";
  } else if (mode == "integer-line") {
    int number = 0;
    std::string text;
    std::cin >> number;
    std::getline(std::cin, text);
    std::cout << "number=" << number << ";remainder=[" << text << "]\n";
  } else if (mode == "invalid") {
    int first = 91, second = 37;
    std::cin >> first;
    const bool failed = std::cin.fail();
    std::cin >> second;
    std::cout << "failed=" << failed << ";stillFailed=" << std::cin.fail()
              << ";second=" << second << ";eof=" << std::cin.eof() << "\n";
  } else if (mode == "unicode") {
    std::string text;
    std::cin >> text;
    std::cout << "unicode=" << text << "\n";
  } else if (mode == "tail") { int value = 73; std::cin >> value;
  } else if (mode == "nested") {
    const int result = nested_input();
    std::cout << "nested=" << result << "\n";
  } else if (mode == "eof") {
    int value = 73;
    std::cin >> value;
    std::cout << "eof=" << std::cin.eof() << ";failed=" << std::cin.fail() << "\n";
  } else if (mode == "other-pipe") {
    getline(); // unrelated-blocking-read
  }
}
'''


def source_line(marker: str) -> int:
    return next(index for index, line in enumerate(SOURCE.splitlines(), 1) if marker in line)


def events(client: Client, request_id: str) -> tuple[dict, dict, dict]:
    frames = [client.recv() for _ in range(3)]
    kinds = [frame.get("payload", {}).get("kind") for frame in frames]
    if kinds != ["observation", "state", "commandFinished"]:
        fail("unexpected execution event sequence", {"requestId": request_id, "frames": frames})
    finished = frames[-1]["payload"]
    if finished.get("requestId") != request_id:
        fail("execution completion belongs to another request", finished)
    return frames[0]["payload"]["observation"], frames[1]["payload"]["state"], finished


def assert_wait(observation: dict, state: dict, finished: dict, function: str = "main") -> None:
    if (observation.get("reason") != "input-wait"
            or observation.get("input", {}).get("status") != "waiting"
            or state.get("phase") != "waitingForInput"
            or finished.get("outcome") != "waiting"):
        fail("blocked stdin did not finish with an input-wait checkpoint", {
            "observation": observation, "state": state, "finished": finished})
    user_frames = [frame for frame in observation.get("stack", [])
                   if isinstance(frame.get("location"), dict)
                   and frame["location"].get("documentId") == "main"]
    if not any(frame.get("functionName") == function and frame.get("variables") for frame in user_frames):
        fail("input wait lost the requesting user frame or its locals", {"function": function, "observation": observation})
    if observation.get("input", {}).get("eof") != "open":
        fail("empty input implicitly requested EOF", observation)


def assert_exit(observation: dict, state: dict, finished: dict, stdout: str) -> None:
    if (state.get("phase") != "terminated" or finished.get("outcome") != "completed"
            or observation.get("stdout", {}).get("text") != stdout):
        fail("input fixture did not finish with the expected exact output", {
            "expected": stdout, "observation": observation, "state": state, "finished": finished})


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: interactive_input_integration.py BACKEND", file=sys.stderr)
        return 2
    if shutil.which("gdb") is None:
        print("GDB is unavailable; integration test skipped")
        return 77

    with tempfile.TemporaryDirectory(prefix="phantom-interactive-input-") as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            connect = client.send({"kind": "connect", "supportedProtocolVersions": [1]})
            if not connect.get("ok"):
                fail("connect failed", connect)
            common = {"protocolVersion": 1, "workspace": connect["workspace"], "session": None}
            sequence = 0

            def send(command: dict, session=None, stop=None) -> tuple[str, dict]:
                nonlocal sequence
                sequence += 1
                request_id = f"input-{sequence}-{command['kind']}"
                frame = {**common, "requestId": request_id, "session": session, "command": command}
                if stop is not None:
                    frame["expectedStop"] = stop
                return request_id, client.send(frame)

            def successful(command: dict, session=None, stop=None) -> tuple[str, dict]:
                request_id, response = send(command, session, stop)
                if not response.get("ok"):
                    fail("interactive input request was rejected", {"command": command, "response": response})
                return request_id, response

            def build_source(source: str, name: str) -> str:
                document = {"documentId": "main", "revisionId": name + "-revision", "path": "main.cpp",
                            "text": source, "sha256": hashlib.sha256(source.encode()).hexdigest()}
                _, build = successful({
                    "kind": "build", "source": {"id": name + "-source", "documents": [document]},
                    "configuration": {"revisionId": name + "-config", "compiler": "clang++",
                                      "flags": ["-std=c++20", "-g", "-O0"],
                                      "outputDirectory": ".phantom/interactive-" + name},
                    "architecture": "x86_64"})
                if not build.get("result", {}).get("success"):
                    fail("input fixture build failed", build)
                return build["result"]["artifact"]["id"]

            build_id = build_source(SOURCE, "input")

            def launch(mode: str, text: str = "") -> tuple[dict, dict]:
                request_id, response = successful({
                    "kind": "launch", "buildId": build_id,
                    "input": {"id": f"initial-{sequence}", "text": text,
                              "encoding": "utf-8", "closeAfterWrite": False},
                    "argv": [mode], "environment": {}, "stopAtEntry": True})
                observation, _, _ = events(client, request_id)
                return observation, response["session"]

            def execute(session: dict, observation: dict, kind="continue") -> tuple[dict, dict, dict]:
                command = {"kind": kind}
                if kind == "step":
                    command["stepKind"] = "over"
                request_id, _ = successful(command, session, observation["stop"])
                return events(client, request_id)

            def append(session: dict, observation: dict, chunk_id: str, text: str) -> dict:
                _, response = successful({"kind": "appendInput", "id": chunk_id, "text": text},
                                         session, observation["stop"])
                return response["result"]["input"]

            def history(session: dict, observation: dict) -> dict:
                _, response = successful({"kind": "readHistory", "point": observation["point"]}, session)
                return response["result"]["observation"]

            # Stepping a cin expression with no input must stop in a reusable
            # user context. Resume with Step, not Continue: stepping libc would
            # return the wrong source location and run past the requested line.
            observation, session = launch("integer")
            entry_stop = observation["stop"]
            for _ in range(12):
                observation, state, finished = execute(session, observation, "step")
                if observation.get("reason") == "input-wait":
                    break
            else:
                fail("empty-cin Step never reached input wait", observation)
            assert_wait(observation, state, finished)
            # Waiting is already a real debugger stop. Pause acknowledges it
            # without creating another observation or changing its stop token.
            before_pause = observation
            before_pause_state = state
            pause_started = time.monotonic()
            pause_id, _ = successful({"kind": "pause"}, session, observation["stop"])
            pause_event = client.recv().get("payload", {})
            if (pause_event.get("kind") != "commandFinished" or pause_event.get("requestId") != pause_id
                    or pause_event.get("outcome") != "completed"):
                fail("Pause at input wait produced a new stop instead of completion", pause_event)
            if time.monotonic() - pause_started >= 3:
                fail("Pause waited on an already stopped input request")
            _, current = successful({"kind": "getState"}, session)
            if (current.get("result", {}).get("state") != before_pause_state
                    or current.get("result", {}).get("observation") != before_pause):
                fail("Pause changed the input-wait checkpoint", current)
            # Repeating Step without adding bytes must remain a recoverable
            # cin wait, including after recovery itself was interrupted.
            for _ in range(2):
                observation, state, finished = execute(session, observation, "step")
                assert_wait(observation, state, finished)
            before_append = history(session, observation)
            if before_append != observation:
                fail("new input-wait history snapshot differs from live observation", before_append)
            revision = observation["input"]["revision"]
            chunk = append(session, observation, "integer-42", "42 ")
            if (chunk.get("deliveredBytes") != 3 or chunk.get("revision", {}).get("text") != "42 "
                    or chunk["revision"].get("parentId") != revision["id"]):
                fail("append did not acknowledge an exact child input revision", chunk)
            retry = append(session, observation, "integer-42", "42 ")
            if retry != chunk:
                fail("same chunk retry duplicated input or changed its revision", {"first": chunk, "retry": retry})
            _, conflict = send({"kind": "appendInput", "id": "integer-42", "text": "43 "}, session, observation["stop"])
            if conflict.get("ok") or conflict.get("error", {}).get("code") != "STALE_CONTEXT":
                fail("conflicting chunk retry was not rejected", conflict)
            _, stale = send({"kind": "appendInput", "id": "stale", "text": "999 "}, session, entry_stop)
            if stale.get("ok") or stale.get("error", {}).get("code") != "STALE_CONTEXT":
                fail("stale expectedStop was allowed to mutate input", stale)
            if history(session, observation) != before_append:
                fail("append mutated an already published history snapshot", history(session, observation))
            after, state, finished = execute(session, observation, "step")
            if (state.get("phase") != "stopped" or finished.get("outcome") != "completed"
                    or (after.get("location") or {}).get("start", {}).get("line") != source_line("integer-after-read")):
                fail("Step after cin wait did not reach the next user source line", {
                    "observation": after, "state": state, "finished": finished})
            main_frame = next((frame for frame in after.get("stack", []) if frame.get("functionName") == "main"), {})
            x = next((variable for variable in main_frame.get("variables", []) if variable.get("name") == "x"), {})
            if x.get("value", {}).get("value", {}).get("decimal") != "42":
                fail("resumed Step lost the extracted integer in the main frame", after)
            assert_exit(*execute(session, after), "x=42\n")

            # Two separate reads, each satisfied by an exact SPACE-terminated
            # token. No newline is required and none may be inserted.
            observation, session = launch("double")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            append(session, observation, "first-token", "12 ")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            if observation["stdout"]["text"] != "first=12\n":
                fail("first extraction was not completed before the second wait", observation)
            if observation["input"]["revision"]["text"] != "12 ":
                fail("input changed the explicit separator", observation["input"])
            append(session, observation, "second-token", "34 ")
            assert_exit(*execute(session, observation), "first=12\nsecond=34\n")

            # Leading, repeated and trailing spaces belong to getline. A
            # preceding formatted extraction leaves its delimiter unread.
            for mode, text, expected in [
                ("getline", "  Ivan  Petrov \n", "line=[  Ivan  Petrov ]\n"),
                ("integer-line", "7  untouched remainder \n", "number=7;remainder=[  untouched remainder ]\n"),
                ("integer-line", "7\n", "number=7;remainder=[]\n"),
            ]:
                observation, session = launch(mode)
                observation, state, finished = execute(session, observation)
                assert_wait(observation, state, finished)
                append(session, observation, f"line-{sequence}", text)
                assert_exit(*execute(session, observation), expected)

            # Invalid data must retain ordinary failbit behavior: a second
            # extraction cannot consume the following valid number implicitly.
            observation, session = launch("invalid")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            append(session, observation, "invalid-data", "oops 55 ")
            assert_exit(*execute(session, observation), "failed=1;stillFailed=1;second=37;eof=0\n")

            # Waiting and submitting an empty chunk never close stdin. Only
            # the explicit close request lets this extraction observe EOF.
            observation, session = launch("eof")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            empty = append(session, observation, "empty-chunk", "")
            if empty.get("eof") != "open" or empty.get("deliveredBytes") != 0:
                fail("empty chunk changed the stream into EOF", empty)
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            _, close = successful({"kind": "closeInput"}, session, observation["stop"])
            if close.get("result", {}).get("input", {}).get("eof") != "requested":
                fail("explicit EOF was not acknowledged", close)
            _, close_retry = successful({"kind": "closeInput"}, session, observation["stop"])
            if close_retry["result"]["input"] != close["result"]["input"]:
                fail("repeated close changed input state", close_retry)
            _, after_eof = send({"kind": "appendInput", "id": "after-eof", "text": "42 "},
                                session, observation["stop"])
            if after_eof.get("ok") or after_eof.get("error", {}).get("code") != "STALE_CONTEXT":
                fail("append reopened stdin after explicit EOF", after_eof)
            _, still_closed = successful({"kind": "closeInput"}, session, observation["stop"])
            if still_closed["result"]["input"] != close["result"]["input"]:
                fail("rejected append after EOF mutated the input revision", still_closed)
            after, state, finished = execute(session, observation)
            assert_exit(after, state, finished, "eof=1;failed=1\n")
            if after["input"].get("eof") not in {"requested", "observed"}:
                fail("EOF provenance disappeared from the final observation", after)

            # Native transport reports exposed ranges in UTF-16 UI units,
            # even though deliveredBytes counts UTF-8 bytes. No semantic
            # capability gate: exposing bytes does not prove extraction.
            observation, session = launch("unicode")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished)
            unicode_text = "😀Ж "
            previous_revision = observation["input"]["revision"]
            chunk = append(session, observation, "unicode-token", unicode_text)
            if (chunk.get("deliveredBytes") != len(unicode_text.encode("utf-8"))
                    or chunk.get("revision", {}).get("text") != unicode_text
                    or chunk["revision"].get("parentId") != previous_revision["id"]
                    or chunk.get("exposedRanges") != [{"start": 0, "end": 4}]):
                fail("native Unicode input revision/exposure has invalid units", chunk)
            if chunk.get("tracking") == "transport-only" and chunk.get("consumedRanges") is not None:
                fail("transport-only input fabricated semantic consumption ranges", chunk)
            assert_exit(*execute(session, observation), "unicode=😀Ж\n")

            # Recovery completes the pending call before normal source
            # stepping, including an extraction at the end of a branch.
            observation, session = launch("tail")
            for _ in range(12):
                observation, state, finished = execute(session, observation, "step")
                if observation.get("reason") == "input-wait":
                    break
            else:
                fail("same-line tail extraction never reached input wait", observation)
            assert_wait(observation, state, finished)
            append(session, observation, "tail-value", "5 ")
            after, state, finished = execute(session, observation, "step")
            if (state.get("phase") != "stopped" or finished.get("outcome") != "completed"
                    or after.get("location") is None):
                fail("same-line recovery did not produce a bounded source stop", {
                    "observation": after, "state": state, "finished": finished})
            assert_exit(*execute(session, after), "")

            # The requesting user frame can be nested below main. Recovery
            # must return to that frame's next statement without running the
            # rest of the helper or stepping directly back into its caller.
            observation, session = launch("nested")
            observation, state, finished = execute(session, observation)
            assert_wait(observation, state, finished, "nested_input")
            append(session, observation, "nested-value", "41 ")
            after, state, finished = execute(session, observation, "step")
            frame = next((frame for frame in after.get("stack", [])
                          if frame.get("functionName") == "nested_input"), {})
            nested = next((variable for variable in frame.get("variables", [])
                           if variable.get("name") == "nested"), {})
            if (state.get("phase") != "stopped" or finished.get("outcome") != "completed"
                    or (after.get("location") or {}).get("start", {}).get("line") != source_line("nested-after-read")
                    or nested.get("value", {}).get("value", {}).get("decimal") != "41"):
                fail("Step after nested cin wait lost its original user frame", {
                    "observation": after, "state": state, "finished": finished})
            assert_exit(*execute(session, after), "nested=42\n")

            # A read from an unrelated empty pipe, even through a user
            # function called getline, is a source-step timeout, not cin wait.
            observation, session = launch("other-pipe")
            for _ in range(24):
                observation, state, finished = execute(session, observation, "step")
                if finished.get("outcome") != "completed":
                    break
            else:
                fail("unrelated blocking pipe never reached a bounded step timeout", observation)
            if (observation.get("reason") != "step-timeout"
                    or state.get("phase") != "stopped"
                    or finished.get("error", {}).get("code") != "STEP_TIMEOUT"
                    or observation.get("input", {}).get("status") == "waiting"):
                fail("unrelated pipe or user getline was misclassified as stdin wait", {
                    "observation": observation, "state": state, "finished": finished})
            execute(session, observation, "stop")

            # This compilation unit has no source line after cin at all.
            # A fabricated line+1 destination would fail to resolve; native
            # call completion must allow normal function return instead.
            build_id = build_source("#include <iostream>\nint main() { int value = 0; std::cin >> value; }\n", "one-line")
            observation, session = launch("one-line")
            observation, state, finished = execute(session, observation, "step")
            assert_wait(observation, state, finished)
            append(session, observation, "last-expression", "9 ")
            after, state, finished = execute(session, observation, "step")
            if finished.get("outcome") != "completed" or state.get("phase") not in {"stopped", "terminated"}:
                fail("cin at the end of one-line main could not resume", {
                    "observation": after, "state": state, "finished": finished})
            if state["phase"] == "stopped":
                after, state, finished = execute(session, after)
            assert_exit(after, state, finished, "")
            if state.get("exit", {}).get("code") != 0:
                fail("one-line main did not return normally", state)
        finally:
            client.close()
    print("interactive input integration passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
