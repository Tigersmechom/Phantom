"""Exercise inferior pipe I/O through the public NDJSON boundary and real GDB.

Input is fixed UTF-8 text, but its encoded bytes include NUL and control bytes.
The delivered counter measures writes into the pipe, not inferior consumption.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

from service_integration import Client, fail


SOURCE = r"""#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

bool write_all(int fd, const char* bytes, std::size_t size) {
  while (size != 0) {
    const auto written = ::write(fd, bytes, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return false;
    bytes += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

int main(int argc, char** argv) {
  if (argc < 2) return 90;
  if (std::strcmp(argv[1], "early-close") == 0) {
    ::close(STDIN_FILENO);
    if (!write_all(STDOUT_FILENO, "closed\n", 7)) return 91;
    if (!write_all(STDERR_FILENO, "unread\n", 7)) return 92;
    return 23;
  }
  if (std::strcmp(argv[1], "invalid-utf8") == 0) {
    const char out[] = {char(0xff), char(0xfe), char(0x80), '\n'};
    const char err[] = {char(0xc0), char(0xaf), '\n'};
    return write_all(STDOUT_FILENO, out, sizeof(out)) &&
           write_all(STDERR_FILENO, err, sizeof(err)) ? 0 : 93;
  }
  if (std::strcmp(argv[1], "arguments-environment") == 0) {
    for (int i = 2; i < argc; ++i)
      if (!write_all(STDOUT_FILENO, argv[i], std::strlen(argv[i]) + 1)) return 91;
    const char* names[] = {"BASH_ENV", "SHELL", "PATH", "PHANTOM_ENV", "EMPTY",
                          "PHANTOM_STDIN_FIFO", "PHANTOM_STDOUT_FIFO",
                          "PHANTOM_STDERR_FIFO", "PHANTOM_READY_FIFO"};
    for (const char* name : names) {
      const char* value = std::getenv(name);
      if (!value) value = "<missing>";
      if (!write_all(STDOUT_FILENO, value, std::strlen(value) + 1)) return 92;
    }
    return write_all(STDERR_FILENO, "environment\n", 12) ? 0 : 93;
  }
  if (std::strcmp(argv[1], "flood") == 0) {
    if (argc != 3) return 90;
    auto remaining = std::strtoul(argv[2], nullptr, 10);
    char out[4096], err[4096];
    std::memset(out, 'O', sizeof(out));
    std::memset(err, 'E', sizeof(err));
    while (remaining != 0) {
      const auto count = remaining < sizeof(out) ? remaining : sizeof(out);
      if (!write_all(STDOUT_FILENO, out, count)) return 94;
      if (!write_all(STDERR_FILENO, err, count)) return 95;
      remaining -= count;
    }
    return 0;
  }
  if (std::strcmp(argv[1], "echo") != 0) return 96;
  char bytes[4096];
  for (;;) {
    const auto size = ::read(STDIN_FILENO, bytes, sizeof(bytes));
    if (size < 0 && errno == EINTR) continue;
    if (size < 0) return 97;
    if (size == 0) break;
    if (!write_all(STDOUT_FILENO, bytes, static_cast<std::size_t>(size))) return 98;
  }
  return write_all(STDERR_FILENO, "stderr\n", 7) ? 0 : 99;
}
"""


def execution_events(client: Client, request_id: str) -> tuple[dict, dict]:
    frames = []
    for _ in range(8):
        frame = client.recv()
        frames.append(frame)
        if frame.get("payload", {}).get("kind") == "commandFinished":
            break
    kinds = [frame.get("payload", {}).get("kind") for frame in frames]
    if kinds != ["observation", "state", "commandFinished"]:
        fail("incomplete execution event sequence", {
            "requestId": request_id, "kinds": kinds, "lastPayload": frames[-1].get("payload"),
        })
    finished = frames[-1]["payload"]
    if finished.get("requestId") != request_id or finished.get("outcome") != "completed":
        fail("execution did not complete", finished)
    return frames[0]["payload"]["observation"], frames[1]["payload"]["state"]


def expect_output(snapshot: dict, text: str, label: str, raw_bytes: int | None = None,
                  retained_from: int = 0) -> None:
    expected_bytes = len(text.encode("utf-8")) if raw_bytes is None else raw_bytes
    expected = {"text": text, "totalBytes": expected_bytes,
                "retainedFromByte": retained_from, "truncated": retained_from != 0}
    if snapshot != expected:
        # Avoid dumping hundreds of KiB when a byte or a counter is wrong.
        fail("incorrect output snapshot", {
            "stream": label,
            "expectedBytes": expected_bytes,
            "actual": {key: value for key, value in snapshot.items() if key != "text"},
            "textMatches": snapshot.get("text") == text,
            "actualTextPrefix": snapshot.get("text", "")[:120],
        })


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: io_integration.py BACKEND", file=sys.stderr)
        return 2
    if shutil.which("gdb") is None:
        print("GDB is unavailable; integration test skipped")
        return 77

    with tempfile.TemporaryDirectory(prefix="phantom-io-test-") as directory:
        workspace = Path(directory)
        client = Client(sys.argv[1], workspace)
        try:
            connect = client.send({"kind": "connect", "supportedProtocolVersions": [1]})
            if not connect.get("ok"):
                fail("connect failed", connect)
            output_limit = connect["capabilities"]["limits"]["maxOutputBytes"]
            if not isinstance(output_limit, int) or output_limit < 1:
                fail("invalid advertised output limit", output_limit)
            common = {"protocolVersion": 1, "workspace": connect["workspace"], "session": None}
            build = client.send({
                **common,
                "requestId": "build-io",
                "command": {
                    "kind": "build",
                    "source": {"id": "source-io", "documents": [{
                        "documentId": "io", "revisionId": "io-1", "path": "io.cpp",
                        "text": SOURCE, "sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
                    }]},
                    "configuration": {"revisionId": "config-io", "compiler": "clang++",
                                      "flags": ["-std=c++20", "-g", "-O0"],
                                      "outputDirectory": ".phantom/io-build"},
                    "architecture": "x86_64",
                },
            })
            if not build.get("ok") or not build.get("result", {}).get("success"):
                fail("IO fixture build failed", build)
            build_id = build["result"]["artifact"]["id"]

            def run(name: str, text: str, mode: str = "echo",
                    arguments: list[str] | None = None,
                    environment: dict[str, str] | None = None) -> tuple[dict, dict]:
                print("IO case: " + name, flush=True)
                launch_id = "launch-" + name
                launch = client.send({
                    **common, "requestId": launch_id,
                    "command": {
                        "kind": "launch", "buildId": build_id,
                        "input": {"id": "input-" + name, "text": text,
                                  "encoding": "utf-8", "closeAfterWrite": True},
                        "argv": [mode, *(arguments or [])], "environment": environment or {}, "stopAtEntry": True,
                    },
                })
                if not launch.get("ok") or launch.get("result", {}).get("kind") != "launchAccepted":
                    fail("IO fixture launch was not accepted", launch)
                entry, state = execution_events(client, launch_id)
                if state.get("phase") != "stopped":
                    fail("IO fixture did not stop at entry", state)
                # A large input can only finish writing after the inferior
                # resumes and drains the pipe; never demand delivery at entry.
                submitted_bytes = len(text.encode("utf-8"))
                if not 0 <= entry["input"]["deliveredBytes"] <= submitted_bytes:
                    fail("entry input accounting is outside submitted bytes", {"input": name})
                continue_id = "continue-" + name
                response = client.send({
                    **common, "requestId": continue_id, "session": launch["session"],
                    "expectedStop": entry["stop"], "command": {"kind": "continue"},
                })
                if not response.get("ok") or response.get("result", {}).get("kind") != "accepted":
                    fail("IO fixture continue was not accepted", response)
                observation, state = execution_events(client, continue_id)
                if observation.get("reason") != "exit" or state.get("phase") != "terminated" or state.get("live") is not None:
                    fail("IO fixture did not terminate", {"reason": observation.get("reason"), "state": state})
                input_state = observation["input"]
                if input_state.get("tracking") != "transport-only" or input_state.get("submitted", {}).get("text") != text:
                    fail("input identity or tracking was lost", {"input": name})
                if mode == "echo" and input_state.get("deliveredBytes") != submitted_bytes:
                    fail("echo did not receive every submitted byte", {
                        "input": name, "expectedBytes": submitted_bytes,
                        "deliveredBytes": input_state.get("deliveredBytes"),
                    })
                return observation, state

            for name, text in [
                ("empty-eof", ""),
                ("control-unicode", "NUL:\0 Ctrl-D:\x04 CRLF:\r\nРусский: ё, 日本語, emoji: 🦊\n"),
                ("large-input", "0123456789abcdef" * (128 * 1024 // 16)),
            ]:
                observation, _ = run(name, text)
                expect_output(observation["stdout"], text, name + " stdout")
                expect_output(observation["stderr"], "stderr\n", name + " stderr")

            bash_env = workspace / "bash-env.sh"
            bash_env.write_text("exit 71\n", encoding="utf-8")
            arguments = ["", "two words", "single'quote", 'double"quote',
                         "back\\slash", "$(exit 71); * ? $HOME"]
            # Target configuration must not reconfigure GDB, the startup
            # shell, or the wrapper. PHANTOM_* names belong to the user too.
            environment = {
                "BASH_ENV": str(bash_env), "SHELL": "/phantom/not-a-shell",
                "PATH": "/phantom/no-such-bin", "PHANTOM_ENV": " \tleading\ntrailing \t",
                "EMPTY": "", "PHANTOM_STDIN_FIFO": "user stdin", "PHANTOM_STDOUT_FIFO": "user stdout",
                "PHANTOM_STDERR_FIFO": "user stderr", "PHANTOM_READY_FIFO": "user ready",
            }
            observation, _ = run("arguments-environment", "", "arguments-environment", arguments, environment)
            expected = "".join(value + "\0" for value in [*arguments, *environment.values()])
            expect_output(observation["stdout"], expected, "arguments/environment stdout")
            expect_output(observation["stderr"], "environment\n", "arguments/environment stderr")

            # Interleaved output from both streams exceeds ordinary pipe
            # capacity. Blocking on either stream would deadlock the inferior.
            output_bytes = output_limit + 8192
            observation, _ = run("dual-output", "", "flood", [str(output_bytes)])
            expect_output(observation["stdout"], "O" * output_limit, "flood stdout",
                          raw_bytes=output_bytes, retained_from=8192)
            expect_output(observation["stderr"], "E" * output_limit, "flood stderr",
                          raw_bytes=output_bytes, retained_from=8192)

            unread_text = "x" * (512 * 1024)
            observation, state = run("early-close", unread_text, "early-close")
            delivered = observation["input"]["deliveredBytes"]
            if not 0 <= delivered < len(unread_text):
                fail("unread input was falsely reported as delivered", {"deliveredBytes": delivered})
            if state.get("exit", {}).get("code") != 23:
                fail("early-close exit status was lost", state)
            expect_output(observation["stdout"], "closed\n", "early-close stdout")
            expect_output(observation["stderr"], "unread\n", "early-close stderr")

            # Output bytes are untrusted. Invalid UTF-8 must be replaced for
            # JSON display while byte counters retain their original meaning.
            observation, _ = run("invalid-utf8", "", "invalid-utf8")
            expect_output(observation["stdout"], "\ufffd\ufffd\ufffd\n", "invalid stdout", raw_bytes=4)
            expect_output(observation["stderr"], "\ufffd\ufffd\n", "invalid stderr", raw_bytes=3)

            # Both EPIPE and malformed output must leave the service reusable.
            observation, _ = run("recovery", "still alive\n")
            expect_output(observation["stdout"], "still alive\n", "recovery stdout")
            expect_output(observation["stderr"], "stderr\n", "recovery stderr")
        finally:
            client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
