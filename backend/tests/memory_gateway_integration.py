"""Public memory gateway: object -> vptr -> table -> code, map lifecycle/history.

Linux GDB/ptrace may read PROT_NONE memory. Permission metadata describes what
the inferior can access; a successful debugger read must not rewrite it.
"""
from __future__ import annotations

import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

from service_integration import Client as TransportClient


class Client(TransportClient):
    """Use the existing NDJSON transport without unrelated output-shape asserts."""
    def __init__(self, executable: str, workspace: Path) -> None:
        super().__init__(executable, workspace)
        connected = self.send({"kind": "connect", "supportedProtocolVersions": [1]})
        assert connected["ok"], connected
        self.workspace = connected["workspace"]
        self.session = None
        self.observation = None
        self.counter = 0

    def frame(self, command: dict, expected_stop: dict | None = None) -> dict:
        self.counter += 1
        frame = {"protocolVersion": 1, "requestId": f"memory-{self.counter}",
                 "workspace": self.workspace, "session": self.session, "command": command}
        if expected_stop is None and command["kind"] in ("continue", "readMemory"):
            expected_stop = self.observation["stop"]
        if expected_stop is not None:
            frame["expectedStop"] = expected_stop
        return frame

    def query(self, command: dict) -> dict:
        return self.send(self.frame(command))

    def execute(self, command: dict) -> list[dict]:
        response = self.query(command)
        assert response["ok"], response
        if command["kind"] == "launch":
            self.session = response["session"]
        events = [self.recv() for _ in range(3)]
        assert [event.get("payload", {}).get("kind") for event in events] == [
            "observation", "state", "commandFinished"], events
        assert events[-1]["payload"]["requestId"] == response["requestId"], events
        self.observation = events[0]["payload"]["observation"]
        return [response, *events]

    def launch(self, artifact: dict) -> None:
        self.execute({"kind": "launch", "buildId": artifact["id"],
                      "input": {"id": "memory-input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                      "argv": [], "environment": {}, "stopAtEntry": True})

    def checkpoint(self) -> dict:
        response = self.query({"kind": "getState"})
        assert response["ok"], response
        return response["result"]


SOURCE = r"""#include <sys/mman.h>
#include <unistd.h>
#include <cstddef>

struct Base {
  virtual ~Base() = default;
  virtual int probe() const { return 1; }
};
struct Derived : Base {
  int marker = 37;
  int probe() const override { return marker; }
};

int main() {
  Derived object;
  const std::size_t page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  void* arena = ::mmap(nullptr, 3 * page, PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (arena == MAP_FAILED) return 91;
  auto* middle = static_cast<unsigned char*>(arena) + page;
  if (::mprotect(middle, page, PROT_READ | PROT_WRITE) != 0) return 92;
  middle[0] = 0xa7;
  middle[page - 1] = 0x5c;
  int phase = 1;
  asm volatile("" : : "r"(phase) : "memory"); // CHECKPOINT_MAPPED
  if (::mprotect(middle, page, PROT_NONE) != 0) return 93;
  phase = 2;
  asm volatile("" : : "r"(phase) : "memory"); // CHECKPOINT_PROTECTED
  if (::munmap(arena, 3 * page) != 0) return 94;
  phase = 3;
  asm volatile("" : : "r"(phase) : "memory"); // CHECKPOINT_UNMAPPED
  return object.probe() == 37 ? 0 : 95;
}
"""


def location(marker: str) -> dict:
    prefix = SOURCE[:SOURCE.index(next(line for line in SOURCE.splitlines() if marker in line))]
    line = prefix.count("\n") + 1
    offset = len(prefix.encode("utf-16-le")) // 2
    return {"documentId": "memory", "revisionId": "memory-1",
            "range": {"start": offset, "end": offset},
            "start": {"line": line, "column": 1}, "end": {"line": line, "column": 1}}


def execute(client: Client, command: dict, marker: str | None = None) -> dict:
    frames = client.execute(command)
    finished = [f["payload"] for f in frames if f.get("payload", {}).get("kind") == "commandFinished"]
    assert len(finished) == 1 and finished[0]["outcome"] == "completed", frames
    observation = client.observation
    assert observation is not None
    if marker:
        assert observation["location"]["start"]["line"] == location(marker)["start"]["line"], observation
        assert observation["reason"] == "breakpoint", observation
    return observation


def variable(observation: dict, name: str) -> dict:
    variables = observation["stack"][0]["variables"]
    return next(value for value in variables if value["name"] == name)


def regions(observation: dict) -> list[dict]:
    mapping = observation["memoryMap"]
    assert mapping["available"] is True and mapping["coverage"] == "complete", mapping
    assert mapping["source"] == "linux-proc-maps", mapping
    return mapping["regions"]


def containing(observation: dict, address: int) -> dict | None:
    return next((region for region in regions(observation)
                 if int(region["startAddressHex"], 16) <= address < int(region["endAddressHex"], 16)), None)


def read(client: Client, address: int, count: int) -> bytes:
    response = client.query({"kind": "readMemory", "addressHex": hex(address), "byteCount": count})
    assert response["ok"], response
    result = response["result"]
    assert result["addressHex"] == hex(address) and result["unreadableBytes"] == 0, result
    data = base64.b64decode(result["bytesBase64"], validate=True)
    assert len(data) == count, result
    return data


def history(client: Client, observation: dict) -> None:
    response = client.query({"kind": "readHistory", "point": observation["point"]})
    assert response["ok"] and response["result"]["observation"] == observation, response


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: memory_gateway_integration.py BACKEND", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux") or shutil.which("gdb") is None:
        print("Linux and GDB are required; memory gateway test skipped")
        return 77
    with tempfile.TemporaryDirectory(prefix="phantom-memory-gateway-") as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            capabilities = client.query({"kind": "capabilities"})
            assert capabilities["ok"], capabilities
            assert capabilities["result"]["capabilities"]["memoryMap"] == "linux-proc-maps", capabilities
            build = client.query({"kind": "build", "source": {"id": "memory-source", "documents": [{
                "documentId": "memory", "revisionId": "memory-1", "path": "memory.cpp", "text": SOURCE,
                "sha256": hashlib.sha256(SOURCE.encode()).hexdigest()}]},
                "configuration": {"revisionId": "memory-config", "compiler": "clang++",
                                  "flags": ["-std=c++20", "-g", "-O0"],
                                  "outputDirectory": ".phantom/memory-build"},
                "architecture": "x86_64"})
            assert build["ok"] and build["result"]["success"], build
            client.launch(build["result"]["artifact"])
            markers = ["CHECKPOINT_MAPPED", "CHECKPOINT_PROTECTED", "CHECKPOINT_UNMAPPED"]
            breakpoints = client.query({"kind": "setBreakpoints", "documentId": "memory", "revisionId": "memory-1",
                                        "breakpoints": [{"id": marker, "range": location(marker), "enabled": True}
                                                        for marker in markers]})
            assert breakpoints["ok"] and all(bp["verified"] for bp in breakpoints["result"]["breakpoints"]), breakpoints

            mapped = execute(client, {"kind": "continue"}, markers[0])
            middle = int(variable(mapped, "middle")["value"]["value"]["addressHex"], 16)
            page = int(variable(mapped, "page")["value"]["value"]["decimal"])
            assert containing(mapped, middle)["permissions"] == "rw-p", mapped["memoryMap"]
            for guard in (middle - page, middle + page):
                assert containing(mapped, guard)["permissions"] == "---p", mapped["memoryMap"]
            assert read(client, middle, 1) == b"\xa7"
            assert read(client, middle + page - 1, 1) == b"\x5c"

            # Verify the complete kernel range list, including special high
            # mappings (>2^53, e.g. vsyscall) when the host exposes them.
            kernel = [line.split(maxsplit=5) for line in
                      Path(f"/proc/{mapped['processInstanceId']}/maps").read_text().splitlines()]
            expected = [(hex(int(line[0].split("-")[0], 16)), hex(int(line[0].split("-")[1], 16)), line[1])
                        for line in kernel]
            actual = [(r["startAddressHex"], r["endAddressHex"], r["permissions"]) for r in regions(mapped)]
            assert actual == expected, {"kernel": expected, "observation": actual}
            for region in regions(mapped):
                for key in ("startAddressHex", "endAddressHex", "offsetHex", "inodeDecimal"):
                    assert isinstance(region[key], str), region

            # Follow the real Itanium ABI vptr using only frontend gateway data.
            obj = variable(mapped, "object")
            object_address = int(obj["addressHex"], 16)
            vptr = int.from_bytes(read(client, object_address, 8), "little")
            table_region = containing(mapped, vptr)
            assert table_region is not None and table_region["permissions"].startswith("r--"), table_region
            assert table_region["kind"] == "file", table_region
            table = read(client, vptr, 24)
            destructor = int.from_bytes(table[:8], "little")
            code_region = containing(mapped, destructor)
            assert code_region is not None and code_region["permissions"][2] == "x", code_region
            assert read(client, destructor, 1), code_region

            # This cannot be a user canonical x86_64 address even with LA57;
            # it is valid uint64 and must reach GDB without JavaScript rounding.
            high = client.query({"kind": "readMemory", "addressHex": "0x200000000000001", "byteCount": 1})
            assert not high["ok"] and high["error"]["code"] == "READ_FAILED", high

            protected = execute(client, {"kind": "continue"}, markers[1])
            assert containing(protected, middle)["permissions"] == "---p", protected["memoryMap"]
            guard_read = client.query({"kind": "readMemory", "addressHex": hex(middle), "byteCount": 1})
            if guard_read["ok"]:
                assert base64.b64decode(guard_read["result"]["bytesBase64"], validate=True) == b"\xa7", guard_read
            else:
                assert guard_read["error"]["code"] == "READ_FAILED", guard_read
            assert containing(client.checkpoint()["observation"], middle)["permissions"] == "---p"
            history(client, mapped)
            stale = client.frame({"kind": "readMemory", "addressHex": hex(middle), "byteCount": 1}, mapped["stop"])
            response = client.send(stale)
            assert not response["ok"] and response["error"]["code"] == "STALE_CONTEXT", response

            unmapped = execute(client, {"kind": "continue"}, markers[2])
            for address in (middle - page, middle, middle + page):
                assert containing(unmapped, address) is None, unmapped["memoryMap"]
            missing = client.query({"kind": "readMemory", "addressHex": hex(middle), "byteCount": 1})
            assert not missing["ok"] and missing["error"]["code"] == "READ_FAILED", missing
            history(client, mapped)
            history(client, protected)
            assert client.checkpoint()["observation"] == unmapped
            execute(client, {"kind": "continue"})
            assert client.checkpoint()["state"]["phase"] == "terminated"
        finally:
            client.close()
    print("memory gateway integration: vtable, permissions, mapping lifecycle, immutable history passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
