"""Actual ELF/profile and launch-policy checks at the frontend NDJSON boundary.

ET_EXEC fixes the executable's link addresses, not allocator or replay behavior.
Disabling ASLR can be denied by the host; require-fixed must then fail honestly.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

from service_integration import Client as TransportClient


SOURCE = "int main() {\n  int value = 7;\n  return value;\n}\n"
CLEAR_ASLR_SOURCE = r"""#include <sys/personality.h>
#include <unistd.h>
__attribute__((constructor)) static void clear_aslr_before_entry() {
  const int mask = ::personality(0xffffffffUL);
  const bool cleared = mask != -1 &&
    ::personality(static_cast<unsigned long>(mask) & ~static_cast<unsigned long>(ADDR_NO_RANDOMIZE)) != -1;
  const char result = cleared ? 'Y' : 'N';
  (void)::write(STDOUT_FILENO, &result, 1);
}
int main() {
  int value = 7;
  return value;
}
"""


class Client(TransportClient):
    def __init__(self, executable: str, workspace: Path) -> None:
        super().__init__(executable, workspace)
        connected = self.send({"kind": "connect", "supportedProtocolVersions": [1]})
        assert connected["ok"], connected
        self.workspace = connected["workspace"]
        self.session = None
        self.counter = 0

    def query(self, command: dict) -> dict:
        self.counter += 1
        frame = {"protocolVersion": 1, "requestId": f"profile-{self.counter}",
                 "workspace": self.workspace, "session": self.session, "command": command}
        self.send_many([frame])
        # A rejected launch may emit a failed-state event after its response.
        # Consume such earlier events without mistaking one for this response.
        while True:
            response = self.recv()
            if response.get("requestId") == frame["requestId"] or response.get("kind") == "error":
                return response
            assert "payload" in response, response

    def build(self, profile: str | None, flags: list[str] | None = None, source: str = SOURCE) -> dict:
        configuration = {"revisionId": "profile-config", "compiler": "clang++",
                         "flags": flags or ["-std=c++20", "-g", "-O0", "-fPIE", "-pie"],
                         "outputDirectory": ".phantom/profile-build"}
        if profile is not None:
            configuration["addressProfile"] = profile
        return self.query({"kind": "build", "source": {"id": "profile-source", "documents": [{
            "documentId": "main", "revisionId": "main-1", "path": "main.cpp", "text": source,
            "sha256": hashlib.sha256(source.encode()).hexdigest()}]},
            "configuration": configuration, "architecture": "x86_64"})

    def stop(self) -> None:
        response = self.query({"kind": "stop"})
        assert response["ok"], response
        while True:
            event = self.recv()
            assert "payload" in event, event
            if event["payload"]["kind"] == "commandFinished":
                assert event["payload"]["requestId"] == response["requestId"], event
                assert event["payload"]["outcome"] == "completed", event
                return

    def launch(self, artifact: dict, policy: str | None) -> tuple[dict, dict | None]:
        command = {"kind": "launch", "buildId": artifact["id"],
                   "input": {"id": "profile-input", "text": "", "encoding": "utf-8", "closeAfterWrite": True},
                   "argv": [], "environment": {}, "stopAtEntry": True}
        if policy is not None:
            command["addressPolicy"] = policy
        response = self.query(command)
        if not response["ok"]:
            return response, None
        self.session = response["session"]
        events = [self.recv() for _ in range(3)]
        assert [event["payload"]["kind"] for event in events] == ["observation", "state", "commandFinished"], events
        assert events[-1]["payload"]["outcome"] == "completed", events
        return response, events[0]["payload"]["observation"]


def artifact(response: dict, expected_type: str, expected_profile: str) -> dict:
    assert response["ok"] and response["result"]["success"], response
    result = response["result"]["artifact"]
    assert result["addressProfile"] == expected_profile, result
    metadata = result["elf"]
    assert metadata["available"] and metadata["format"] == "ELF", metadata
    assert metadata["class"] == 64 and metadata["endianness"] == "little", metadata
    assert metadata["elfType"] == expected_type and metadata["architecture"] == "x86_64", metadata
    raw = Path(result["binaryPath"]).read_bytes()
    assert raw[:6] == b"\x7fELF\x02\x01", raw[:16]
    assert int.from_bytes(raw[16:18], "little") == {"ET_EXEC": 2, "ET_DYN": 3}[expected_type]
    assert result["binarySha256"] == hashlib.sha256(raw).hexdigest(), result
    assert any(segment["type"] == "PT_LOAD" and segment["flags"]["execute"]
               for segment in metadata["programHeaders"]), metadata
    for segment in metadata["programHeaders"]:
        for key in ("offsetHex", "virtualAddressHex", "fileSizeHex", "memorySizeHex", "alignmentHex"):
            assert isinstance(segment[key], str) and segment[key].startswith("0x"), segment
    return result


def layout(observation: dict, policy: str, elf_type: str) -> dict:
    result = observation["executionLayout"]
    assert result["addressPolicy"] == policy and result["elfType"] == elf_type, result
    assert result["allocatorDeterminism"] == "not-established" and result["replayVerified"] is False, result
    assert len(result["runFingerprint"]) == 64, result
    assert result["aslr"]["requestedDisabled"] == (policy != "native"), result
    if result["aslr"]["evidence"] == "linux-proc-personality":
        mask = int(result["aslr"]["personalityMaskHex"], 16)
        assert result["aslr"]["verifiedDisabled"] == bool(mask & 0x40000), result
        assert isinstance(result["processStartTimeTicks"], str), result
    else:
        assert result["aslr"]["evidence"] == "unavailable", result
        assert result["aslr"]["verifiedDisabled"] is None and result["aslr"]["personalityMaskHex"] is None, result
    return result


def executable_mappings(observation: dict, executable: str) -> list[tuple[str, str, str]]:
    mapping = observation["memoryMap"]
    assert mapping["available"] and mapping["coverage"] == "complete", mapping
    result = [(region["startAddressHex"], region["endAddressHex"], region["permissions"])
              for region in mapping["regions"] if region["path"] == executable]
    assert result, mapping
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: address_profile_integration.py BACKEND", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux") or not shutil.which("gdb") or not shutil.which("clang++"):
        print("Linux, GDB and clang++ are required; address-profile test skipped")
        return 77
    with tempfile.TemporaryDirectory(prefix="phantom-address-profile-") as directory:
        client = Client(sys.argv[1], Path(directory))
        try:
            # Default is native: a deliberate PIE stays ET_DYN.
            pie = artifact(client.build(None), "ET_DYN", "native")
            failure, observed = client.launch(pie, "require-fixed")
            assert not failure["ok"] and failure["error"]["code"] == "LAUNCH_FAILED" and observed is None, failure
            success, observed = client.launch(pie, "native")
            assert success["ok"] and observed is not None, success
            native = layout(observed, "native", "ET_DYN")
            success, observed = client.launch(pie, None)
            assert success["ok"] and observed is not None, success
            default = layout(observed, "disable-aslr", "ET_DYN")
            assert default["runFingerprint"] != native["runFingerprint"]

            client.stop()
            fixed = artifact(client.build("fixed-executable"), "ET_EXEC", "fixed-executable")
            assert fixed["id"] != pie["id"] and fixed["binaryPath"] != pie["binaryPath"], fixed
            # Caller -pie is explicitly overridden by the profile's driver flags.
            flags = fixed["command"]
            assert flags.index("-fno-pie") > flags.index("-fPIE"), flags
            assert flags.index("-no-pie") > flags.index("-pie"), flags
            first_response, first = client.launch(fixed, "disable-aslr")
            assert first_response["ok"] and first is not None, first_response
            first_layout = layout(first, "disable-aslr", "ET_EXEC")
            second_response, second = client.launch(fixed, "disable-aslr")
            assert second_response["ok"] and second is not None, second_response
            second_layout = layout(second, "disable-aslr", "ET_EXEC")
            assert first_layout["runFingerprint"] == second_layout["runFingerprint"]
            assert first_response["session"] != second_response["session"]
            assert executable_mappings(first, fixed["binaryPath"]) == executable_mappings(second, fixed["binaryPath"])

            strict_response, strict = client.launch(fixed, "require-fixed")
            if strict_response["ok"]:
                assert strict is not None
                assert layout(strict, "require-fixed", "ET_EXEC")["aslr"]["verifiedDisabled"] is True
                repeat_response, repeat = client.launch(fixed, "require-fixed")
                assert repeat_response["ok"] and repeat is not None, repeat_response
                assert layout(repeat, "require-fixed", "ET_EXEC")["aslr"]["verifiedDisabled"] is True
                assert executable_mappings(strict, fixed["binaryPath"]) == executable_mappings(repeat, fixed["binaryPath"])
            else:
                assert strict_response["error"]["code"] == "LAUNCH_FAILED" and strict is None, strict_response
                # A permissive profile still works after strict verification was denied.
                recovery, observed = client.launch(fixed, "disable-aslr")
                assert recovery["ok"] and observed is not None, recovery
                layout(observed, "disable-aslr", "ET_EXEC")

            client.stop()
            invalid = client.build("imaginary-profile")
            assert not invalid["ok"] and invalid["error"]["code"] == "INVALID_REQUEST", invalid
            invalid, _ = client.launch(fixed, "imaginary-policy")
            assert not invalid["ok"] and invalid["error"]["code"] == "INVALID_REQUEST", invalid

            # Raw linker switches can beat driver switches. Inspect actual ELF;
            # never declare fixed addresses merely because -no-pie was supplied.
            # Omit non-PIE CRT startup objects so the linker really succeeds in
            # emitting ET_DYN; this artifact is inspected, never executed.
            escaped = client.build("fixed-executable", ["-std=c++20", "-g", "-O0", "-nostartfiles",
                                                       "-Wl,-e,main", "-Wl,-pie"])
            assert not escaped["ok"] and escaped["error"]["code"] == "BUILD_FAILED", escaped
            assert "actual x86_64 ET_EXEC" in escaped["error"]["message"], escaped
            old, _ = client.launch(fixed, "disable-aslr")
            assert not old["ok"] and old["error"]["code"] == "STALE_CONTEXT", old

            # Runtime startup code can undo GDB's request before main. Check
            # the actual personality at entry, never its earlier configuration.
            clearing = artifact(client.build("fixed-executable", source=CLEAR_ASLR_SOURCE),
                                "ET_EXEC", "fixed-executable")
            response, cleared = client.launch(clearing, "disable-aslr")
            assert response["ok"] and cleared is not None, response
            changed_layout = layout(cleared, "disable-aslr", "ET_EXEC")
            assert cleared["stdout"]["text"] in ("Y", "N"), cleared["stdout"]
            if cleared["stdout"]["text"] == "Y":
                assert changed_layout["aslr"]["verifiedDisabled"] in (False, None), changed_layout
                refused, cleared = client.launch(clearing, "require-fixed")
                assert not refused["ok"] and refused["error"]["code"] == "LAUNCH_FAILED", refused
                assert cleared is None
            else:
                print("constructor personality change denied by host; entry-time verification remains explicit")
        finally:
            client.close()
    print("address profiles: actual ELF, flag precedence, ASLR verification and strict-policy recovery passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
