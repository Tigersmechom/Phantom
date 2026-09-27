"""Check the process boundary, doctor output and unsupported CLI options."""

import json
import subprocess
import sys


def run(*args):
    return subprocess.run(
        [sys.argv[1], *args], capture_output=True, text=True, timeout=5, check=False
    )


report = run("--self-check")
assert report.returncode == 0, report.stderr
assert report.stderr == "", report.stderr
data = json.loads(report.stdout)
assert data["kind"] == "phantom.backend.self-check", data
assert data["version"] == sys.argv[2], data
assert data["status"] == "ready", data
assert data["protocol"] == "v1-stdio-ndjson", data
assert data["platform"] in {"linux", "macos", "other"}, data
assert data["architecture"] in {"arm64", "x86_64", "other"}, data
assert data["cxxStandard"] >= 202002, data
assert set(data["capabilities"]) == {
    "build", "gdb", "history", "recordReplay", "expressionTrace", "variableWrite"
}, data
assert data["capabilities"]["build"] is True, data
assert data["capabilities"]["gdb"] is True, data
assert data["capabilities"]["history"] is True, data
assert data["capabilities"]["recordReplay"] is False, data

version = run("--version")
assert version.returncode == 0, version.stderr
assert version.stdout == f"phantom-backend {sys.argv[2]}\n", version.stdout
assert version.stderr == "", version.stderr

for args in [(), ("--help",)]:
    result = run(*args)
    assert result.returncode == 0, result.stderr
    assert "v1-stdio-ndjson" in result.stdout, result.stdout
    assert "GDB" in result.stdout or "stdio" in result.stdout, result.stdout

for args in [("--launch",), ("--version", "--self-check"), ("--protocol",)]:
    result = run(*args)
    assert result.returncode == 2, result
    assert result.stdout == "", result.stdout
    assert result.stderr, result

print("CLI build report and unsupported-command checks passed; no engine tested.")
