"""Type-check real backend traffic against the frontend's TypeScript DTOs.

This wraps the existing GDB integration scenario rather than maintaining a
second copy of its protocol fixtures. JSON is emitted as fresh TypeScript
object literals with `satisfies`, so nested types, discriminated unions and
excess fields are checked; JSON imports or casts would hide those mistakes.
No frontend dependencies are installed by the test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import service_integration
import advanced_gateway_integration


ROOT = Path(__file__).resolve().parents[2]


def contract_source(args: argparse.Namespace) -> tuple[str, str]:
    if args.contract_ref:
        # Resolve once, so a concurrent fetch cannot change the checked source.
        commit = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"{args.contract_ref}^{{commit}}"],
            cwd=ROOT, text=True,
        ).strip()
        source = subprocess.check_output(
            ["git", "show", f"{commit}:src/backend-contract.ts"], cwd=ROOT, text=True,
        )
        return source, commit
    path = args.contract or ROOT / "src/backend-contract.ts"
    return path.read_text(encoding="utf-8"), str(path)


def find_compiler(explicit: str | None) -> str | None:
    if explicit:
        executable = shutil.which(explicit)
        return str(Path(executable).resolve()) if executable else None
    local = ROOT / "node_modules/.bin/tsc"
    return str(local) if local.is_file() else shutil.which("tsc")


def capture(executable: Path) -> list[tuple[str, dict]]:
    traffic: list[tuple[str, dict]] = []
    original_client = service_integration.Client

    class RecordingClient(original_client):
        def send(self, frame: dict) -> dict:
            traffic.append(("request", frame))
            return super().send(frame)

        def send_many(self, frames: list[dict]) -> None:
            traffic.extend(("request", frame) for frame in frames)
            super().send_many(frames)

        def recv(self) -> dict:
            frame = super().recv()
            traffic.append(("received", frame))
            return frame

    original_argv = sys.argv
    try:
        service_integration.Client = RecordingClient
        sys.argv = [str(Path(service_integration.__file__)), str(executable)]
        result = service_integration.main()
        if result:
            raise RuntimeError(f"GDB integration exited with {result}")
    finally:
        service_integration.Client = original_client
        sys.argv = original_argv
    original_argv = sys.argv
    try:
        advanced_gateway_integration.TRAFFIC.clear()
        sys.argv = [str(Path(advanced_gateway_integration.__file__)), str(executable)]
        if advanced_gateway_integration.main():
            raise RuntimeError("advanced gateway integration failed")
        # Deliberately malformed inputs exercise the transport validator, whose
        # uncorrelated wire-error envelope is outside DebugBackendAdapter DTOs.
        traffic.extend((direction, frame) for direction, frame in advanced_gateway_integration.TRAFFIC
                       if frame.get("kind") != "error")
    finally:
        sys.argv = original_argv
    return traffic


def typecheck_source(traffic: list[tuple[str, dict]]) -> tuple[str, dict[str, int]]:
    lines = [
        'import type { BackendRequestDTO, BackendResponseDTO, BackendEventDTO,',
        '  DebugBackendAdapter, SessionRefDTO } from "./backend-contract";',
        # Connect has a transport discriminator and a session convenience field
        # in addition to the adapter return value. An adapter strips these.
        'type ConnectWire = Awaited<ReturnType<DebugBackendAdapter["connect"]>>',
        '  & { kind: "connectResult"; session: SessionRefDTO | null };',
        'type ConnectRequest = Parameters<DebugBackendAdapter["connect"]>[0]',
        '  & { kind: "connect" };',
    ]
    counts: dict[str, int] = {}
    for index, (direction, frame) in enumerate(traffic):
        if direction == "request":
            target = "ConnectRequest" if frame.get("kind") == "connect" else "BackendRequestDTO"
        elif frame.get("kind") == "connectResult":
            target = "ConnectWire"
        elif "payload" in frame:
            target = "BackendEventDTO"
        else:
            target = "BackendResponseDTO"
        counts[target] = counts.get(target, 0) + 1
        payload = json.dumps(frame, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        request_id = frame.get("requestId", frame.get("causedByRequestId", "connect"))
        lines.append(f"// {direction} frame {index}: {request_id}")
        lines.append(f"const frame_{index} = {payload} satisfies {target};")
    for expected in ("ConnectRequest", "ConnectWire", "BackendRequestDTO", "BackendResponseDTO", "BackendEventDTO"):
        if not counts.get(expected):
            raise AssertionError(f"No {expected} traffic was captured")
    return "\n".join(lines) + "\n", counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--contract", type=Path, help="standalone TypeScript DTO file (default: working tree)")
    source.add_argument("--contract-ref", help="Git revision containing src/backend-contract.ts; never checks out files")
    parser.add_argument("--tsc", default=os.environ.get("PHANTOM_TSC"), help="TypeScript compiler executable")
    args = parser.parse_args()
    compiler = find_compiler(args.tsc)
    if compiler is None:
        print("SKIP: TypeScript compiler unavailable; provide --tsc or PHANTOM_TSC", file=sys.stderr)
        return 77
    if shutil.which("gdb") is None:
        print("SKIP: GDB unavailable", file=sys.stderr)
        return 77
    contract, identity = contract_source(args)
    version = subprocess.check_output([compiler, "--version"], text=True).strip()
    traffic = capture(args.backend.resolve())
    fixture, counts = typecheck_source(traffic)
    with tempfile.TemporaryDirectory(prefix="phantom-frontend-contract-") as directory:
        root = Path(directory)
        (root / "backend-contract.ts").write_text(contract, encoding="utf-8")
        (root / "traffic.ts").write_text(fixture, encoding="utf-8")
        result = subprocess.run(
            [compiler, "--strict", "--noEmit", "--target", "ES2022", "--module", "ESNext",
             "--moduleResolution", "bundler", "--skipLibCheck", "false", "--pretty", "false", "traffic.ts"],
            cwd=root, text=True, capture_output=True, timeout=60,
        )
        if result.returncode:
            print(f"Contract check failed against {identity} ({version})", file=sys.stderr)
            source_lines = fixture.splitlines()
            reported = set()
            for match in re.finditer(r"traffic\.ts\((\d+),", result.stdout):
                line = int(match.group(1))
                if line >= 2 and line <= len(source_lines) and line not in reported:
                    print(source_lines[line - 2], file=sys.stderr)
                    reported.add(line)
            print(result.stdout, end="", file=sys.stderr)
            print(result.stderr, end="", file=sys.stderr)
            return result.returncode
    print(f"PASS: {len(traffic)} real frames satisfy frontend DTOs ({version})")
    print(f"Contract: {identity}, SHA-256 {hashlib.sha256(contract.encode()).hexdigest()}")
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
