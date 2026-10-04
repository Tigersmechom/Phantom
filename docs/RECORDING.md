# Bounded recording, reverse execution and prerequisite probes

The Linux x86_64 backend has an explicit `gdb-record-full` launch profile.
It records supported machine instructions inside the current live GDB session,
then permits reverse instruction steps and seeking within the retained log.
Ordinary launches keep the `native` profile. rr recording of user programs,
durable checkpoints and restoring arbitrary saved observations are separate
work; `capabilities.restore` remains `"none"`.

`capabilities.recordingProfiles` lists `native` and `gdb-record-full` as
supported explicit launch requests. This advertises the adapter interface;
it does not establish that every instruction in a particular program can be
recorded, or that host prerequisites will permit the requested launch.

The request and result types are in
[backend-contract.ts](../src/backend-contract.ts) and
[backend-runtime-contract.ts](../src/backend-runtime-contract.ts).
Examples below show the `command` field. Include the usual protocol version,
request ID, workspace and session envelope. Recording reads and movement also
require `expectedStop` from the current observation.

## Launch and inspect a recording

Add these fields to a normal launch request using an existing build artifact:

```json
{
  "kind": "launch",
  "buildId": "your-built-artifact-id",
  "recordingProfile": "gdb-record-full",
  "maxRecordedInstructions": 200000,
  "input": {
    "id": "input-1",
    "text": "12 34\n",
    "encoding": "utf-8",
    "closeAfterWrite": true
  },
  "argv": [],
  "environment": {},
  "stopAtEntry": true
}
```

This profile requires an entry stop and finite initial stdin ending in EOF.
`appendInput` and `closeInput` are unavailable in a recording session; choose
`native` for interactive input. The instruction limit defaults to 200,000 and
accepts 1–1,000,000, bounded by `capabilities.limits.maxRecordedInstructions`.
GDB evicts older instructions when this bounded log fills; the limit is a
retention bound, not a request to stop the program after that many instructions.
The requested profile is separate from ELF/ASLR policy: fixed executable
addresses do not themselves record execution or establish allocator replay.

The adapter also requires an owned inferior `pidfd`. If it cannot obtain one,
recording launch fails with `LAUNCH_FAILED`. A synchronous GDB source step can
defer GDB's own SIGINT inside an endless line; the adapter uses `pidfd` signaling
to target the exact inferior process for bounded interruption without trusting
a reused numeric PID. This prerequisite is checked on the actual launch,
independently of the isolated recorder probe.

After launch, ordinary steps, continue and bounded instruction tracing advance
the recorded process. Read its current recording position with:

```json
{"kind":"readRecording"}
```

Available recording status contains:

| Field | Meaning |
| --- | --- |
| `mode` | `record` at the recording frontier, or `replay` inside the retained log. |
| `currentInstruction` | Current instruction boundary in this GDB log. |
| `firstInstruction`, `lastInstruction` | Oldest and newest retained instruction entries. |
| `earliestSeekableInstruction` | Earliest boundary this adapter can seek safely. |
| `recordedInstructions`, `maxRecordedInstructions` | Retained instruction count and configured bound. |
| `evicted` | Whether the beginning of the original recording has been lost. |
| `coverage` | Explicit scope of machine state and effects that are not restored. |

Instruction positions are decimal **strings**; parse them with `BigInt` when
arithmetic is necessary. They are not observation IDs, source-line numbers or
history ordinals. A newly started empty log has boundary `"0"`. Unavailable
status carries a reason, for example recording not requested, process exited,
or recording state unavailable. Never substitute a previously cached position
for a failed status read.

## Move through the retained log

```json
{"kind":"reverseInstruction"}
{"kind":"seekRecording","instruction":"25"}
```

Both commands operate on a live recording and use its latest `expectedStop`.
Read status first and choose a retained position; seeking before the retained
beginning or after the recorded end is rejected. A reverse instruction command
at the earliest retained boundary is also rejected. Movement publishes a new
observation and state with a new stop token. Previously saved observations
remain immutable; a backward machine move does not decrement history ordinals.

Forward stepping while inside the recording replays its recorded machine
states. Beyond the frontier, GDB attempts to record new execution. The backend
does not yet provide a branch-edit workflow or allow variable writes as a way
to rewrite the recorded past.

The current profile configures synchronous all-stop GDB operation. GDB's
software recorder has target-dependent instruction and syscall support; an
unsupported operation can stop execution. On the tested Ubuntu/GDB 15.1 host,
a scalar fixture records and reverses successfully, while an ordinary `cout`
call reaches an unsupported AVX instruction in glibc `strlen`. A passing small
probe therefore does not promise that a whole C++ application can be recorded.
See the [GDB recording documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html).

An execution error must be assessed with the returned observation/state:
the process may remain at a valid stop after partial progress. A debugger exit
code of zero alone does not prove that recording succeeded. Loss of the live
process is distinct from hitting a retained-log boundary; a terminated process
cannot be resurrected by these commands.

## Machine history, operating-system state and output

GDB changes supported registers and memory during replay. This is not a
transaction over the operating system: files already written, pipe bytes
already delivered, external processes and other side effects are not undone.
The input transport ledger describes bytes delivered to the process, not a
rewound semantic `cin` cursor.

`/proc` metadata, descriptors, mappings and module inspection describe the
current operating-system process. Observations carry
`osEvidenceScope:"current-process"`; `inspectProcess` responses and module
snapshots carry `evidenceScope:"current-os-state"`. After a reverse step they must not be
presented as proof of historical descriptor positions, allocation ownership or
kernel mapping restoration. Retaining a snapshot makes its captured evidence
immutable without changing what it proves.

Committed stdout/stderr use an append-only output journal. Reading an older
observation or moving backward must not erase output already emitted outside
the process. Pending `cout`/stdio buffer snapshots are separate machine-state
evidence and can change under replay when that runtime buffer is observable.
The frontend can render pending bytes in red, while showing committed bytes
through the journal and the selected observation's output cursor. It must not
resubmit historical bytes as a new external effect merely because they were
displayed again.

The output cursor states how its prefix is known:

| `outputCursor.source` | Prefix evidence |
| --- | --- |
| `transport` | Counters observed on the native execution transport. |
| `recording-checkpoint` | Prefix previously observed at this exact recording boundary, reused during replay. |
| `unknown` | No observed output boundary is available for this instruction; both counters are `null`. |

A seek to an arbitrary intermediate instruction does not invent a stdout
prefix from today's complete output. Its prefix stays unknown unless that
exact boundary was already observed. `readOutputJournal` can therefore return
a non-null `selectedPoint` with `selectedThroughByte:null`; the journal bytes
still exist, but their position relative to that selected execution boundary
has not been established. The frontend must preserve this distinction instead
of treating `null` as zero or as the end of the journal.

The [inspection gateway guide](INSPECTION_GATEWAYS.md) describes
`readOutputJournal`, process and module inspection, memory captures, instruction
traces and the data supplied to the future **2D** memory view. Module and memory
capture retention is independent of the GDB instruction-log bound.

## Probe this host without changing a live session

```json
{"kind":"probeRecorders"}
```

This command can run before launch. Its normal response is
`{kind:"recorderProbe",probe:...}`. The backend starts only its shipped scalar
fixture in isolated child processes; the request accepts no executable paths
or arbitrary GDB commands. It neither attaches to the current inferior nor
changes its session, observation or stop token.

The GDB probe verifies a forward value of 29 at one PC, reversal to value 17 at
the earlier PC, and forward replay back to the final value and PC. The rr probe
performs actual record and replay of the fixture. Tool-version output is
retained as evidence, but an installed executable alone does not establish
availability. A failed recording is not replayed as though it were complete.

The result reports each subprocess stage's attempt, status, exit/signal,
bounded stdout/stderr and failure detail. It also reads the host's
`perf_event_paranoid` and `ptrace_scope` values when accessible. On the current
runner, rr 5.9.0 rejects recording because `perf_event_paranoid` is 4. The probe
does not modify sysctls or request additional privileges. Hardware counters,
CPU support and permissions remain host prerequisites; see
[rr's overview and limitations](https://rr-project.org/).

Probe subprocesses share a ten-second default deadline. Each stage has a
64 KiB output limit. Temporary trace size is monitored against 16 MiB and a
file-count bound; a short overshoot between checks is possible. Traces are
deleted afterward. Send the ordinary `cancel` command targeting the probe's
request ID to stop its isolated process group. The probe returns
`cancelled:true`; cancelling it does not pause or terminate an unrelated live
debug session. Copy the target probe's workspace/session envelope into the
cancel request. If the probe was sent with `session:null`, its cancel uses
`session:null` too, even when an unrelated live session already exists.

## Verification

The recorder probe tests cover exact state verification, missing tools and
fixture, false-positive text, non-UTF-8 diagnostics, time/output/trace limits,
cancellation, child cleanup and incomplete-record rejection. The protocol
integration test also probes and cancels beside a real stopped inferior, then
steps that inferior to verify that no interrupt or session change leaked from
the probe. The suite's final pass counts belong in the implementation handoff
after the complete Debug and sanitizer runs.


The instruction limit bounds the number of recorded instructions, not bytes
allocated by GDB. One instruction can modify a large memory range. A separate
recorder-process memory quota is not implemented; clients must not interpret
`maxRecordedInstructions` as a memory-byte budget. If a recording position
cannot be established, output cursor provenance is unknown even when physical
transport bytes remain available (including after record-profile exit).


## Verified checkpoint

All 26 CTest checks pass in Debug and ASan/UBSan on the installed Linux/GDB
combination. The contract test checks 819 real frames against both TypeScript
DTO files; the five existing harness checks and four contract fixture checks
also pass. Recorder scenarios include `0 → 1 → 2 → 0` stores, reverse/seek,
eviction, malformed cursors, unchanged seeks, cancellation, source-step
timeout, real decoder/memory-record refusal, exact binary syscall output
without replay duplication, unknown output prefixes, immutable history and
returning to native interactive execution. Module tests exercise actual
`dlopen`/`dlclose`, BSS mappings and retained snapshots. Probe tests verify
failure/cancellation cleanup while preserving a separate live session.
