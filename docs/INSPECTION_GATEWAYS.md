# Backend gateways: layout, process, memory and instruction changes

These are implemented protocol-v1 extensions for the Linux x86_64 GDB adapter.
The frontend owns the **2D virtual-memory view**; the backend provides exact
addresses, metadata, captured bytes and changes. No renderer is required to use
these requests. Read `capabilities` before enabling a control and use the shared
[TypeScript contract](../src/backend-contract.ts) for request/result shapes.

## Request identity and lifetime

Examples below show the `command` member of a normal `BackendRequestDTO`.
Include the current `protocolVersion`, unique `requestId`, `workspace` and
`session` in the envelope. Live reads and execution also require the exact
`expectedStop` from the current observation. A stale stop or session fails with
`STALE_CONTEXT`; a historical read never substitutes present memory.

| Command | Uses `expectedStop` | Effect |
| --- | --- | --- |
| `inspectProcess` | Required | Read OS metadata for the owned inferior. |
| `readRegisters` | Required | Read actual frame-0 machine registers. |
| `captureMemory` | Required | Retain explicitly selected byte ranges. |
| `readMemoryCapture` | No | Read a retained capture from this session. |
| `diffMemoryCaptures` | No | Compare two retained, identically shaped captures. |
| `diffMemoryMaps` | No | Compare two retained observation maps. |
| `traceInstructions` | Required | Advance execution and capture selected values at instruction boundaries. |
| `readInstructionTrace` | No | Page through a retained instruction trace. |

Captures and traces share a separate bounded store: at most 128 records and
`capabilities.limits.maxInspectionStoreBytes` serialized bytes (16 MiB by
default). Oldest records are evicted first; missing records return
`HISTORY_EVICTED`. A fresh launch clears this store. A repeated historical read
does not execute the inferior, mutate the capture or append output.

All addresses and offsets are hexadecimal strings. Parse them with `BigInt`,
not JavaScript `Number`. Byte counts within the advertised budgets are numbers.
Stop/history ordinals are session-local, not global timestamps.

## Build and launch address profiles

`configuration.addressProfile` accepts `native` (default) or
`fixed-executable`. The latter adds final `-fno-pie -no-pie` driver arguments
and requires the **actual output file** to be an x86_64 `ET_EXEC` ELF. Linker
flags that still produce `ET_DYN` cause `BUILD_FAILED`, even if compilation
succeeded. The profile participates in build identity.

`artifact.elf` reports availability, ELF class/endianness/type/machine,
`entryAddressHex`, relevant program headers (`PT_LOAD`, `PT_INTERP`,
`PT_GNU_STACK`, `PT_GNU_RELRO`) and a GNU build ID when found in `PT_NOTE`.
Inspection uses bounded regular-file reads, independent of `readelf` and debug
symbols. It rejects malformed/truncated metadata and unsupported formats.
This is executable metadata, not section/symbol/DWARF or runtime module indexing.

`launch.addressPolicy` accepts:

- `native`: do not ask GDB to disable randomization.
- `disable-aslr` (default): ask GDB to disable it, then report actual evidence.
- `require-fixed`: require x86_64 `ET_EXEC` and verify `ADDR_NO_RANDOMIZE` in
  the owned process's personality at entry. If verification is denied,
  unavailable or false, launch fails with `LAUNCH_FAILED` and stops the inferior.

Each observation retains `executionLayout` from entry: requested policy, ELF
type, `aslr.requestedDisabled`, `aslr.verifiedDisabled`, evidence/personality mask,
kernel-reported address boundaries, process start time and `runFingerprint`.
`verifiedDisabled:null` means evidence unavailable. The fingerprint covers the
binary hash, requested argv/environment/input and policy; it is **not** a full
fingerprint of inherited environment, files, libraries or external state.
It identifies launch inputs; it does not certify replay.

This evidence is sampled at entry, not continuously: target code can later
change its personality or mappings. `inspectProcess` reads current metadata.
Kernel address fields may be redacted to zero; do not interpret zero as an
absent mapping. No global ASLR/sysctl setting is changed. Allocator ordering,
arenas/tcache, thread schedules and external effects remain unverified:
`allocatorDeterminism:"not-established"`, `replayVerified:false`, `restore:"none"`.

## Process diagnostics and the 2D map

```json
{"kind":"inspectProcess"}
```

`result.inspection` contains separate availability/coverage for `stat`,
`personality`, `status`, `executable`, `fileDescriptors`, `memory` and `system`.
The collector pins `/proc/<pid>` and checks start time before/after collection.
Optional denied files do not discard other valid sections. It reads status
and personality, the exe/fd symlink targets, `smaps_rollup` totals, kernel and
page-size evidence. Limits are 64 KiB per proc file, 128 descriptors and 4096
bytes per symlink; truncation or denial is explicit. Descriptor targets are
listed, never opened. Environment and command-line contents are not collected.
Non-UTF-8 paths use a null text field and exact `*BytesHex` companion.

`observation.memoryMap` remains the mapping snapshot for a stop. Regions are
virtual `[startAddressHex,endAddressHex)` intervals, including stack, heap,
shared libraries, anonymous ranges, guard pages and kernel special mappings.
Permissions describe inferior access; ptrace/GDB can sometimes read a page
with no inferior read permission. A VMA does not identify an allocation, object,
vtable or resident physical page. Map metadata does not mark
`observation.coverage.memory` as captured bytes.

```json
{"kind":"diffMemoryMaps","beforePoint":{"branchId":"main","eventOrdinal":2},"afterPoint":{"branchId":"main","eventOrdinal":3},"start":0,"count":100}
```

Both observations must still exist and contain complete map snapshots. Each
change has `kind:added|removed|changed` and `before`/`after` regions. Exact
interval endpoints define a match: splitting or merging a VMA appears as
removed/added regions, not a claim about allocation or object lifetimes.
`start`, `totalChanges`, `hasMore` page the result. Runtime ELF load bias is available through `inspectModules` below.
Symbol/DWARF lookup and automatic vtable/RTTI overlays remain future work; existing
`readMemory` can already follow an object address through its vptr into a table.

## Immutable byte captures and differences

Use actual addresses from current variables/maps in place of this example:

```json
{"kind":"captureMemory","ranges":[{"addressHex":"0x404020","byteCount":16}]}
```

The response `result.capture` has `id`, process/stop/point, `coverage` and
`ranges`. A readable range has `available:true`, `bytesBase64`, `addressHex`,
`byteCount` and `unreadableBytes:0`. A range that cannot be fully captured has
`available:false` and an explicit reason; missing bytes are never zero-filled.
There are at most eight nonoverlapping ranges and 64 KiB total, or the smaller
advertised `maxCaptureBytes`. Individual reads are bounded and sequential;
externally modified shared mappings are not an atomic snapshot of the world.

```json
{"kind":"readMemoryCapture","captureId":"capture-1"}
{"kind":"diffMemoryCaptures","beforeCaptureId":"capture-1","afterCaptureId":"capture-2","start":0,"count":100}
```

Capture differences require the same addresses, lengths and order. The result
contains `comparedBytes`, `changedBytes`, unavailable ranges, and paged contiguous
changed runs with `beforeBytesHex`/`afterBytesHex`. A range unavailable at either
end is not compared. Unchanged bytes at the two endpoints do not prove that
there were no intermediate writes.

## Registers and bounded instruction tracing

```json
{"kind":"readRegisters","registers":["rip","rsp","rax","eflags"]}
{"kind":"traceInstructions","count":32,"registers":["rip","rax"],"memoryRanges":[{"addressHex":"0x404020","byteCount":16}]}
```

Omitted/empty `registers` selects the x86_64 general-purpose registers, `rip`
and `eflags`; at most 64 explicit unique plain names are accepted. Unknown
names fail, and non-hex representations (including some vector/pseudo-register
formats) have explicit unavailable state.
This is a machine-register view of frame 0, not a reconstructed caller frame.
Tracing always includes `rip` and accepts empty `memoryRanges` for register-only
work. It allows at most 256 instruction attempts and eight nonoverlapping
memory ranges totalling at most 4096 bytes, subject to configured limits.

`traceInstructions` is an execution command. It emits an accepted response,
`instructionTraceRecorded` and `commandFinished`. A usable final stop also
emits observation/state. A failure before execution leaves the current
observation unchanged; loss of GDB publishes a failed state with no live point.
Use the event's `traceId` to fetch pages:

```json
{"kind":"readInstructionTrace","traceId":"trace-3","start":0,"count":64}
```

The trace carries initial register/memory snapshots, before/after stop points,
`requestedInstructions`, `attemptedInstructions`, `executedInstructions`,
status and termination reason. Entries contain before/after PCs, register
changes and before/after selected memory ranges. `instructionCompleted` is
false when an attempted instruction stops for a breakpoint, signal, input wait
or another non-completion condition. Entry count is not itself the number of
completed instructions. Pause/cancel/stop, input wait, exit and timeouts produce
bounded results and the current live state; tracing does not restore its start.

Coverage is `selected-instruction-boundaries`: several stores can be observed
between source lines when they occur in different instructions. Same-value
writes, changes undone inside one instruction, unselected memory/registers,
other-thread write history and semantic C++ assignments are not captured.
Other threads may run while the selected thread steps: a memory delta is
evidence of changed bytes, not attribution of every change to that instruction.
There is no retroactive query for unrecorded steps. This is a forward
instruction trace, not rr/`record full`, verified rollback or runtime injection.

## Verification of this slice

The 26 registered CTest checks pass in Debug and ASan/UBSan builds. The shared
contract check validates 819 real request/response/event frames, including output,
module, recorder probe and recorded-navigation gateways. The existing five frontend-harness checks and four contract
fixture checks also pass.

Regression coverage includes malformed/oversized ELF and proc metadata,
64-bit address precision, actual PIE/ET_EXEC output, constructor-cleared ASLR,
intermediate `0 → 1 → 2 → 0` stores, same-value-write limitations, syscall input
wait/resume, Pause/Stop/cancel, signals/exit, unmapped-page boundaries, retained
I/O, map lifecycle, paging/eviction, stale sessions/stops and a deterministic
GDB failure during the final trace snapshot. These checks validate the installed
Linux/GDB/runtime combination; they do not establish a cross-distribution ABI
matrix or verified restore of arbitrary observations.


## Runtime ELF modules for the 2D memory view

```json
{"kind":"inspectModules"}
{"kind":"readModuleSnapshot","snapshotId":"modules-1"}
```

The live command requires `expectedStop`. Its immutable `moduleSnapshot`
includes mapped file identity, ELF program headers, load instances and load
bias, and intersections of `PT_LOAD` segments with actual VMAs. A module can
have several load instances. Anonymous BSS tails are linked only by segment
geometry. Unassigned ranges remain explicit; a path alone does not prove an
ELF image or module membership. Negative load bias is possible for manually
mapped ET_EXEC files. Hex and decimal addresses/identities remain strings.

Collection pins process identity, verifies opened device/inode and stable file
metadata, bounds total ELF reads to 8 MiB and modules to 128, and reports partial
coverage. It never executes a target file. Deleted, denied, malformed or changed
files retain their available map evidence and explicit failure reason. The
snapshot shares the bounded inspection store with memory/trace captures and
remains readable after unload or exit, until eviction or a new session.
`evidenceScope:current-os-state` explicitly separates procfs evidence from a
restored GDB instruction position. Symbols, DWARF objects and automatic vtable
recognition are additional layers, not inferred from mapping names.

## Exact output journal

```json
{"kind":"readOutputJournal","stream":"stdout","fromByte":0,"byteCount":65536}
```

This session-scoped read works after process exit. `segments` contain exact
`bytesBase64` or explicit `gap` intervals. Embedded NUL and invalid UTF-8 survive
unchanged. Transport output is appended once; repeated stops, history reads and
reverse execution do not erase or duplicate flushed output. Retention is
bounded by `maxOutputJournalBytesPerStream` and 256 segments per stream. Bytes
lost from the transport tail between observations are gaps, never invented
characters. This is a retained session journal, not a durable disk archive.

An optional `point` selects a retained observation. `selectedThroughByte`
indicates its known output prefix; `null` means no proven prefix exists for
that execution position. Physical `totalBytes` still describes all output
already received. `observation.outputCursor` explains whether the prefix came
from transport, a known recording checkpoint, or is unknown. Pending C/C++
stream buffers remain in the selected observation and are not appended to the
journal until they actually reach the output transport.

Recorder commands and their separate external-effect limits are documented in
[RECORDING.md](RECORDING.md).
