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
| `inspectModules` / `inspectModuleSymbols` | Required | Capture current module mappings or one module's ELF sections/symbols. |
| `readModuleSnapshot` / `readModuleSymbols` | No | Read retained module metadata or symbol pages. |
| `inspectVariableLayout` | Required | Capture declared type/storage layout for an emitted root locator. |
| `readVariableLayout` | No | Read a retained variable layout. |
| `inspectVtable` | Required | Decode a selected vptr slot under an explicitly requested ABI profile. |
| `readVtableSnapshot` | No | Read a retained vptr/header/word capture. |
| `inspectScalarStorage` / `writeScalarStorage` | Required | Capture authoritative scalar type/storage; compare and edit through a retained snapshot. |
| `readScalarStorage` | No | Read an immutable scalar storage snapshot. |
| `writeMemory` | Required | Compare, write and verify bounded native storage bytes; retain intervention provenance. |
| `writeMemoryBatch` | Required | Preflight disjoint ranges, apply in request order and retain partial/final evidence as one intervention. |
| `writeScalarStorageBatch` | Required | Bind every scalar snapshot/type/address, then apply checked disjoint storage edits with per-phase values. |
| `writeRegister` | Required | Compare and edit one verified native 64-bit general register; retain before/write/readback evidence. |
| `readMemoryIntervention` / `listMemoryInterventions` | No | Read memory/storage interventions only. |
| `readRegisterIntervention` / `listRegisterInterventions` | No | Read register interventions only. |
| `readIntervention` / `listInterventions` / `listBranches` | No | Read all session interventions and their shared branch ancestry. |
| `readOutputJournal` | No | Read retained physical output bytes and gaps. |
| `probeRecorders` | No | Exercise a separate supplied fixture; no live session is required. |
| `probeRuntime` | No | Verify fixed syscalls, RW→RX execution and state restoration in a separate shipped fixture. |
| `runRuntimeHelper` | Required | Execute the opted-in scratch helper in the live native process; retain restoration evidence and an intervention branch. |

Captures and traces share a separate bounded store: at most 128 records and
`capabilities.limits.maxInspectionStoreBytes` serialized bytes (16 MiB by
default). Oldest records are evicted first; missing records return
`HISTORY_EVICTED`. A fresh launch clears this store. A repeated historical read
does not execute the inferior, mutate the capture or append output.

Address fields and other fields named `*Hex` are hexadecimal strings. Layout
sizes, offsets and array bounds/counts are decimal strings. Parse exact integer
strings with `BigInt`, not JavaScript `Number`. Bounded page/read byte counts
within the advertised budgets are numbers; use the DTO field types.
Stop/history ordinals are session-local, not global timestamps.

Live inspections (`readRegisters`, `readVariables`, `inspectVariableLayout`,
`disassemble`, `readRecording`, and the memory/scalar gateways) leave queued
stdin and requested EOF pending while servicing GDB replies. This applies to
failed reads too. They can drain already produced stdout/stderr, but never
advance instruction execution or input delivery merely to answer a query.
Normal execution and explicit input commands keep their delivery semantics.
Saved observations/history remain immutable: a transport change is visible in
the next actual stopped snapshot, not rewritten into an earlier observation.

## Isolated runtime probe

```json
{"kind":"probeRuntime"}
```

`capabilities.runtimeProbe:"isolated-linux-x86_64-syscall-v1"` advertises this
diagnostic command. It accepts no arguments; executable paths, syscall numbers,
payload bytes and time limits are not client-selectable. It works before launch
with `session:null`, while a session is stopped, and after termination. A supplied
session or `expectedStop` must still match the normal envelope rules.

The result is `{kind:"runtimeProbe",probe:RuntimeProbeDTO}`. Its scope is
`isolated-runtime-fixture` and profile is `linux-x86_64-syscall-probe-v1`.
`gdbVersion` and `execution` retain separate bounded process diagnostics.
`available:true` requires successful process completion and a complete, strictly
validated evidence record with every check true. A missing/malformed proof or a
failed stage returns `available:false` and a reason; successful GDB startup alone
does not establish readiness. A well-formed record with failed checks may be
retained, but never makes the result available.

The trusted fixture exercises `getpid`, anonymous private `mmap` with RW access,
a fixed payload write, expected `EINVAL` from an unaligned `mprotect`, an RW→RX
transition, execution of one fixed instruction, and `munmap`. It never requests
RWX permissions. A pending `SIGUSR1` must stop before the helper executes and
without entering its handler. After each operation it compares the exact bytes
of GDB-reported registers (including floating/vector state), the bounded original
stack mapping, `errno`, the signal mask, and the trusted syscall/entry instructions.
Final mappings must match the original snapshot. Proof is printed only after the
restored fixture exits normally.

`evidence` is null when no valid record exists. Otherwise its fields are:

| Fields | Meaning |
| --- | --- |
| `profile`, `pid`, `pageSize`, `scratchAddressHex` | The isolated experiment's identity and allocation. The address is diagnostic and is no longer allocated on success. |
| `getpid`, `allocated`, `writable`, `executable`, `payloadExecuted`, `released`, `deniedSyscall` | The fixed syscall/allocation/permissions checks above; `deniedSyscall` means the expected `EINVAL`, not a general seccomp test. |
| `registersRestored`, `stackUnchanged`, `errnoUnchanged`, `signalMaskUnchanged`, `codeUnchanged` | Exact comparisons in the declared fixture scope; `codeUnchanged` covers the trusted syscall and entry instructions. |
| `signalStopVerified`, `handlerNotRun` | The controlled signal was intercepted before execution and its handler did not run. |
| `registerCount`, `stackBytes` | The number of compared registers and size of the compared original stack mapping. |

The default shared deadline is `limits.runtimeProbeTimeoutMs` (10000 ms) for
version checking plus execution, followed by bounded process cleanup. Each stage
bounds combined raw stdout/stderr
to `limits.maxRuntimeProbeOutputBytes` (65536 bytes). Cancellation targets this
request's separate process, including a pre-main inferior in a different process
group; it never interrupts the live engine. A cancellation at the final handoff
still sets `cancelled:true`, `available:false`, `reason:"cancelled"`. Diagnostics
report failure to confirm cleanup where OS inspection/signalling is unavailable.

No session stop, observation, queued stdin/EOF, output journal, branch or
intervention record is changed. This result certifies only the fixed experiment
in its current environment: arbitrary inferior calls/syscalls, live code injection,
external-effect rollback and recorder-compatible interventions remain unsupported.
Target threads, seccomp, signal state, loader/CET and ABI evidence need their own
live-target validation. Normal GDB inferior function calls can have additional
effects; the probe deliberately uses a prelinked syscall instruction and explicit
register restoration. See [GDB inferior calls](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Calling.html),
[signal handling](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Signals.html),
[register bytes](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Values-From-Inferior.html)
and [mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html).

## Live runtime scratch helper

`capabilities.runtimeHelper:"linux-x86_64-scratch-v1"` exposes one fixed live
operation. First opt into the build profile:

```json
{
  "revisionId": "runtime-config-1",
  "compiler": "clang++",
  "flags": ["-std=c++20", "-g", "-O0"],
  "outputDirectory": ".phantom/build",
  "addressProfile": "fixed-executable",
  "runtimeProfile": "linux-x86_64-scratch-v1"
}
```

This is the `configuration` member of a normal build command. The default
`runtimeProfile:"none"` adds no helper. Opt-in adds a versioned assembly input
in the reserved `.phantom-runtime-v1` snapshot subtree; user documents cannot
occupy it. The helper source hash participates in build identity. Its three
bytes (`syscall; int3`) must belong to a unique hidden function in a dedicated
RX section and matching non-writable PT_LOAD in the actual ELF64 little-endian
x86-64 ET_EXEC. Stripped/ambiguous/incompatible output fails the build. The
verified `artifact.runtimeHelper` manifest contains `profile`, `symbol`,
`addressHex`, `bytesHex` and `helperSha256`; ordinary builds omit it.

At a current native stop, send:

```json
{"kind":"runRuntimeHelper","profile":"linux-x86_64-scratch-v1"}
```

The normal envelope must include the current session and exact `expectedStop`.
Launch must explicitly select `processProfile:"single-process-v1"`; see
[process creation profile](#process-creation-profile). A successful build alone
does not establish that another process cannot share its address space.
The command accepts no executable path, syscall number, payload, address or
timeout. It executes `getpid`, allocates one private RW page, writes a fixed
`movabs` instruction, changes the page to RX, single-steps that instruction,
and unmaps the page. No retained allocation or arbitrary-code API is implied.

Preflight requires exactly one stopped native thread, the original launched
executable hash, matching live helper bytes in a private RX mapping, verified
GDB x86-64 metadata, readable FP/vector/general registers, and a main stack
mapping no larger than 1 MiB. A known glibc DWARF `errno` symbol is required
(on the Ubuntu test runner, `libc6-dbg` supplies this metadata). The backend
never calls `__errno_location` or a user function to obtain it. Missing evidence,
record-full, input waits, an existing signal stop, pending signals or kernel
syscall/restart state reject the operation before mutation.

The helper temporarily changes GDB signal handling to stop before a handler can
run. Success requires exact restoration of those policies and all captured
register bytes, unchanged original stack bytes, `errno`, kernel signal mask,
helper instructions and final mappings. These are declared comparisons, not a
rollback of elapsed time, kernel accounting, allocator decisions or the external
world. A signal, denied syscall, lost acknowledgement, timeout, cancellation
during execution or failed verification closes the debugger and inferior. No
further cleanup syscall executes after an unexpected signal: resuming could
discard its original delivery information. Process termination releases scratch
storage on these failure paths.

The result is `{kind:"runtimeIntervention",intervention,throughSequence}`.
`RuntimeInterventionDTO` uses the existing identity, before/after stop, branch,
context status and refresh-error fields, with `target` set to the build manifest.
Its report has `profile`, `writeAttempted`, `executionAttempted`, `debuggerAlive`,
`cancelled`, `outcome`, `phase`, `evidence` and `error`. Attempt flags become true
at the execution-command send boundary: execution may have happened even without
an acknowledgement. `outcome:"verified"` means all declared checks passed;
`"failed"` retains uncertainty and the concrete error. Preflight rejection is a
normal protocol error without an intervention entry.

Success evidence records `pid`, `pageSize`, historical `scratchAddressHex`,
`registerCount`, `stackBytes` and these thirteen checks: `getpid`, `allocated`,
`writable`, `executable`, `payloadExecuted`, `released`, `registersRestored`,
`stackUnchanged`, `errnoUnchanged`, `signalMaskUnchanged`, `signalPolicyRestored`,
`codeUnchanged`, `mapsRestored`. Missing proof is null, never inferred from the
requested operation. A successful scratch address is already unmapped.

Every attempted helper, including a failed one, has one audit and branch; a
verified helper refreshes the stop even though the compared state was restored.
An unverified attempt clears the live observation and publishes a failed state.
`readIntervention`/`listInterventions` include runtime entries; memory/register
category queries retain their existing meaning. Exact retries return the stored
response after stop changes or debugger death, without re-execution. The shared
ledger reserves 32 KiB before entry and enforces its existing count/byte limits.
Queued stdin/EOF, previous observations and the physical output journal are not
replayed or rewritten by this operation.

`limits.runtimeHelperTimeoutMs` is 10000 for the shared preparation/execution
deadline, followed by bounded termination if needed. `cancel` targets the active
request; Pause/Stop wait for it to finish. A preflight cancellation drains its
outstanding read command before returning. Cancellation after verified execution
is sealed separately as `cancelled:true`; the completed operation's evidence is
retained. Restoring RIP to an enabled source breakpoint can make the next
Continue stop at that same breakpoint once more. This is exposed as a real stop;
the backend does not silently advance additional user instructions.

## Process creation profile

`capabilities.processProfiles` advertises `native` and `single-process-v1`.
The optional launch field `processProfile` defaults to `native`. To request
the restricted profile, add this to a normal launch command:

```json
{"processProfile":"single-process-v1","recordingProfile":"native","stopAtEntry":true}
```

The trusted I/O wrapper installs `no_new_privs` and a Linux x86-64 seccomp BPF
filter before executing the target, including its loader, preload libraries
and constructors. `fork`, `vfork`, `clone` and `clone3` return `EPERM`; this also
prevents `pthread_create`. Non-x86-64 syscall ABIs and x32 syscall numbers are
rejected, including attempts through `int 0x80`. Other native syscalls retain
their ordinary behavior. This is a process-creation restriction, not an I/O or
general security sandbox. Filter inheritance and architecture checks follow
the [kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).

The profile closes a specific runtime-helper gap: `clone(CLONE_VM)` without
`CLONE_THREAD` can create a separate process which changes the same address
space while GDB sees one stopped thread. It can replace a mapping without
changing the final `/proc/maps` text. Counting threads or comparing map rows
does not prove ownership. [Linux clone](https://man7.org/linux/man-pages/man2/clone.2.html).

Launch succeeds only after the wrapper acknowledges successful installation
and the stopped owned process confirms `NoNewPrivs:1`, `Seccomp:2`, one thread
and an active ptrace tracer. A missing/wrong acknowledgement or unavailable
kernel evidence fails launch; there is no fallback to `native`. The live
scratch helper requires this verified profile and rechecks kernel evidence
before execution. A `native` launch remains usable for ordinary debugging,
but `runRuntimeHelper` rejects it before creating an intervention.

`observation.executionLayout.processIsolation` records launch evidence:

```json
{"requested":"single-process-v1","verified":true,"mechanism":"linux-seccomp-bpf","noNewPrivileges":true,"seccompMode":2}
```

For a native launch it contains `requested:"native"`, `verified:false`,
`mechanism:"none"` and null kernel fields; this does not claim the environment
has no other seccomp policy. The selected profile participates in the run
fingerprint. Old observations retain their original launch evidence.

This version requires an entry stop and native recording; record-full is
rejected before launch. The restriction is inherited across target exec and
cannot be disabled during the session. Relaunch with `native` to run a program
which needs threads or child processes. Memory allocation ownership across
user execution remains a separate problem: this profile does not implement
retained allocations, release authority or C++ object lifetime.

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

## ELF sections and symbols at runtime

Obtain a module ID from the current `inspectModules` result, then capture its
section/symbol metadata at the same `expectedStop`:

```json
{"kind":"inspectModuleSymbols","moduleId":"<module.id>"}
{"kind":"readModuleSymbols","snapshotId":"symbols-1","start":100,"count":100}
```

Both return `kind:moduleSymbols` with an immutable `snapshot`, `start`,
`totalSymbols` and `hasMore`. Capture returns the first 100 retained symbols
(or the configured smaller page size). Further pages read only the saved
capture, including after `dlclose` or exit. IDs require the session that created
them. `totalSymbols` counts captured records; `report.elfMetadata.symbolCount`
counts entries declared by the file's symbol tables. A truncated capture may
therefore have fewer available records than the file. `.symtab` and `.dynsym`
retain separate table/index identities; aliases and duplicate names are not
silently collapsed.

The parser reads ELF64 little-endian x86-64 metadata from a verified descriptor.
Sections expose flags, file offset, virtual address, size and alignment.
`SHT_NOBITS` such as BSS does not promise bytes at its file offset. Symbol
values, sizes and addresses are strings, preserving all 64 bits. Names retain
exact UTF-8 or `name:null` plus `nameBytesHex`. A stripped or sectionless ELF can
legitimately provide fewer symbols or none; this does not mean the process
contains no code or objects. External debug links and separate DWARF files are
not traversed by this parser.

`runtimeLocations` applies each proven PT_LOAD load bias to allocated sections
and defined symbols, with intersections against actual mapped ranges. Negative
bias, overflow, partial mapping and missing load instances remain explicit.
Exhausted matching budgets use unknown evidence rather than inventing an
unmapped address. Zero-size symbols describe a point, not an extent inferred
from the next symbol. TLS offsets require thread-specific resolution; absolute,
common and undefined symbols do not receive fabricated relocated addresses.
GNU IFUNC addresses identify resolvers, not the function selected by a call.
Dynamic symbol interposition and runtime relocation contents are not inferred.

`classification:vtable|typeinfo|typeinfo-name|vtt` is evidence from the Itanium
mangled-name prefix only. It supports labels in a **2D** memory view; it does not
prove that an arbitrary pointer is a valid object/vptr or decode every slot of
a table. Table groups, secondary address points and construction tables require
additional ABI evidence. A vptr can point inside a table rather than at the
symbol's first byte. See the [Itanium ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable)
and [ELF symbol specification](https://gabi.xinuos.com/elf/05-symtab.html).

Capture is limited to one module, 4 MiB metadata reads, 1024 sections and 4096
symbols, with additional bounded relocation/matching output. Process identity,
current maps and opened file metadata are checked before/after inspection.
The shared inspection store bounds retained JSON. File metadata plus mappings
is evidence of current OS state, including when GDB is replaying old machine
state; it is not a memory-content hash or an allocation lifetime record.

## Declared variable layout from GDB/DWARF

Use a root variable locator from the current observation or a `readVariables`
result at the same stop:

```json
{"kind":"inspectVariableLayout","locator":"frame:0:object"}
{"kind":"readVariableLayout","snapshotId":"layout-2"}
```

The live request requires `expectedStop`. Results have `kind:variableLayout`
and an immutable `snapshot.layout`. They describe the declared type, byte size,
member offsets, compact array shape/stride, union overlap and compiler-provided
artificial fields. This is structure metadata, not a value evaluation or an
allocation trace. `lifetime:unknown` remains explicit even when GDB supplies a
storage address before a source declaration has executed.

The embedded helper uses GDB's Python metadata API and exact local-variable
names (`frame:<level>:<ASCII identifier>` in this profile). It accepts no
expressions, casts, arbitrary Python, dynamic-type queries
or user helper paths. It never follows pointers/references or stringifies a
`gdb.Value`; inferior function calls stay disabled. Root locators must be emitted
at the current stop; ambiguous shadowed names are rejected. The bounded
per-stop cache retains up to 4096 supported root locators across frame queries;
saturation preserves already issued entries and reports a limit for new ones. Missing Python or
debug metadata has an explicit error/unavailable result.

Bitfield offsets use `bitOffsetConvention:gdb-target-bitpos`, with separate
bit size and offset within a byte; bitfields have no invented address. Static
members are not placed in object storage. Union fields overlap without a claim
about the active member. Reference referent addresses are not mislabeled as
reference-slot storage. Optimized-out variables may retain type metadata while
storage is unavailable. Base-class addresses stay unknown where this Python
API cannot prove whether an offset requires virtual-base evaluation.

Arrays use a first-element template, bounds, count and stride; a large array is
not expanded element by element. Limits are depth 8, 128 nodes, 128 fields,
256 characters per name and 256 KiB emitted helper JSON. Truncation is explicit;
these are traversal/output limits, not a byte quota on GDB's own DWARF decoder.
The normal debugger command deadline still applies. Metadata API reference:
[GDB Types in Python](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Types-In-Python.html).

## Vptr, table headers and raw table words

```json
{"kind":"inspectVtable","abi":"itanium-x86_64-absolute-v1","vptrAddressHex":"0x12345678","maxEntries":16}
{"kind":"readVtableSnapshot","snapshotId":"vtable-3"}
```

`vptrAddressHex` is the address of the **storage containing the vptr**, such as
the compiler-provided artificial field of a polymorphic object or a selected
base subobject. It is not the vtable address itself. The frontend can obtain
the storage address from layout metadata or an explicit memory selection.
The backend does not assume that every object begins with a vptr, enumerate
all base subobjects, or follow user expressions. The request requires the
current session and `expectedStop`; it leaves execution and history position
unchanged. Both commands return `kind:vtableSnapshot` with an immutable
`snapshot.report`.

This profile interprets 8-byte little-endian absolute pointers under the
Linux x86-64 Itanium layout. `abiEvidence:requested-profile` records the caller's
choice, not an automatically verified compiler ABI. Relative vtables are not
supported; a wrong profile cannot always be detected from arbitrary bytes.
ELF64, an x86-64 machine ID and a `_ZTV` name alone do not establish the encoding.
LLVM can use 32-bit relative components in the same target environment; see
[LLVM vtable generation](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/CGVTables.cpp).

The capture retains exact `bytesHex` for the vptr slot, the two-word header
before its address point and up to 64 following words. Under the requested
profile, the header contains signed `offsetToTopDecimal` and an RTTI pointer.
`topAddressCandidateHex` is checked address arithmetic, not proof of allocation
ownership or object lifetime. A positive offset can occur during construction;
zero RTTI can occur without RTTI support. `lifetime:unknown` stays explicit.
The profile follows [Itanium virtual tables and construction tables](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable).

`tableSymbols` labels matching `_ZTV` and compiler `_ZTC` ranges;
`rttiSymbols` labels exact `_ZTI` addresses. Metadata is collected from verified
mapped files. `entries[].functions` labels exact `STT_FUNC` addresses, preserving
aliases; an executable mapping alone is only `classification:executable-address`.
No virtual function or typeinfo function is invoked. Missing symbols do not
prove an invalid vptr. Prefixes, loaded mappings and raw memory remain separate
evidence; symbol interposition and allocation/type identity are not inferred.
Table/RTTI labels require ordinary address-bearing `STT_OBJECT` symbols;
an IFUNC resolver or a function with a misleading `_ZTV` prefix is not table
evidence. `coverage` describes this bounded window and its metadata evidence,
not discovery of every virtual method or the class inheritance graph. An empty
`functions` list means no matching exact function label was captured.

Entries are **words, not methods**. A symbol can contain a primary table plus
secondary tables and their headers; `tableEnd:unknown` prevents its size from
becoming a fabricated method count. Null/non-executable words do not terminate
the scan. A proven symbol extent or readable mapping can bound the captured
window, and `scanStop` explains why it ended. An address point at the end of a
symbol can legitimately yield no following words. The reader never interprets
a partial word/header as a complete value.

Memory reads require readable mappings, even where GDB could bypass page
protection. The decoder performs at most five raw reads and 560 bytes, including
vptr/header rereads; matching samples are `sampled-not-atomic`, not proof that
shared memory remained unchanged. Up to four distinct module reports each have
a 1 MiB metadata-read budget. Truncated/missing symbols and unavailable memory
remain explicit. Complete current mappings are compared before and after the
request. `evidenceScope:debugger-memory-and-current-os-metadata` matters during
record-full replay: GDB memory can reflect the replay position while procfs and
mapped-file metadata still describe the current OS.

Historical reads use saved JSON only and survive object destruction or process
exit until retention eviction or a new session. They do not reread a pointer
that may now refer to a different allocation. The shared inspection store and
its existing byte/record limits apply. No new graphical renderer is included.

## Checked native memory interventions

`capabilities.memoryWrite = "native-private-memory-v1"` enables explicit raw
storage edits. `variableWrite` remains false: a storage address does not prove
C++ object lifetime, initialization, type correctness or mutability.

```json
{
  "kind": "writeMemory",
  "profile": "native-private-memory-v1",
  "addressHex": "0x7fffffffdabc",
  "expectedBytesHex": "07000000",
  "replacementBytesHex": "2a000000"
}
```

Supply the current session and `expectedStop`. This example replaces four
little-endian bytes representing 7 with 42; the command itself has no integer
or endianness semantics. Obtain actual addresses/bytes from the current stop,
then read the report rather than assuming success from the response envelope.

The first profile requires native execution, phase `stopped`, exactly one
confirmed stopped thread, and one complete current `rw-p` mapping covering the
entire range. Current procfs maps must match the observation. Shared,
executable, read-only, unmapped, cross-VMA and overflowing ranges are rejected.
Both byte strings must contain the same nonzero number of literal hex bytes,
up to `maxMemoryWriteBytes` (256 by default). Expressions are never evaluated.
`waitingForInput` and every `gdb-record-full` launch are rejected, including
when recording has become inactive. Ordinary native execution stays available.

The backend reads the whole range and compares it with `expectedBytesHex`.
A mismatch (`conflict`) or equal replacement (`unchanged`) does not send a
write or advance the stop. Otherwise it sends one GDB/MI memory write, without
the optional repeat count, then reads again even if GDB reported an error.
There is no automatic retry or rollback. This is **not atomic compare-and-swap**:
external interference, same-value writes and ABA changes are not excluded.
A private mapping also does not establish ownership of a live C++ object.

The synchronous result is `{kind:"memoryIntervention", intervention,
throughSequence}`. `report.outcome` distinguishes `verified`,
`readback-mismatch`, `unverified`, `write-rejected`, `read-before-failed`,
`conflict` and `unchanged`. Read `writeAttempted`, `writeAcknowledged`, exact
before/after bytes and phase-tagged errors independently: a verified final
value can coexist with a failed GDB acknowledgement. Partial reads contain
only their proven prefix; missing evidence is null.

Every potentially submitted write creates a lineage branch from the current
live point, even if final bytes equal the original bytes. The response is
followed by `branchCreated`, `observation` (`reason:"mutation"`) and `state`.
The PC does not advance, but stop identity and state revision do. If a fresh
stopped snapshot cannot be confirmed, the debugger is closed and the events
are `branchCreated`, then failed `state` with `live:null`; the current
observation is null. The audit still records the attempted effect, its
`contextStatus` and `refreshError`. A failure before submitting a write can
also close the debugger, without creating a branch. Inspection/write/refresh
operations in this path do not feed pending stdin or EOF.

`readMemoryIntervention{interventionId}` returns the immutable audit;
`listMemoryInterventions{start,count}` pages it. `listBranches` returns the
current branch and each branch's parent point/intervention ID. History lookup
uses the full `(branchId,eventOrdinal)` pair; `listHistory` includes only that
branch's own observations. Follow parent links to display ancestry. Ordinals,
state revisions and event sequences stay monotonic across branches.

Branches record interventions in this one process. They do not clone the
process, restore the old state or preserve an executable alternate future.
Old observations, captures and traces remain unchanged subject to their
existing retention limits. Physical output is one process journal across
branches; its `branchId` describes the selected point (or current branch),
not separate output ownership. Selecting an old point does not remove later
physical output. The launch fingerprint remains a launch fingerprint; use
branch/audit provenance when comparing altered runs.

Retries are session-scoped: an identical `requestId` **and entire request**
returns the original response with no additional writes or events, even after
the stop changed or the process exited. A different request with that ID is
rejected. Event subscribers use sequence/replay as usual; a duplicate reply's
`throughSequence` does not promise a second event delivery. No guarantee
survives backend restart or a new session.

The ledger is separate from evictable inspections: at most 128 records and
`maxInterventionStoreBytes` (4 MiB default). Single writes and raw batches reserve
32 KiB each; typed scalar batches reserve 64 KiB each. Mixed operations consume
the sum of their reservations, so 64 typed batches fill the default byte budget.
Encoded write requests are limited to 4096 bytes. A full ledger rejects new
operations before writing; IDs are never silently evicted. Comparison
conflicts/no-ops also occupy records. A successful new launch or workspace
change clears the ledger and branches. Export needed audits before that.

Bounded general-register writes are described below. Runtime code injection,
control-register edits and branching inside recorded execution remain separate
work. Bounded multi-range byte edits are described below.
The MI write command and recorder side effects are described in the official
[GDB data manipulation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Data-Manipulation.html)
and [record/replay](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html)
manuals.

## Batched memory interventions

`capabilities.memoryWriteBatch = "native-private-memory-batch-v1"` enables
`writeMemoryBatch` with a current session and `expectedStop`. For example:

```json
{
  "kind": "writeMemoryBatch",
  "profile": "native-private-memory-batch-v1",
  "edits": [
    {"addressHex":"0x1000","expectedBytesHex":"01000000","replacementBytesHex":"02000000"},
    {"addressHex":"0x2000","expectedBytesHex":"00","replacementBytesHex":"01"}
  ]
}
```

The example addresses must be replaced with addresses captured from the current
stopped process. Each edit requires equal nonempty expected/replacement bytes.
Limits are `maxMemoryBatchRanges` (8) and `maxMemoryBatchBytes` (256, or a smaller
configured memory-read limit). Addresses are parsed numerically: overlapping
ranges, including differently spelled aliases of the same address, are rejected.
Adjacent ranges and descending addresses are allowed; execution preserves request
order. Each range must fit entirely in one current `rw-p` VMA. Ranges may occupy
different private mappings. All mapping policies are checked before any write.
Native execution, one stopped thread and an ordinary stopped phase are required;
record-full and input waits are rejected just as for single-range writes.

The operation has three phases:

1. **Preflight:** read and compare all ranges before sending any write. A failed
   read or mismatched expected byte aborts at that range with zero writes.
2. **Execution:** compare each range again, then use the existing checked single
   write/readback path. No-op ranges are also rechecked. The first conflict,
   rejected/partial write, read failure or missing GDB acknowledgement stops all
   later writes. An error acknowledgement stops the batch even if readback found
   the requested bytes. Earlier effects are retained and no rollback is attempted.
3. **Final sampling:** after any attempted write, read every requested range,
   including no-ops and skipped ranges, while GDB remains alive. A read error does
   not suppress evidence from other ranges unless the debugger died. This can
   reveal changes to an earlier range since its immediate write/readback.

The result remains `{kind:"memoryIntervention",intervention,throughSequence}`.
Discriminate by `intervention.profile`: batches have `mappings[]` aligned with
request order instead of the singleton `mapping`. `report.items[]` contains each
item's `index`, address, size, expected/replacement bytes and three independent
evidence records:

- `preflight`: bytes, `matchesExpected`, and an optional read error.
- `execution`: the existing complete single-range report, including whether a
  write was attempted/acknowledged and immediate readback.
- `final`: later bytes, `matchesExpected`, `matchesReplacement`, and a read error.

A null phase means it was not reached. A phase record may itself contain null
bytes or a proven prefix; its comparisons stay null unless the read was complete,
error-free and GDB was alive. Do not replace missing immediate readback with the
later final sample: they describe different moments. A complete mismatch has
`matchesExpected:false` or `matchesReplacement:false`; it is not a read error.

| `report.outcome` | Meaning |
| --- | --- |
| `preflight-failed` | Initial comparison failed; no write was attempted. |
| `unchanged` | All execution comparisons passed and every range was a no-op. |
| `interrupted` | An execution failed; inspect individual effects and skipped items. |
| `verification-failed` | Execution completed, but a final sample failed or differed. |
| `verified` | Execution completed and all final samples matched replacements. |

`failureIndex` identifies the first failure encountered. Later failures during
final sampling do not replace an earlier execution failure, even if the later
failure has a smaller item index. `writeAttempted` is true if any item may have
submitted a write. `atomic:false` and `rollbackAttempted:false` are explicit:
this is sequential observation, not a transaction or simultaneous snapshot.
External writes and ABA changes remain possible. See
[GDB memory commands](https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI-Data-Manipulation.html)
and the kernel's [procfs mapping documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html).

The entire batch consumes **one** shared audit record. Any attempted write
creates **one** lineage branch and one refreshed stop/observation, regardless of
how many items ran. Post-write context failure still closes the debugger and
preserves the report separately from `contextStatus`. Preflight failures and
all-no-op batches create no branch. Historical snapshots/captures are immutable;
physical output remains process-wide and queued stdin/EOF is not delivered by
the operation. Single-range and typed operations retain their existing shapes.

The same 4096-byte request limit, 32 KiB reservation, bounded non-evicting ledger
and whole-request retry identity apply. New preflight/final read messages are
bounded both in UTF-8 bytes and serialized JSON size so escaping cannot overflow
the audit reservation. `readMemoryIntervention`, `listMemoryInterventions` and
`listBranches` expose raw, typed and batch interventions together. A retry after
a partial failure, changed stop or dead debugger returns the original audit
without another write. Backend restart/new-session durability is not implied.
This is a raw-storage gateway. Typed storage batches are described below;
C++ assignment semantics and object lifetime remain separate work.

## Typed scalar storage

`capabilities.scalarStorage = "native-dwarf-scalar-v1"` adds a typed layer over
the checked memory intervention. It supports integer storage of 8/16/32/64
bits and one-byte `bool` on the verified x86-64 little-endian target. It does
not assert that a C++ object's lifetime has begun. The legacy `writeVariable`
command and `variableWrite:false` stay unchanged.

`capabilities.scalarStorageProfiles` additionally advertises
`"native-dwarf-scalar-v2"`, which supports exact `float`/`double` bits as well
as the v1 types. Select it explicitly with
`inspectScalarStorage{locator,profile:"native-dwarf-scalar-v2"}`. Omitting
`profile` still selects v1: float targets remain unavailable with null scalar
metadata/bytes/value. A write's profile must match the issued snapshot;
changing the profile at write time returns `INVALID_REQUEST` before any write.

1. `inspectScalarStorage{locator}` inspects an unambiguous root locator emitted
   at this stop, including roots from paged `readVariables` in another frame.
   It returns `{kind:"scalarStorage",snapshot}` with immutable point/stop/PID,
   authoritative type metadata, address, exact bytes and decoded scalar value.
2. `writeScalarStorage{profile:"native-dwarf-scalar-v1",snapshotId,value}`
   requires that snapshot's current session and `expectedStop`. The backend
   resolves the locator again, compares type/address metadata, encodes the
   requested value, then uses the shared memory compare/write/readback path.
3. `readScalarStorage{snapshotId}` reads the retained snapshot without a live
   process. Snapshots share the existing 128-entry inspection cache; eviction
   yields `HISTORY_EVICTED`. The intervention audit and request dedup ledger
   retain their own copy of typed provenance independently of that cache.

For example, after obtaining an `int` snapshot called `scalar-1`:

```json
{
  "kind": "writeScalarStorage",
  "profile": "native-dwarf-scalar-v1",
  "snapshotId": "scalar-1",
  "value": {"kind":"integer","decimal":"-2147483648","bits":32,"signed":true}
}
```

For a bool snapshot use `{"kind":"boolean","value":true}`. Integer decimal
strings are canonical: no leading plus/zeros, whitespace, exponent or `-0`.
Width and signedness must exactly match the inspected metadata; there are no
implicit C++ conversions or truncation. Signed/unsigned ranges are checked
without floating-point conversion, including `INT64_MIN` and `UINT64_MAX`.
`storage.value` and the intervention's before/after values use the same exact
representation. A noncanonical bool byte such as `02` has complete available
storage but `value:null` and reason `invalid-scalar-representation`; replacing
it with `00` or `01` still compares its original raw bytes.

For a v2 `float` snapshot the exact negative-zero write is:

```json
{
  "kind": "writeScalarStorage",
  "profile": "native-dwarf-scalar-v2",
  "snapshotId": "scalar-2",
  "value": {"kind":"float","bits":32,"rawBitsHex":"80000000"}
}
```

`rawBitsHex` is exactly 8 (binary32) or 16 (binary64) lowercase hexadecimal
digits, most significant first, without `0x`. It represents the **numeric bit
pattern**, whereas `storage.bytesHex` represents **bytes in memory order**:
the example above has `bytesHex:"00000080"` on this little-endian profile.
Float metadata has `kind:"float"`, `signed:null`, `byteOrder:"little"`, and
coherent `byteSize:4,bits:32,representation:"ieee754-binary32"` or
`byteSize:8,bits:64,representation:"ieee754-binary64"`.

Every bit pattern is accepted, including signed zero, subnormals, infinities,
and quiet/signaling NaNs with their sign/payload intact. Encoding, decoding and
comparison operate on bytes, without host/inferior floating-point arithmetic
or decimal conversions. Same bits are a no-op, even for NaN; changing zero's
sign or a NaN payload is a real storage change. Decimal text, JSON numbers,
classification fields and automatic width conversions are not accepted by
this exact-write API. A future numeric UI must choose and display the intended
bit pattern before submitting it.

Both live scalar inspection and writing require native execution, exactly one
confirmed stopped thread, and phase `stopped` outside an input wait. Const,
volatile, atomic, reference, pointer, enum, aggregate and unsupported
extended integer types are rejected. V1 additionally rejects floats; v2 only
admits builtin `float` of four bytes and `double` of eight bytes, including
typedefs. `long double` (even if compiled to eight bytes), half/quad precision
and `_Atomic` float/double remain unsupported. A register-only or optimized-out value
has no writable memory storage. Unknown/ambiguous/unissued locators are not
resolved by guessing. Type names are labels, never assignment expressions or
an authority for signedness.

The engine uses trusted GDB Python type APIs and compares unqualified types
against built-in scalar types. This also rejects `_Atomic int`, which GDB can
report with integer type code/name and whose qualifier is not removed by
`Type.unqualified()`. `Type.is_signed` for integer/bool, other required metadata, the target
architecture and byte order must be available; older GDB versions may return
an unavailable target instead of guessing. Capability advertises the profile,
not a guarantee that every GDB/build/variable supplies this evidence.
[Type API](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Types-In-Python.html),
[value/address API](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Values-From-Inferior.html).
The float representation follows the verified native x86-64 ABI;
[Intel's format reference](https://www.intel.com/content/www/us/en/developer/articles/technical/floating-point-reference-sheet-for-intel-architecture.html)
describes binary32/binary64 encodings. Matching a size or printed type name
alone does not establish this evidence.

The result remains `memoryIntervention`, now with profile
`native-dwarf-scalar-v1` or `native-dwarf-scalar-v2` and a `scalar` section containing the original snapshot
ID, locator, verified target metadata, requested value and observed before/
after scalar values. A missing or partial readback leaves `afterValue:null`;
requested values never substitute for observed effects. Events, once-only
request handling, branch creation, readback errors, failed-context cleanup and
ledger bounds match raw memory edits. A retry still succeeds after the source
snapshot is evicted, because the original request's result is already saved.

Inspecting/refreshing metadata does not execute the inferior or feed queued
stdin/EOF. An edit invalidates other snapshots from the previous stop, including
when the PC is unchanged. Raw and typed edits share the same branch ancestry.
An externally changed value at the same stop causes a byte conflict, not an
unconditional overwrite. C++ assignment semantics, object initialization,
alternate-future restoration and language side effects
remain outside this storage profile.

## Typed scalar batches

`capabilities.scalarStorageBatch = "native-dwarf-scalar-batch-v1"` enables
`writeScalarStorageBatch` with the current session and `expectedStop`:

```json
{
  "kind": "writeScalarStorageBatch",
  "profile": "native-dwarf-scalar-batch-v1",
  "edits": [
    {
      "profile": "native-dwarf-scalar-v1",
      "snapshotId": "scalar-1",
      "value": {"kind":"integer","decimal":"42","bits":32,"signed":true}
    },
    {
      "profile": "native-dwarf-scalar-v2",
      "snapshotId": "scalar-2",
      "value": {"kind":"float","bits":64,"rawBitsHex":"8000000000000000"}
    }
  ]
}
```

Obtain each snapshot through `inspectScalarStorage` at the same live stop.
The batch profile is distinct from each item's scalar profile; v1 and v2 may
coexist, but each item must match its issued snapshot's profile exactly. V1
still rejects floating-point values. Scalar encodings, qualifiers and type
restrictions are unchanged. There are no implicit conversions.

Limits are `maxScalarStorageBatchItems` (8) and `maxScalarStorageBatchBytes`
(64, or the smaller configured memory-read limit). Empty batches, duplicate
snapshot IDs, and distinct snapshots whose storage overlaps are rejected.
Adjacent storage and unsorted addresses are allowed; request order is preserved.
Before any write, every snapshot must be retained, available and bound to the
current point/stop/process. Every locator's GDB type/address is resolved again,
every replacement is encoded, and all mappings and original bytes are checked.
Invalid metadata/value requests fail without creating an intervention;
byte-comparison failures retain a `preflight-failed` intervention with no writes.

The common batch engine then performs fresh per-item compare/write/readback and
final sampling of all ranges. Immediately before each actual write, GDB resolves
that item's type/address **again**: an earlier write might have changed evidence
used to locate a later variable. Changed metadata stops execution before that
write, retaining earlier effects. The raw execution report records this as
`write-rejected`, `writeAttempted:false`, with a `STALE_CONTEXT` error. Missing
metadata has its own error. This adds a storage-location check; it does not prove
C++ lifetime, exclude external interference or make the package atomic.

The response remains `memoryIntervention`, with
`profile:"native-dwarf-scalar-batch-v1"`, `mappings[]`, the existing
`MemoryBatchReportDTO`, and `scalars[]` aligned by `index` with `report.items[]`.
Each scalar records its original `snapshotId`, `profile`, `locator`, `target`
metadata and `requestedValue`, plus four independently decoded values:

| Field | Raw evidence used |
| --- | --- |
| `preflightValue` | `report.items[index].preflight.bytesHex` |
| `beforeValue` | `report.items[index].execution.beforeBytesHex` |
| `afterValue` | `report.items[index].execution.afterBytesHex` |
| `finalValue` | `report.items[index].final.bytesHex` |

Absent phases, partial reads and invalid scalar representations yield `null`.
A complete byte sequence can have a decoded value alongside a read error;
inspect the raw phase's error/comparison fields to determine verification.
Final bytes never fill in missing immediate readback. All-no-op batches have
before/preflight values but null after/final values because no post-write reads
were needed. Float values preserve exact bits, including signaling NaN payloads.

Native execution, one stopped thread, ordinary `stopped` phase and the same
private writable non-executable VMA gates apply. Input waits and record-full
writes remain unsupported. The operation neither executes program code nor
delivers queued stdin/EOF. Any attempted write creates one branch and one
refreshed stop for the entire package; all older observations/snapshots remain
immutable. A partial failure is retained without automatic rollback or retry.

Typed batches reserve 64 KiB in the shared non-evicting ledger. Serialized
metadata is checked before mutation; the reservation includes the original
request (at most 4096 bytes), raw report, provenance, decoded phases and response
envelope. The total byte budget and 128-record limit still apply across all
profiles. An identical whole-request retry returns the same audit after stop
changes, snapshot eviction or debugger death. A fresh request needs a current
context and enough remaining ledger capacity. The ordinary single-scalar and
raw-batch response shapes are unchanged. This API writes verified storage;
`variableWrite` remains false until C++ assignment/lifetime guarantees exist.

## Checked native register interventions

`capabilities.registerWrite = "native-x86_64-gpr-v1"` enables `writeRegister`.
Read the current value through `readRegisters`, then submit an exact expected
value and replacement under the same session and `expectedStop`:

```json
{
  "kind": "writeRegister",
  "profile": "native-x86_64-gpr-v1",
  "register": "rax",
  "expectedValueHex": "0x0000000000000007",
  "replacementValueHex": "0x000000000000002a"
}
```

Both value fields require `0x` followed by exactly 16 lowercase hexadecimal
digits in numeric order. Normalize an available `readRegisters` value to this
width using exact integer/string handling; never JavaScript `Number`. Every
64-bit pattern is allowed, including `0xffffffffffffffff`. Decimal expressions,
negative strings, truncation, implicit extension and register aliases are rejected.

This profile permits only `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, and `r8` through
`r15`. It requires native execution, one confirmed stopped thread, ordinary
`stopped` phase, GDB Python metadata, actual `i386:x86-64` architecture and an
eight-byte register. `rip`, `rsp`, `rbp`, flags, segment/system state, vector
registers and partial aliases such as `eax` are excluded. The register belongs
to the live thread's frame 0; callers cannot specify another thread/frame/index.
Missing or contradictory metadata fails before writing. Record-full and input
waits are unsupported. Other register inspection remains available as before.

Each primitive explicitly selects and verifies the live thread/frame, validates
architecture/width, and resolves a numeric index from the current MI register
name table. No index is hardcoded or retained across operations. The trusted
Python script reads metadata only; the mutating MI command receives one strict
hexadecimal literal. These commands do not execute instructions, evaluate caller
expressions, or deliver queued stdin/EOF. GDB's ordinary register display is
frame-relative, which is why selecting frame 0 is necessary.
[GDB register semantics](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Registers.html),
[MI register command implementation](https://gnu.googlesource.com/binutils-gdb/+/d01e823438c7dc264d6885fbbfeace4d8955dcb7/gdb/mi/mi-main.c#909).

The backend reads and compares the complete value, sends at most one write,
then independently reads back even when GDB rejects acknowledgement after a
possible effect. A conflict or equal replacement sends no write. There is no
automatic retry, rollback or atomic compare-and-swap. Changing a data register
can change later program behavior; this is machine-state intervention, not C++
variable assignment or a claim about object lifetime.

The synchronous result is `{kind:"registerIntervention",intervention,
throughSequence}`. Its immutable audit has the common ID/request/process,
before/after points/stops, branch, `contextStatus`, and `refreshError` fields,
plus `profile:"native-x86_64-gpr-v1"`, `target`, and `report`. It has no memory
`mapping`. Target identifies `{architecture:"x86_64",register,bits:64,
threadId,frameLevel:0}`. Report contains the register/width, requested expected
and replacement values, `beforeValueHex`/`afterValueHex`, comparison booleans,
attempt/acknowledgement/liveness flags and phase-tagged bounded errors.
Outcomes match single-memory edits: `conflict`, `unchanged`, `verified`,
`readback-mismatch`, `unverified`, `read-before-failed`, `write-rejected`.

Malformed/unavailable reads produce null values, never zero or a guessed prefix.
A complete error-bearing read may retain a value but cannot authorize a write
or verify readback. An error acknowledgement can coexist with `verified` when
the later read proves the requested bits; inspect acknowledgement/errors too.
Any possibly attempted write creates one lineage branch and refreshed stop,
even on failed acknowledgement or unchanged readback. Failure to confirm the
new stopped snapshot closes GDB, sets `contextStatus:"failed"`, and preserves
the audit; old observations remain immutable. Conflict/no-op creates an audit
without a branch. Physical output remains one process journal.

Register audits reserve 32 KiB in the same non-evicting session ledger as memory
audits. Original requests are bounded to 4096 bytes. All profiles share the
128-record cap and `maxInterventionStoreBytes` (4 MiB default), including the
64 KiB reservations of typed batches. `limits.maxInterventions` advertises this
global cap; legacy `maxMemoryInterventions` remains its compatibility alias.
Whole-request retries retain once-only behavior across changed stops, process
exit and debugger loss, until a successful new launch or workspace change.

## Shared intervention journal

`capabilities.interventionLog:true` advertises the generic history gateway:

- `readIntervention{interventionId}` returns
  `{kind:"intervention",intervention}` for any supported profile.
- `listInterventions{start,count}` returns
  `{kind:"interventions",items,start,total,hasMore}` in original audit order.
- `readRegisterIntervention` / `listRegisterInterventions` have the same arguments
  and return `registerIntervention` / `registerInterventions`, restricted to
  register edits. Existing memory read/list commands remain memory-only,
  including typed scalar and memory-batch profiles.

Inspect each audit's `profile` to choose a renderer. IDs are globally unique
within the session and shared by `listBranches`. In category-specific lists,
`start`, `total` and `hasMore` refer to the filtered category, not global ledger
offsets; entries retain their original IDs and order. A wrong-category read
returns `HISTORY_EVICTED`. Reads need the owning session but no live process or
`expectedStop`, and produce no new events. Historical reads omit
`throughSequence`; that field belongs to the original mutation response.
