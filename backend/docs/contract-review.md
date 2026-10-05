# Contract review: v1 validation and stdio framing

This review keeps `src/backend-contract.ts` protocol version 1 unchanged. The
standalone validator is deliberately stricter than a TypeScript type assertion:
an incoming value is rejected before it reaches the service/router.

## Framing proposal

The default transport is one UTF-8 JSON value per line (NDJSON). A newline in a
JSON string must be escaped; the transport reads at most `maxWireBytes` (16 MiB)
before parsing and reports a terminal `INVALID_REQUEST`/`LIMIT_EXCEEDED` envelope
for a bad frame. It does not open a network port. The first frame is the adapter
connect request, represented by `{"kind":"connect","supportedProtocolVersions":[1]}`
(the validator also accepts the DTO shape without the optional `kind` envelope).
Subsequent frames are v1 `BackendRequestDTO` values. Responses and events retain
their DTO envelopes and are emitted as one line each. A writer serializes one
complete line at a time; a final non-empty frame is accepted at EOF even without
the trailing newline, while an empty partial buffer is ignored.

The connect response chooses one common protocol version and publishes the
workspace/state/capability checkpoint. A response is never inferred from a
transport close. Commands unsupported by the selected capability return
`UNSUPPORTED`; an unknown command kind is never ignored.

Execution is serialized, but `pause`, `stop` and `cancel` have a control path
beside the request queue. If a control line races dequeue of its target, the
adapter waits for the active operation hand-off and carries an early interrupt
across the GDB/MI command write. This prevents a same-packet control from
being lost when `resume` is about to start.
Controls check workspace, session and any `expectedStop` before signalling.
When several controls target the same operation, precedence is
`stop > cancel > pause`: a later pause cannot erase a confirmed cancellation.
An applied control is acknowledged once even when its own effect has already
changed the current stop. EOF cancels active work and prevents queued build,
launch or execution requests from starting a new process.

## Runtime invariants

`parse_wire_json` performs a bounded lexical pass before constructing the
nlohmann DOM. It rejects duplicate object keys (including equivalent escaped
keys), malformed JSON escapes, invalid UTF-8, lone UTF-16 surrogate escapes,
excessive depth/node/string/object/array budgets, and unsafe JSON numbers. JSON
integer values must fit the exact safe transport range `[-2^53+1, 2^53-1]`.
Exact runtime integers are carried by the DTO as decimal strings with explicit
bit width and signedness; they are never parsed through a JavaScript-like
number. Floats carry text and an explicit finite/NaN/infinity/negative-zero
classification.

IDs are non-empty UTF-8 strings bounded to 256 bytes. Source text is bounded to
4 MiB and input text to 1 MiB by default. Pages, arguments, breakpoints,
environment entries, memory reads and instruction counts have independent
budgets. Unknown fields in requests/commands and scalar DTOs are errors.

Inferior argument strings cannot contain NUL or a physical line break because
they are serialized into one GDB/MI command. Environment names use the POSIX
`[A-Za-z_][A-Za-z0-9_]*` form and values reject NUL. The environment is stored
in a private NUL-delimited manifest and applied by the wrapper immediately
before target exec. A target `PATH`, `LD_*`, `SHELL` or `BASH_ENV` value cannot
change GDB, its startup shell or wrapper loading. Leading/trailing whitespace,
quotes and newlines in environment values are preserved literally.

Source ranges use zero-based UTF-16 code-unit offsets and one-based UTF-16 line
and column coordinates. Conversion helpers reject byte offsets inside a UTF-8
code point and UTF-16 offsets inside a supplementary pair. Input revisions keep
the exact text and an explicit parent revision; `exposedRanges` and
`consumedRanges` are always tied to one revision and never move when a future
suffix is edited. Delivered pipe bytes are not treated as observed C++
extractions. The native transport-only profile may return `trace:null`; a
semantic profile may return `status`, `activeRange`, and confirmed consumed
ranges.

Expression traces reject duplicate stage/group IDs, dangling dependencies,
duplicate active IDs and dependency cycles. A range/document revision mismatch
is invalid. The validator checks shape and evidence fields; it does not invent
debugger observations or source locations.

The current Linux GDB adapter gives the inferior fd 0/1/2 through a trusted
`phantom-io-wrapper` and private one-shot FIFOs. Submitted input is written
through a bounded transport cursor; an open interactive session may append
future text without closing the writer. The adapter reports
`tracking:"transport-only"`: `deliveredBytes` is only a pipe-write count, not
proof that `cin` or a raw read consumed it. A Linux `/proc/<pid>/syscall`
sample, matched against the owned stdin FIFO and the interrupted x86_64
registers, classifies a blocked source step or continue as `input-wait` while
preserving the user frame. The waiting request ends with `outcome:"waiting"`;
the frontend can append an exact chunk and issue a new step/continue with the
returned stop context. Source stepping finishes the immediate callee of the
saved user frame before resuming normal line stepping. GDB owns the temporary
return breakpoint; no next-line guess or inferior expression call is needed.
A genuine source step timeout still uses `STEP_TIMEOUT` and keeps the session
inspectable.
NUL bytes, unterminated input and long lines
are ordinary pipe data subject only to the DTO input budget. stdout and stderr
are drained independently, each with its own bounded retained snapshot and
truncation metadata. If the helper is unavailable, launch fails closed instead
of silently falling back to a merged PTY profile.

The optional `stdout.buffered` snapshot separates `pendingBytes`, the active
write-window capacity/remaining fields, and physical `storageCapacityBytes`.
The active write window is based on glibc `_IO_write_base.._IO_write_end`; the
physical storage is `_IO_buf_base.._IO_buf_end`. `capacityBytes` and
`remainingCapacityBytes` are compatibility aliases for the write-window fields.
The snapshot is an instantaneous ABI-specific observation and does not promise
that the same number of bytes will be written before the next flush.

The October extension adds `stdout.coutBuffered` using the shared
`RuntimeBufferSnapshotDTO`: source is `glibc-_IO_FILE` or
`libstdc++-stdio_filebuf`, stream is `stdout` or `cout`, and association is
`cout-if-synchronized`, `cout-synchronized` or `cout-unsynchronized`.
Confirmed synchronized aliases are displayed once. Independent C and C++
pending buffers do not establish a total emission order.
The LP64 libstdc++ probe checks the actual rdbuf RTTI/layout, the standard
no-conversion codecvt, and fd 1 against the owned transport FIFO. Redirected
descriptors and custom conversion facets return explicit unavailable reasons.
When the actual top PC is outside the submitted source, both pending snapshots
are unavailable: a runtime stop can interrupt a flush after bytes were written
but before its put pointers were reset. Promoting an input caller for display
does not relax this guard. The profile was tested against libstdc++13.

The ready handshake keeps the parent stdin writer open until the wrapper has
opened its reader, including for empty input. It then removes the bootstrap
reader so a target `close(0)` produces EPIPE. The owning command loop pumps at
most 64 KiB per stream per turn; a continuous stdout writer cannot starve MI,
stderr or cancellation. At a stop, `FIONREAD` fixes the queued output budget
so an enlarged FIFO's final tail is captured without waiting for all writers
to close. A closed writer delivers real pipe EOF. See the
[Linux FIFO semantics](https://man7.org/linux/man-pages/man7/fifo.7.html) and
[pipe EOF/SIGPIPE rules](https://man7.org/linux/man-pages/man7/pipe.7.html).

Each output stream retains up to 1 MiB of raw bytes by default (independent of
the 16 MiB input wire-frame budget). `text` replaces each invalid UTF-8 byte
with U+FFFD, including a partial codepoint at a retained-tail boundary; byte
counts and truncation offsets remain raw stream offsets. Protocol v1 input
remains UTF-8 text, with embedded NUL/control characters permitted.

GDB requires shell quoting of the wrapper paths; the helper executes the target
directly after redirecting descriptors. This follows the documented
[GDB exec-wrapper lifecycle](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html).

## Compatibility extensions and capability gating

The optional `kind:"connect"` and `workspace` members belong to the NDJSON
envelope only. Interactive stdin is now an implemented native capability, while
semantic input ranges, operation/capture manifests, object identity, thread
ordering, build feature manifests and performance evidence remain capability
gated extensions. Native `transport-only` supplies immutable `revision` and
`exposedRanges` in UTF-16 units. Clients must inspect `capabilities.inputTracking`
before using semantic `consumedRanges` or `activeRange`; these fields are absent
in the native profile and must never be inferred from pipe counters. An EOF
request is reported immediately as `requested`, even if queued bytes still
need to drain. This is not proof that a C++ extractor has observed EOF.
`submitted` preserves the original launch input and close policy; subsequent
chunks and EOF requests affect the current revision and EOF state only.
New command kinds and mutation/audit records still require a versioned
DTO/fixture change. Unsupported commands or fields fail closed with
`UNSUPPORTED`/`INVALID_REQUEST`.

## Implemented inspection gateways (2026-10-04)

The current native slice adds accepted request kinds together with strict DTO
validation and advertised capabilities. The frontend's virtual-memory view is
**2D**; this backend slice implements its data gateways only. Request examples,
retention semantics and actual bounds are in
[INSPECTION_GATEWAYS.md](../../docs/INSPECTION_GATEWAYS.md).

- Build `configuration.addressProfile` is `native` (default) or
  `fixed-executable`. The latter appends `-fno-pie -no-pie` and verifies the
  actual x86_64 `ET_EXEC`, not just requested flags. `artifact.elf` includes
  bounded ELF64 little-endian program-header metadata and GNU PT_NOTE build ID.
- Launch `addressPolicy` is `native`, `disable-aslr` (default) or
  `require-fixed`. Strict launch requires actual ET_EXEC and a verified
  `ADDR_NO_RANDOMIZE` mask on the owned inferior; otherwise it stops it and
  returns `LAUNCH_FAILED`. `executionLayout` records entry-time evidence and
  requested launch-input fingerprint. It does not verify inherited environment,
  dependency contents, allocator determinism or replay; `restore` stays `none`.
- `inspectProcess` reads bounded stat/status/personality, exe/fd symlink targets,
  smaps_rollup and kernel/page-size metadata. It pins the proc directory and
  compares start time before/after collection. Independent denial/partial data
  stays explicit; kernel-redacted zero address fields do not establish absence.
- `readRegisters` reads frame-0 machine values, with per-register availability.
  `captureMemory` retains up to eight nonoverlapping ranges (64 KiB total by
  default); `readMemoryCapture` and `diffMemoryCaptures` use only saved bytes.
  Missing bytes are not filled with zero or read from a later live stop.
- `diffMemoryMaps` compares complete retained observation maps. A changed
  interval with the same endpoints is `changed`; split/merged intervals are
  `removed`/`added`, with no allocation/object identity claim.
- `traceInstructions` advances execution through at most 256 instruction
  attempts and captures selected registers plus up to eight ranges/4096 bytes
  at instruction boundaries. It returns normal lifecycle events and an
  `instructionTraceRecorded` event with trace ID; `readInstructionTrace` pages
  at most 64 entries per response. Changes within a source step become visible
  when they cross recorded instruction boundaries. Same-value writes,
  instruction-internal reversals and other-thread write history remain absent.

All new live read/capture/trace requests require `expectedStop`. Saved-capture,
map-diff and trace-read requests are session-scoped historical queries, never
implicit execution or live reads. Capture/trace retention is separate from
stop history, bounded to 128 records and `maxInspectionStoreBytes`; a new
session clears it and eviction yields `HISTORY_EVICTED`. Reading shared memory
sequentially is not a globally atomic snapshot if external writers exist.

## Remaining frontend gateway roadmap (2026-10-04)

The new requirements extend P1/P4/P5/P6; they do not replace the existing
operation/lifetime and input plans. The implementation includes native output,
mapping snapshots and the accepted inspection/layout gateways above. The
contracts below describe the broader remaining integration boundaries, **not
additional accepted request kinds**. Proposed names remain provisional until
DTOs, runtime validation, capabilities and fixtures land together. See the complete
acceptance matrix and order in [handoff §20](../../docs/BACKEND_HANDOFF.md#20-дополнение-04102026-память-вывод-и-расширенный-gdb).

The native mapping entry point is `capabilities.memoryMap:'linux-proc-maps'`
and `StopObservationDTO.memoryMap:MemoryMapSnapshotDTO`, carrying availability,
`source:'linux-proc-maps'`, `coverage:'complete'|'truncated'` and region
metadata. This does not change `observation.coverage.memory` to captured:
mapping metadata contains no memory bytes. The existing bounded `readMemory`
command retains its `expectedStop` requirement. Runtime ELF indexing, a bounded
session output journal and opt-in GDB recording are implemented in the extension
below. Automatic vtable overlays, durable recorder storage, verified replay of
arbitrary observations and runtime code injection remain future work. Checked
native storage edits and intervention lineage are implemented below (2026-10-05).

| Gateway | Proposed data and invariants | Dependencies |
| --- | --- | --- |
| Virtual address space | Implemented maps, immutable explicit byte captures and paged map/capture differences; a future `MemoryReadPage` may expose broader partial islands. | Retention/coverage remain bounded. Full-process byte capture is not implied by a complete mapping list. |
| Modules and C++ layout | `ModuleImage`: build-id, artifact hash, ELF kind/load bias/segments/sections. `MemoryOverlay`: region/module/object generation, extent, symbol/type/ABI, evidence; vtable address points, vptr, RTTI/VTT and inheritance relationships are optional typed overlays. | Main-artifact ELF headers and runtime module indexing are implemented; ELF sections/DWARF and ABI adapters remain. P2 is required for confirmed lifetime. |
| OS diagnostics | Current `inspectProcess` exposes procfs, descriptors, smaps_rollup, kernel and personality evidence; broader `RuntimeEnvironment` adds debugger/library identities and recorder probes. | The isolated scalar recorder probe is implemented. Per-section evidence rather than a distro assumption. Full smaps and physical-page indexing remain outside the current collector. |
| Output | `OutputJournal`: run/branch/stream, append-only committed byte offsets and retention gaps. `OutputView`: selected point, committed-through offset, separately identified pending snapshots and known/unknown ordering. | Native C/C++ probes and session journal are implemented. Journal retention is independent of history; record-full replay preserves committed bytes and marks unobserved output prefixes unknown. |
| Execution layout | Implemented ELF/profile plus entry-time personality evidence. A broader manifest must capture runtime dependencies, inherited environment and allocator configuration, then verify rerun behavior. | Equal addresses and the current launch-input fingerprint alone never authorize restore. |
| Changes inside a step | Implemented forward instruction-boundary trace for selected registers/ranges. Broader `ChangeIntervalPage` adds recorder/profile and semantic operation/thread ordering evidence. | rr or instrumentation must exist before the interval for complete historical queries. Boundary differences, captured stores and semantic assignments remain distinct. |
| Runtime intervention | Implemented `MemoryInterventionDTO`: expected/current bytes, write/readback evidence, resulting stop and lineage branch; bounded dedup ledger. Native single/batched raw-memory and single/batched typed integer/bool/float storage profiles. | Register writes, code/syscall injection, recorder-compatible branches and replay remain separate P5 steps. |

All memory addresses and offsets retain exact string representations; no
JavaScript-number conversion. Ranges use explicit units: memory/output ranges
are bytes, input/source ranges are UTF-16. Current-process identity includes
session/generation and the owning inferior, not a bare PID. Reused addresses
never imply reused object/module identity. New read commands require the same
stop check as `readMemory`; new historical commands accept an immutable point
and never silently inspect live state.

### Output ordering and reversibility

Synchronized C++ output can share C `stdout` buffering; after disabling sync,
separate C and C++ pending buffers do not reveal their relative emission order.
The frontend may present one output area with red pending regions, but must
label unordered sources instead of inventing a concatenation. Unknown/custom
`streambuf` remains unavailable. Reads must not execute inferior functions or
force a flush. [libstdc++ mixing C and C++ I/O](https://gcc.gnu.org/onlinedocs/libstdc++/manual/io_and_c.html).

Committed bytes mean bytes observed at the backend transport, not necessarily
durable storage or a rendered terminal. A historical cursor may change pending
snapshots and the visible committed-through marker; it cannot erase physical
effects already emitted. Keep the journal immutable, mark committed output
after the selected cursor as future relative to that point, and do not append
duplicate journal entries when reading history or replaying an already recorded
effect. No total order is promised across independent stdout/stderr transports.
Finite retention must show an explicit gap rather than an apparently complete
journal. Separate branches preserve each original run's effects and provenance.

### Address stability and recorder choice

The named fixed-executable profile validates `ET_EXEC`; the launch policy
requests ASLR disable only for the owned inferior and records entry-time
personality evidence. Global kernel policy stays untouched. GDB's configuration
value alone is not proof that the host permitted it.
[GDB launch settings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html).
Allocator state, environment, input and external nondeterminism still belong to
replay validation. Neither fixed heap placement nor equal module addresses
prove replay equivalence; object identity continues to use logical generations.

An endpoint-snapshot diff cannot recover overwritten intermediate values.
Python `memory_changed` events report debugger-user memory modifications;
they are not an inferior write trace. [GDB Python events](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html).
Evaluate rr and a bounded `record full` profile independently. `btrace` lacks
data history, and `record full` requires a compatible execution mode rather
than being enabled inside the existing asynchronous control loop. Instruction
coverage, recorder eviction and unsupported operations must reach the client.
[GDB recording](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html).

### Observation versus intervention

Backend-owned syscalls and procfs reads belong to observation/resource control.
Calling `mprotect` in the backend does not alter the inferior's mappings.
Inferior syscall/call/code injection is a separate auditable mutation: validate
the stop, maintain branch identity, record partial effects, bound execution,
restore saved machine state and clean up owned mappings or report failure.
Choose compile-time hooks/preloaded helpers where suitable; an injected code
page uses RW then RX, with page/ABI/icache handling, never a permanent RWX
shortcut. [Linux mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html).
The current read-only buffer and mapping work does not enable injection.

### Acceptance before capability promotion

Each gateway needs parser/limit fixtures, real headless integration and frontend
contract fixtures. Cross-cutting cases are stale stop/session, process exit and
PID reuse, cancellation, permission denial, missing symbols/ABI, truncation,
repeated historical reads and immutable branch provenance. Specific priorities:

- Output: sync on/off, mixed C/C++, flush transitions, custom/null buffers,
  oversized writes, NUL/invalid UTF-8, exit/crash and deduplication during seek.
- Memory: large sparse maps, unmapped/guard pages, split/reused mappings,
  shared pages, deleted/whitespace paths, PIE/RELRO, dynamic libraries and
  multiple/virtual inheritance. Nonresident is not synonymous with unmapped.
- Layout: denied personality, repeated malloc/free/realloc/mmap, changed
  environment, custom allocator and sanitizer profiles; mismatch is explicit.
- Trace: repeated stores with identical final values, register-only changes,
  overlapping writes, syscalls/signals, unsupported instructions and log gaps.
- Intervention: denied/partial syscall, timeout/cancel/signal, restored
  bytes/protections/registers, cleanup on stop and consistent replay audit.

Native output/maps, entry-time layout evidence and bounded inspection/trace
gateways are implemented. Next come a recorder/replay prototype, runtime
ELF/vtable overlays and then runtime interventions. Probe
Ubuntu versions through OS/ABI/capability evidence; a distro label alone does
not establish support.


## 2026-10-04: output journal, module snapshots and recorder gateways

Runtime extensions live in `src/backend-runtime-contract.ts`, re-exported by
`src/backend-contract.ts`. `inspectModules` requires the current session and
`expectedStop`; `readModuleSnapshot` reads a retained immutable module snapshot
without moving the process. Snapshot evidence explicitly belongs to current OS
state. Module identity uses checked file metadata, not a claim of whole-file
content hashing or C++ object lifetime.

`readOutputJournal` reads exact bytes and explicit missing intervals in bounded
pages. An optional history point identifies the selected output prefix; a
missing proven prefix is null. Already delivered output never shrinks with
history selection or reverse execution. See
[`INSPECTION_GATEWAYS.md`](../../docs/INSPECTION_GATEWAYS.md) for limits.

`probeRecorders` runs the shipped scalar fixture in separate owned processes.
It supports cancellation, has no caller-selected executable paths and does not
mutate the live session. Successful fixture replay is evidence for that fixture,
not a promise of arbitrary program support. See
[`RECORDING.md`](../../docs/RECORDING.md) for profiles and external-effect limits.


Opt-in `launch.recordingProfile:gdb-record-full` adds live `readRecording`,
`reverseInstruction` and `seekRecording`. These commands require `expectedStop`;
seek positions are canonical unsigned 64-bit decimal strings, unrelated to
history ordinals. Execution emits accepted/observation/state/commandFinished.
Failed movement preserves a verified current stop; invalid bounds leave the
prior observation unchanged. Retained history never mutates. Profile, finite
input and instruction budget participate in the run fingerprint. Native stdin
and stepping remain the default. The complete contract and limitations are in
[`RECORDING.md`](../../docs/RECORDING.md).


## 2026-10-04: ELF symbol captures and declared variable layout

`inspectModuleSymbols{moduleId}` captures one currently mapped file, its ELF
sections/symbols and verified load-instance intersections. Its first page and
`readModuleSymbols{snapshotId,start,count}` use the same immutable capture.
`totalSymbols` is the retained row count; ELF metadata also reports the full
on-disk table count. Stripping and retention truncation are distinct. Address
and size values remain strings, TLS/IFUNC/absolute/common/undefined semantics
stay separate, and Itanium prefix classification is evidence rather than an
assertion about valid vptrs. The snapshot's scope is current OS state.

`inspectVariableLayout{locator}` accepts an unambiguous root locator emitted
at the current stop through observation/readVariables. Layout contains declared
type structure, bounded child metadata and proven storage addresses; pointer
values are not followed and target functions never execute. Missing storage,
optimized values, bitfields, static/reference/base fields, inactive union
selection and lifetime have explicit limitations. The helper's bit-position
convention is `gdb-target-bitpos`; output/traversal limits do not claim a byte
quota on GDB's own DWARF decoding. `readVariableLayout{snapshotId}` only reads
retained JSON. Both live commands require `expectedStop`.

Schemas are in `backend-runtime-contract.ts`; main command/result unions and
native runtime validators change together. Their protocol tests join the
real-traffic TypeScript `satisfies` check.

## 2026-10-04: explicitly selected absolute-vtable profile

`inspectVtable{abi,vptrAddressHex,maxEntries}` requires an exact live stop and
`abi:"itanium-x86_64-absolute-v1"`; the address denotes pointer storage, not
the table. `readVtableSnapshot{snapshotId}` reads an immutable session capture.
Reports contain exact raw bytes, signed decimal offset-to-top, checked top
candidate, RTTI address and bounded words with optional ELF symbol labels.
These are conditional interpretations under `abiEvidence:requested-profile`;
`lifetime:unknown` and `tableEnd:unknown` remain explicit. Neither executable
mapping permission nor `_ZTV` symbol membership proves a callable method or
valid object. Relative vtables are outside this profile, without a promise of
automatic detection of every incompatible layout.

Complete maps are checked before/after; unreadable mappings cannot be bypassed
through GDB's ptrace privileges. Slot/header rereads report sampled consistency,
not atomicity. Symbol metadata uses at most four 1 MiB inspections. Memory reads,
word count, report retention and callback count are bounded; absent symbol
evidence and partial reads are never synthesized from present memory on a
historical request. GDB memory and current OS metadata have distinct scope
during replay. The protocol regression joins the real TypeScript traffic test.

## 2026-10-05: checked storage edits and intervention lineage

`writeMemory` is an explicit native-only raw-byte operation, with expected
bytes, single stopped thread, one private non-executable writable mapping and
mandatory post-write readback. `variableWrite` remains false. New results are
`memoryIntervention`, `memoryInterventions` and `branches`; retained reads use
session identity without live handles. The full request is deduplicated before
the current-stop gate, preserving the original response and once-only events.

Every attempted write forks lineage and advances stop identity, or fails closed
with an immutable audit and null live observation. Branches do not imply
restoration of a previous process. History uses full point identity; the output
journal remains process-wide. Counters stay monotonic across forks. The ledger
has bounded non-evicting reservations separate from inspection caches. Details
and error semantics: [inspection gateways](../../docs/INSPECTION_GATEWAYS.md#checked-native-memory-interventions).

## 2026-10-05: authoritative scalar storage edits

`scalarStorage: native-dwarf-scalar-v1` exposes inspect/read/write scalar
storage commands without changing legacy `writeVariable`. Retained snapshot
IDs bind expected type, address and bytes to the exact current stop. Writes
re-resolve GDB metadata and share the raw edit audit/branch/dedup path. New
`ScalarStorageValueDTO` carries canonical integer strings with exact matching
width/sign, or bool. No implicit C++ conversion or lifetime claim is made.

`MemoryInterventionDTO` is discriminated by raw versus scalar profile; scalar
reports require the original typed target, requested value and actual decoded
before/after values. A partial read or invalid bool representation stays null.
Unavailable metadata/storage never becomes an editable value. See the
[scalar gateway](../../docs/INSPECTION_GATEWAYS.md#typed-scalar-storage).

## 2026-10-05: opt-in exact IEEE storage profile

`scalarStorageProfiles` advertises v1 and `native-dwarf-scalar-v2`; the old
`scalarStorage` capability still names v1. Optional `inspectScalarStorage.profile`
defaults to v1. A snapshot retains its chosen profile and a write must match it.
V1 never exposes float scalar metadata/values, including unavailable targets.
V2 adds verified builtin float/4-byte and double/8-byte storage; int/bool support
is unchanged. DTO profile unions preserve the narrower v1 payloads.

V2 float values require `{kind:"float",bits:32|64,rawBitsHex}` with exactly
8/16 lowercase hexadecimal digits in numeric MSB-first order and no prefix.
The storage hex remains target memory byte order. Metadata uses
`representation:"ieee754-binary32"|"ieee754-binary64"`, coherent width/size,
`signed:null` and `byteOrder:"little"`. This exact storage DTO is deliberately
separate from Observation's display float DTO; decimal/classification/host
numeric values are not accepted in exact writes.

All bit patterns preserve sign, subnormals, infinities, and quiet/signaling NaN
payloads without FP evaluation. The shared audit decodes only observed complete
bytes, never substitutes the requested value after partial/missing readback,
and retains once-only handling on retries. C++ lifetime, language assignment,
long double/extended formats, qualifiers/atomic types and record-full writes
are not implied. See the [v2 examples and gates](../../docs/INSPECTION_GATEWAYS.md#typed-scalar-storage).

## 2026-10-05: bounded multi-range memory intervention

`writeMemoryBatch{profile:"native-private-memory-batch-v1",edits}` is advertised
through optional `memoryWriteBatch`, `maxMemoryBatchRanges` and
`maxMemoryBatchBytes` capabilities/limits. Each item contains address and equal
nonempty expected/replacement bytes. Validation rejects overlaps/aliases,
overflow, more than eight ranges or more than 256 total bytes (also respecting
the configured memory-read limit). Native/current-stop/thread/VMA gates match
single-range edits; the full mapping pass precedes any mutation.

`MemoryInterventionDTO` now discriminates the batch variant by profile, with
`mappings[]` and `MemoryBatchReportDTO`. The former singleton variants keep
`mapping` and their original report. A batch retains initial preflight,
fresh per-item compare/write/readback and final all-range samples separately.
All ranges must pass preflight; execution stops at the first failure/missing
acknowledgement. After any attempted write, final reads include skipped and
no-op ranges while GDB is alive. Missing/partial evidence is never invented.
Earlier observed effects remain visible; rollback and atomicity are false.

One batch has one ledger ID, one lineage branch and one refreshed stop after
any write attempt. Shared once-only request handling survives stale stops and
debugger death; no-op/conflict batches consume an audit entry without forking.
Serialized read-error bounds keep the full report inside the existing 32 KiB
reservation with its request and envelope. Old history, physical output,
single/typed writes and queued input retain their existing semantics.
Complete outcomes, null semantics and examples:
[batch gateway](../../docs/INSPECTION_GATEWAYS.md#batched-memory-interventions).

## 2026-10-05: typed scalar storage batches

`writeScalarStorageBatch{profile:"native-dwarf-scalar-batch-v1",edits}` adds
1–8 disjoint current-stop scalar snapshots, with 64 total storage bytes or the
smaller configured memory-read limit. Optional `scalarStorageBatch`,
`maxScalarStorageBatchItems` and `maxScalarStorageBatchBytes` advertise it.
Each entry has its own exact snapshot-matching v1/v2 profile and scalar value;
v1 float remains a type/schema error. Duplicate IDs, aliases, stale contexts,
unsupported storage and unencodable values cannot cause an earlier write.

All issued targets are re-resolved before the raw batch preflight. Each actual
write also re-resolves its target immediately before mutation; an earlier edit
may have changed address/unwind evidence. Changed metadata stops later writes
while preserving earlier effects. The common sequential batch engine retains
its non-atomic, no-rollback, stop-on-first-failure behavior and final sampling.

`ScalarStorageBatchInterventionDTO` extends the raw batch shape with a distinct
profile and indexed `scalars[]` carrying original provenance, requested values
and four independently decoded phases. Preflight/before/after/final values use
only their corresponding complete raw bytes, with null for missing/partial or
invalid scalar representations. Error-bearing complete bytes can be decoded;
the raw phase's error still governs verification. No observed value is inferred
from the request or a different phase. Float bits remain exact.

The shared ledger reserves 64 KiB per typed batch and 32 KiB for old profiles,
enforcing both the sum and 128-entry cap. Serialized provenance is bounded before
mutation. Whole-request retry identity survives stop changes, inspection-cache
eviction and debugger death in the same session. Existing single/raw shapes,
branch/history behavior and stdin/EOF isolation are preserved. Native stopped
single-thread and private VMA gates still apply; C++ lifetime/assignment and
record-full interventions remain outside the contract. See
[typed batch gateway](../../docs/INSPECTION_GATEWAYS.md#typed-scalar-batches).
