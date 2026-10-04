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

## Frontend gateway roadmap (2026-10-04)

The new requirements extend P1/P4/P5/P6; they do not replace the existing
operation/lifetime and input plans. Unsynchronized `cout` inspection, a native
mapping snapshot and a unified output harness are the current implementation
slice. The contracts below describe subsequent integration boundaries, **not
new accepted request kinds**. Names are provisional until DTOs, runtime
validation, capability checks and fixtures land together. See the complete
acceptance matrix and order in [handoff §20](../../docs/BACKEND_HANDOFF.md#20-дополнение-04102026-память-вывод-и-расширенный-gdb).

The native mapping entry point is `capabilities.memoryMap:'linux-proc-maps'`
and `StopObservationDTO.memoryMap:MemoryMapSnapshotDTO`, carrying availability,
`source:'linux-proc-maps'`, `coverage:'complete'|'truncated'` and region
metadata. This does not change `observation.coverage.memory` to captured:
mapping metadata contains no memory bytes. The existing bounded `readMemory`
command retains its `expectedStop` requirement. ELF/vtable overlays, richer
diagnostics and the journal/profile/trace/intervention gateways remain future
work as described below.

| Gateway | Proposed data and invariants | Dependencies |
| --- | --- | --- |
| Virtual address space | `MemoryMapSnapshot`: process/stop/point, source, coverage, ordered regions with hex `[start,end)`, permissions/sharing, hex file offset, device/inode/path. A bounded region listing is separate from captured bytes. `MemoryReadPage` carries address/length and per-range availability; historical reads require captured data. | Native procfs snapshot first; paging and immutable history storage next. |
| Modules and C++ layout | `ModuleImage`: build-id, artifact hash, ELF kind/load bias/segments/sections. `MemoryOverlay`: region/module/object generation, extent, symbol/type/ABI, evidence; vtable address points, vptr, RTTI/VTT and inheritance relationships are optional typed overlays. | ELF/DWARF plus ABI adapters; P2 required for confirmed lifetime. A VMA is not an allocation or C++ object. |
| OS diagnostics | `RuntimeEnvironment`: kernel/architecture, debugger/library identities, procfs/ptrace/ASLR probes with status/reason/evidence. `smaps`, fd and status views have separate cost/capability/permissions. | Actual runner probes; absent permissions degrade only affected features, with no global sysctl edits. |
| Output | `OutputJournal`: run/branch/stream, append-only committed byte offsets and retention gaps. `OutputView`: selected point, committed-through offset, separately identified pending snapshots and known/unknown ordering. | Native C/C++ buffer probes first; journal persists separately from history eviction. Recorder effects need a replay policy before reverse execution is enabled. |
| Execution layout | `ExecutionProfile`: requested ASLR/PIE/allocator configuration; `ExecutionManifest`: actual ELF/toolchain/runtime/environment identities, measured layout evidence, warnings and reproducibility coverage. | Build identity change, prelaunch probes and verified rerun checks; equal addresses alone never authorize restore. |
| Changes inside a step | `ChangeIntervalPage`: capture/profile, from/to points, instruction or operation occurrence, thread/activation, changed registers/ranges with before/after availability, ordering, gaps and continuation cursor. | Recorder or instrumentation enabled before the interval. Captured stores, snapshot differences and semantic assignments remain distinct kinds. |
| Runtime intervention | `InterventionRecord`: request/branch/expected stop, mechanism, requested edits, actual effects, cleanup status and resulting context. Execution requires an explicitly selected supported intervention profile. | P5 audit/branch foundations, ABI implementation, recorder compatibility and rollback/partial-failure tests. |

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

Plan a named non-PIE profile with matching compile/link flags, validate `ET_EXEC`
in the artifact, and request ASLR disable only for the owned inferior. Record
requested versus verified settings and refusal evidence. Do not change global
kernel policy. GDB exposes the per-launch setting, but its configuration value
is not proof that the host permitted it. [GDB launch settings](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html).
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

Deliver native output/maps first, then the verified layout profile, recorder
prototype, richer ELF/vtable overlays and finally runtime interventions. Probe
Ubuntu versions through OS/ABI/capability evidence; a distro label alone does
not establish support.
