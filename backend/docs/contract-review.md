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
proof that `cin` or a raw read consumed it. The target contract classifies a
blocked source step as `input-wait` when the stop is inside the inferior's stdin
read path; the current native implementation still has the old
`STEP_TIMEOUT` fallback until that classifier and resume path are implemented.
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
gated extensions. A client must inspect `capabilities.inputTracking` before
using `revision`, `exposedRanges`, `consumedRanges` or `activeRange`; absent
coverage is represented by `null`/`none`, never inferred from pipe counters.
New command kinds and mutation/audit records still require a versioned
DTO/fixture change. Unsupported commands or fields fail closed with
`UNSUPPORTED`/`INVALID_REQUEST`.
