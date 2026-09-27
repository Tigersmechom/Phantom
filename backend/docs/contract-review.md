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
`[A-Za-z_][A-Za-z0-9_]*` form and values reject NUL. The environment is applied
to the inferior through GDB before `-exec-run`; it is not used to alter the
debugger process itself (so a target `PATH` or `LD_*` value cannot change GDB
lookup/loading).

Source ranges use zero-based UTF-16 code-unit offsets and one-based UTF-16 line
and column coordinates. Conversion helpers reject byte offsets inside a UTF-8
code point and UTF-16 offsets inside a supplementary pair. `InputTrace.revision`
must equal the submitted input text byte-for-byte; delivered pipe bytes are not
treated as observed C++ extractions.

Expression traces reject duplicate stage/group IDs, dangling dependencies,
duplicate active IDs and dependency cycles. A range/document revision mismatch
is invalid. The validator checks shape and evidence fields; it does not invent
debugger observations or source locations.

The current Linux GDB adapter gives the inferior a private canonical PTY.
Submitted input is written once followed by two deterministic terminal VEOF
markers (the first flushes an unterminated line; the second makes the next read
observe EOF) and is reported as `transport-only`; the byte count is not
presented as proof that `cin` or a raw read consumed it. The adapter rejects the
PTY's EOF control byte and lines longer than the host's `MAX_CANON`, so a writer
cannot block forever on a line the inferior cannot receive. PTY output is
bounded and retained as stdout, while stdout and stderr are intentionally merged
by this profile. A separate stream capture must be capability-gated rather than
silently inferred from the merged bytes.

## Compatibility extensions kept out of v1

The optional `kind:"connect"` and `workspace` members belong to the NDJSON
envelope only. They are not added to the frontend DTO. Future interactive stdin,
new command kinds, mutation/audit records, operation/capture manifests, object
identity, thread ordering, build feature manifests and performance evidence
require a versioned DTO/fixture change. Until then, corresponding commands or
fields fail closed with `UNSUPPORTED`/`INVALID_REQUEST`.
