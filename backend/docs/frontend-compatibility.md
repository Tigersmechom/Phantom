# Frontend compatibility checkpoint

The reviewed frontend baseline is `origin/main` commit
`56308532338bcccc65413c794052e06fc73a3e4f` (fetched on 2026-09-27).
This is a **DTO/transport compatibility check**, not a connected Electron
debugger: that frontend still uses `frameNative` for Basic compile/run and
`demo.ts` for Debug presentation. It declares `DebugBackendAdapter`, but does
not implement it or expose a debugger bridge from `electron/preload.cjs`.

## Contract changes in the ready frontend

Compared with the backend branch's original `f643fff` frontend baseline,
`src/backend-contract.ts` adds only optional semantic trace fields:

| Added fields | Current backend behavior |
| --- | --- |
| Observation `operations`, `controlFlow`, `outcome`, `gaps` | Omitted; ordinary GDB stops do not establish these semantic facts. |
| Expression `globalReferences` | Omitted; no observed expression capture is advertised. |
| Capabilities `operationTrace`, `controlFlowTrace`, `globalPrimitiveReferences`, `runtimeOutcomes` | Omitted; consumers must require explicit support before using them. |

Protocol version remains 1. These additions require no backend DTO migration.
Merging the frontend commit brings its presentation changes into this branch;
it does not by itself connect the UI to the backend or enable instrumentation.

## Real traffic conformance test

`tests/frontend_contract_test.py` runs `tests/service_integration.py` against
the real compiled backend and GDB, records the requests, responses and events,
and emits fresh JSON object literals with TypeScript `satisfies` assertions.
The TypeScript compiler checks nested fields, union discriminators, required
members, scalar types and unexpected properties against the actual frontend
contract. The test does not replace DTOs with a separately maintained schema
and does not use casts that would suppress type errors.

The scenario covers connect/capabilities, getState before launch, a multi-file build, launch,
breakpoints, step, variable reads, stale-session rejection, state checkpoints,
event replay, history listing, stop, same-packet continue/pause and target I/O.
The existing integration assertions separately check state/sequence identities,
source mapping, lifecycle completion and independent output streams. Passing
these tests establishes compatibility for the exercised traffic, not every
possible value or every command.

The Debug backend passed this check against the exact baseline above with
TypeScript 5.9.3: 70 real frames (20 requests, 20 responses, 28 events and two
connect frames). The check first caught invalid empty output objects in
stop-generated observations; the backend now supplies complete output snapshots.
Before the first successful launch, `getState` returns a structured
`STALE_CONTEXT` error: v1 requires a non-null session state in a successful
state result. `connect` remains the nullable checkpoint for the initial state.

NDJSON connect adds `kind: "connectResult"` and a top-level `session` to the
adapter's connect result. The test models these transport fields explicitly;
an adapter must strip the envelope fields when returning the declared
`DebugBackendAdapter.connect` value. Requests and events otherwise use the
frontend DTOs directly.

From the repository root, with TypeScript already installed:

```sh
python3 backend/tests/frontend_contract_test.py \
  backend/out/linux-debug/phantom-backend \
  --contract-ref 56308532338bcccc65413c794052e06fc73a3e4f \
  --tsc node_modules/.bin/tsc
```

For an isolated compiler without installing the Electron/frontend dependency
tree, this command uses the npm cache and leaves repository packages unchanged:

```sh
npm exec --yes --package=typescript@5.9.3 -- \
  python3 backend/tests/frontend_contract_test.py \
  backend/out/linux-debug/phantom-backend \
  --contract-ref 56308532338bcccc65413c794052e06fc73a3e4f
```

`--contract-ref` resolves the Git revision once and reads its exact contract
without checkout/merge. Omit it to check the working tree, or use `--contract`
for another standalone DTO file. The test prints the contract commit/hash and
compiler version. It returns 77 when GDB or TypeScript is unavailable and does
not install dependencies itself.

## Remaining application integration

The native bridge still needs a process owner and an NDJSON adapter with
runtime validation of incoming frames, subscribe-before-connect buffering,
request correlation, session adoption, checkpoint/replay handling, and
disconnect/dispose behavior. The renderer then needs a separate real backend
session controller and a projection into its existing presentation model.
History selection must remain independent of the live stop; unsupported trace
overlays, variable writes and restore must remain disabled according to
capabilities. These are separate integration changes, not implied by the
compatibility tests.

The dependency-free frontend tests from the exact baseline were run from an
isolated archive: backend-contract, demo, runtime-trace, expression-layout and
camera-motion (17 tests passed on Node 24.21.0). A complete frontend build and
Electron/browser checks were not run: this Linux checkout has no frontend
dependency installation or configured browser. No renderer/preload/native
source was changed for this checkpoint.
