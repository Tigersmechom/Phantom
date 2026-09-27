import type { BackendEventDTO, RuntimeValueDTO, SourceSpanDTO, StopObservationDTO } from '../../src/backend-contract.ts';
import type { ExpressionEvent } from '../../src/execution-types.ts';

export const fixtureSource = 'int main() { auto result = f() + g(); }\n';
export const fixtureInput = '\t-3  \r\n4 😀 9\u00a0';
const range = (text: string): SourceSpanDTO => {
  const start = fixtureSource.indexOf(text), end = start + text.length;
  return { documentId: 'main', revisionId: 'source-v1', range: { start, end }, start: { line: 1, column: start + 1 }, end: { line: 1, column: end + 1 } };
};
const integer = (decimal: string): RuntimeValueDTO => ({ availability: 'available', value: { kind: 'integer', decimal, bits: 64, signed: false } });
export const exactUint64 = integer('18446744073709551615');
export const unavailable: RuntimeValueDTO = { availability: 'unavailable', reason: 'uninitialized', detail: 'Confirmed by instrumentation' };
export const ieeeNaN: RuntimeValueDTO = { availability: 'available', value: { kind: 'float', text: 'NaN', bits: 64, classification: 'nan', rawBitsHex: '7ff8000000000000' } };
export const displayExpression: ExpressionEvent = { id: 'display:sum', line: 1, operands: ['9007199254740993', '2'], operator: '+', result: '9007199254740995', label: 'f() + g()' };
export const observation: StopObservationDTO = {
  id: 'observation-3', point: { branchId: 'branch-main', eventOrdinal: 3 }, stop: { stopId: 'stop-3', stateRevision: 0 },
  processInstanceId: 'process-1', buildId: 'build-arm64-v1', sourceBundleId: 'bundle-v1', reason: 'step', location: range('f() + g()'), threadId: 'thread-1',
  stack: [{ id: 'frame-1', activationId: 'main-1', functionName: 'main()', location: range('f() + g()'), variables: [
    { id: 'u', name: 'u', type: 'uint64_t', scopeId: 'main-body', activationId: 'main-1', locator: 'main-1:u', value: exactUint64, writable: true },
    { id: 'x', name: 'x', type: 'int', scopeId: 'main-body', activationId: 'main-1', locator: 'main-1:x', value: unavailable, writable: true },
    { id: 'nan', name: 'nan', type: 'double', scopeId: 'main-body', activationId: 'main-1', locator: 'main-1:nan', value: ieeeNaN, writable: false },
  ] }],
  input: {
    submitted: { id: 'input-v1', text: fixtureInput, encoding: 'utf-8', closeAfterWrite: true }, tracking: 'observed-extractions', deliveredBytes: 17,
    trace: { revision: fixtureInput, consumedRanges: [{ start: 1, end: 3 }], activeRange: { start: 7, end: 8 }, status: 'reading' }, consumedThroughUtf16: 3,
    stream: { eof: false, fail: false, bad: false },
    lastRead: { id: 'read-a', kind: 'formatted', status: 'completed', targetLocator: 'main-1:a', consumedRanges: [{ start: 1, end: 3 }], value: { availability: 'available', value: { kind: 'integer', decimal: '-3', bits: 32, signed: true } } },
  },
  stdout: { text: '', totalBytes: 0, retainedFromByte: 0, truncated: false }, stderr: { text: '', totalBytes: 0, retainedFromByte: 0, truncated: false },
  expressions: [{
    id: 'expression-3', range: range('f() + g()'), evidence: 'instrumentation', complete: true, activeStageIds: ['sum'],
    groups: [
      { id: 'calls', relationToPrevious: 'not-established', stages: [
        { id: 'g', kind: 'call', operator: 'call', label: 'g()', range: range('g()'), operands: [], result: integer('2'), dependsOn: [] },
        { id: 'f', kind: 'call', operator: 'call', label: 'f()', range: range('f()'), operands: [], result: integer('9007199254740993'), dependsOn: [] },
      ] },
      { id: 'addition', relationToPrevious: 'observed-after', stages: [
        { id: 'sum', kind: 'operator', operator: '+', label: 'f() + g()', range: range('f() + g()'), operands: [{ value: integer('9007199254740993'), range: range('f()') }, { value: integer('2'), range: range('g()') }], result: integer('9007199254740995'), dependsOn: ['f', 'g'] },
      ] },
    ],
  }],
  coverage: { variables: 'partial', expressions: 'observed', memory: 'none' },
};
export const fixtureEvents = [
  { protocolVersion: 1, workspace: { id: 'workspace-1', revisionId: 'workspace-v1' }, session: { id: 'session-1', generation: 1 }, processInstanceId: 'process-1', sequence: 1, causedByRequestId: 'step-3', payload: { kind: 'observation', observation } },
  { protocolVersion: 1, workspace: { id: 'workspace-1', revisionId: 'workspace-v1' }, session: { id: 'session-1', generation: 1 }, processInstanceId: 'process-1', sequence: 2, causedByRequestId: 'step-3', payload: { kind: 'commandFinished', requestId: 'step-3', outcome: 'completed' } },
] satisfies BackendEventDTO[];
