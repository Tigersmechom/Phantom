import test from 'node:test';
import assert from 'node:assert/strict';
import { BACKEND_PROTOCOL_VERSION } from '../src/backend-contract.ts';
import { fixtureEvents, fixtureInput, fixtureSource, observation, exactUint64, ieeeNaN, unavailable, displayExpression } from './fixtures/backend-events.ts';

test('protocol fixtures round-trip through JSON without narrowing exact integers or IEEE special values', () => {
  const restored = JSON.parse(JSON.stringify(fixtureEvents));
  assert.deepEqual(restored, fixtureEvents);
  assert.equal(restored[0].protocolVersion, BACKEND_PROTOCOL_VERSION);
  assert.equal(exactUint64.value.decimal, '18446744073709551615');
  assert.equal(BigInt(exactUint64.value.decimal), 2n ** 64n - 1n);
  assert.notEqual(unavailable.availability, ieeeNaN.availability);
  assert.equal(ieeeNaN.value.classification, 'nan');
  assert.equal(typeof displayExpression.operands[0], 'string');
  assert.equal(displayExpression.result, '9007199254740995');
});

test('input ranges refer to exact UTF-16 text while delivered bytes remain transport metadata', () => {
  const input = observation.input, trace = input.trace;
  assert.equal(trace.revision, input.submitted.text);
  assert.equal(input.deliveredBytes, Buffer.byteLength(fixtureInput, 'utf8'));
  assert.notEqual(input.deliveredBytes, fixtureInput.length, 'Unicode byte counts are not renderer offsets');
  assert.deepEqual(trace.consumedRanges.map(span => fixtureInput.slice(span.start, span.end)), ['-3']);
  assert.equal(fixtureInput.slice(trace.activeRange.start, trace.activeRange.end), '4');
  assert.equal(fixtureInput.slice(9, 11), '😀', 'Supplementary characters occupy two UTF-16 units');
  assert.notEqual(trace.revision, fixtureInput + ' ', 'An edited input must suppress old highlights');
  assert.equal(input.stream.eof, false, 'Closing the transport does not assert observed stream EOF');
});

test('expression fixture preserves supplied call grouping and exact source spans', () => {
  const expression = observation.expressions[0];
  assert.deepEqual(expression.groups[0].stages.map(stage => stage.id), ['g', 'f']);
  assert.equal(expression.groups[0].relationToPrevious, 'not-established');
  const sum = expression.groups[1].stages[0];
  assert.equal(expression.groups[1].relationToPrevious, 'observed-after');
  assert.deepEqual(sum.dependsOn, ['f', 'g']);
  for (const group of expression.groups) for (const stage of group.stages) {
    const { range, start, end } = stage.range;
    assert.equal(fixtureSource.slice(range.start, range.end), stage.label);
    assert.equal(start.column - 1, range.start);
    assert.equal(end.column - 1, range.end);
  }
  assert.equal(sum.result.value.decimal, '9007199254740995');
  assert.equal(fixtureEvents[1].payload.requestId, fixtureEvents[0].causedByRequestId);
  assert.ok(fixtureEvents[1].sequence > fixtureEvents[0].sequence);
});
