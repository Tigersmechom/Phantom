import test from 'node:test';
import assert from 'node:assert/strict';
import { DEMO_SOURCE, DEMO_FRAME_COUNT, DEFAULT_INPUT, parseInput, snapshot, demoInputTrace } from '../src/demo.ts';

const input = parseInput(DEFAULT_INPUT);
const frames = () => Array.from({ length: DEMO_FRAME_COUNT }, (_, step) => snapshot(step, input));

test('declarations distinguish unavailable values from value-initialized C++ vectors', () => {
  const entry = snapshot(0, input);
  assert.equal(entry.n, null);
  assert.equal(entry.i, null);
  assert.equal(entry.sum, null);
  assert.deepEqual(entry.arrayValues, Array(6).fill(null));
  assert.deepEqual(entry.prefix, Array(7).fill(null));
  assert.deepEqual(entry.initialized, { n: false, values: false, prefix: false, i: false });
  assert.equal(snapshot(1, input).n, 6);
  assert.deepEqual(snapshot(2, input).arrayValues, Array(6).fill(0));
  assert.deepEqual(snapshot(2, input).prefix, Array(7).fill(null));
  assert.deepEqual(snapshot(16, input).prefix, Array(7).fill(0));
  assert.equal(snapshot(16, input).sum, 0);
  assert.equal(snapshot(17, input).i, 0);
});

test('every history snapshot is identical after forward, backward and repeated visits', () => {
  for (const submitted of [input, [0, 0, 0, 0, 0, 0], [-3, 1, -4, 0, 5, -9], [-1_000_000, 1_000_000, 0, -1, 1, 0]]) {
    const originalInput = [...submitted];
    const forward = Array.from({ length: DEMO_FRAME_COUNT }, (_, step) => structuredClone(snapshot(step, submitted)));
    for (let step = DEMO_FRAME_COUNT - 1; step >= 0; step--) {
      assert.deepEqual(snapshot(step, submitted), forward[step], `Backward frame ${step} must exactly match its forward snapshot`);
      if (step < DEMO_FRAME_COUNT - 1) {
        snapshot(step + 1, submitted);
        assert.deepEqual(snapshot(step, submitted), forward[step], `Forward/back round trip must not fill missing values at frame ${step}`);
      }
    }
    assert.deepEqual(submitted, originalInput);
  }
});

test('crossing allocations backwards restores unavailable slots, while known zeros stay zero', () => {
  for (const route of [[0, 1, 2, 3, 16, 17], [56, 17, 16, 15, 3, 2, 1, 0], [16, 15, 16, 2, 1, 2]]) {
    for (const step of route) {
      const frame = snapshot(step, [0, 0, 0, 0, 0, 0]);
      assert.deepEqual(frame.arrayValues, Array(6).fill(step < 2 ? null : 0));
      assert.deepEqual(frame.prefix, Array(7).fill(step < 16 ? null : 0));
      assert.equal(frame.initialized.values, step >= 2);
      assert.equal(frame.initialized.prefix, step >= 16);
      assert.equal(frame.sum, step < 16 ? null : 0);
    }
  }
});

test('stdin changes exactly one value per extraction and keeps untouched slots at zero', () => {
  for (let index = 0; index < 6; index++) {
    const bound = snapshot(3 + index * 2, input), read = snapshot(4 + index * 2, input);
    assert.equal(bound.line, 11);
    assert.equal(bound.inputIndex, index);
    assert.equal(bound.readCount, index);
    assert.equal(bound.arrayValues[index], 0);
    assert.equal(read.line, 12);
    assert.equal(read.readCount, index + 1);
    assert.deepEqual(read.arrayValues, [...input.slice(0, index + 1), ...Array(5 - index).fill(0)]);
  }
  assert.equal(snapshot(15, input).inputIndex, null);
});

test('every iteration records condition, call, parameters, addition, returned store and increment', () => {
  const cumulative = [0];
  for (const value of input) cumulative.push(cumulative.at(-1) + value);
  for (let index = 0; index < 6; index++) {
    const iteration = Array.from({ length: 6 }, (_, phase) => snapshot(18 + index * 6 + phase, input));
    assert.deepEqual(iteration.map(frame => frame.phase), ['condition', 'call', 'callee-entry', 'evaluate', 'store', 'increment']);
    assert.deepEqual(iteration.map(frame => frame.line), [15, 16, 4, 5, 16, 15]);
    const [condition, call, enter, evaluate, store, increment] = iteration;
    assert.equal(condition.i, index);
    assert.equal(condition.expression.result, 1);
    assert.equal(condition.expression.resultKind, 'boolean');
    assert.equal(call.expression.result, null, 'A pending call must not reveal its eventual result');
    assert.equal(enter.functionName, 'add(a, b)');
    assert.equal(enter.a, cumulative[index]);
    assert.equal(enter.b, input[index]);
    assert.deepEqual(evaluate.expression.operands, [cumulative[index], input[index]]);
    assert.equal(evaluate.expression.result, cumulative[index + 1]);
    assert.equal(evaluate.prefix[index + 1], 0, 'Calculation alone has not assigned the destination');
    assert.equal(store.functionName, 'main()');
    assert.equal(store.a, null);
    assert.equal(store.b, null);
    assert.equal(store.prefix[index + 1], cumulative[index + 1]);
    assert.equal(store.sum, cumulative[index + 1]);
    assert.equal(store.filled, index + 1);
    assert.equal(store.expression.target, `prefix[${index + 1}]`);
    assert.equal(increment.i, index + 1);
  }
});

test('false final condition, output and main return are separate deterministic frames', () => {
  const trace = frames();
  assert.equal(trace.length, 57);
  assert.equal(trace.filter(frame => frame.phase === 'condition').length, 7);
  assert.equal(trace.filter(frame => frame.phase === 'input').length, 6);
  const condition = trace[54], output = trace[55], returned = trace[56];
  assert.equal(condition.i, 6);
  assert.equal(condition.expression.result, 0);
  assert.equal(condition.expression.resultKind, 'boolean');
  assert.equal(output.i, null);
  assert.equal(output.inLoop, false);
  assert.equal(output.initialized.i, false);
  assert.equal(output.output, 'sum = 23\n');
  assert.equal(output.done, false);
  assert.equal(returned.done, true);
  assert.equal(returned.expression.result, 0);
  assert.deepEqual(returned.prefix, [0, 3, 4, 8, 9, 14, 23]);
  assert.equal(snapshot(56, [1, 2, 3, 4, 5, 6]).output, 'sum = 21\n');
});

test('source ranges are exact and snapshots can be revisited without mutation or invented values', () => {
  const expression = snapshot(21, input).expression;
  const line = DEMO_SOURCE.split('\n')[expression.line - 1];
  assert.equal(line.slice(expression.range.start.column - 1, expression.range.end.column - 1), 'a + b');
  const original = snapshot(22, input);
  original.prefix[0] = 999;
  original.arrayValues[0] = 999;
  assert.equal(snapshot(22, input).prefix[0], 0);
  assert.equal(snapshot(22, input).arrayValues[0], 3);
  assert.equal(snapshot(4, []).arrayValues[0], null);
  assert.equal(snapshot(56, []).sum, null);
  assert.deepEqual(snapshot(-1, input), snapshot(0, input));
  assert.deepEqual(snapshot(1000, input), snapshot(56, input));
  assert.deepEqual(snapshot(21.8, input), snapshot(21, input));
  assert.deepEqual(snapshot(Number.NaN, input), snapshot(0, input));
  assert.equal(new Set(frames().flatMap(frame => frame.expression ? [frame.expression.id] : [])).size, frames().filter(frame => frame.expression).length);
});

test('input trace preserves submitted whitespace and advances only known demo extractions', () => {
  const submitted = '\t-3  \r\n1\t4\u00a0 1\n5   9  ';
  const ranges = [...submitted.matchAll(/\S+/gu)].map(match => ({ start: match.index, end: match.index + match[0].length }));
  assert.equal(demoInputTrace(0, submitted).status, 'idle');
  for (let index = 0; index < 6; index++) {
    const active = demoInputTrace(3 + 2 * index, submitted);
    assert.equal(active.revision, submitted, 'revision is verbatim submitted text, not normalized tokens or an ID');
    assert.deepEqual(active.consumedRanges, ranges.slice(0, index));
    assert.deepEqual(active.activeRange, ranges[index]);
    assert.equal(submitted.slice(active.activeRange.start, active.activeRange.end), String(parseInput(submitted)[index]));
    const read = demoInputTrace(4 + 2 * index, submitted);
    assert.deepEqual(read.consumedRanges, ranges.slice(0, index + 1));
    assert.equal(read.activeRange, undefined);
  }
  assert.equal(demoInputTrace(14, submitted).status, 'complete');
  assert.deepEqual(demoInputTrace(56, submitted), demoInputTrace(14, submitted));
  assert.deepEqual(demoInputTrace(3, submitted).consumedRanges, [], 'History does not retain later consumption');
  for (const invalid of ['', '1 2', '1 2 3 4 😀 6', '1 2 3 4 5 nope']) {
    const trace = demoInputTrace(56, invalid);
    assert.equal(trace.revision, invalid);
    assert.equal(trace.status, 'error');
    assert.deepEqual(trace.consumedRanges, []);
    assert.equal(trace.activeRange, undefined);
  }
});

test('every prepared expression has exact operand and operation anchors in DEMO_SOURCE', () => {
  const snippets = new Map([
    [1, ['n = 6', ['6']]], [4, ['std::cin >> value', ['value']]],
    [16, ['n + 1', ['n', '1']]], [17, ['i = 0', ['0']]],
    [18, ['i < n', ['i', 'n']]], [19, ['add(prefix[i], values[i])', ['prefix[i]', 'values[i]']]],
    [21, ['a + b', ['a', 'b']]], [22, ['prefix[i + 1] = add(prefix[i], values[i])', ['add(prefix[i], values[i])']]],
    [23, ['++i', ['i']]], [55, ['prefix[n]', ['prefix[n]']]], [56, ['return 0', ['0']]],
  ]);
  const slice = range => DEMO_SOURCE.split('\n')[range.start.line - 1].slice(range.start.column - 1, range.end.column - 1);
  for (const [step, [expression, operands]] of snippets) {
    const event = snapshot(step, input).expression;
    assert.equal(slice(event.range), expression);
    assert.deepEqual(event.operandRanges.map(slice), operands);
    assert.deepEqual(event.operandLabels, operands, 'Labels come from the known source annotation, never inferred from numeric values');
    assert.equal(event.operands.length, event.operandRanges.length);
  }
  for (const frame of frames()) if (frame.expression) {
    assert.ok(frame.expression.range);
    assert.ok(frame.expression.operandRanges.every(range => range.start.line === frame.line));
    assert.equal(frame.expression.operandLabels.length, frame.expression.operands.length);
  }
  const mutated = snapshot(21, input);
  mutated.expression.operandLabels[0] = 'changed';
  assert.deepEqual(snapshot(21, input).expression.operandLabels, ['a', 'b'], 'Presentation labels cannot mutate a later history snapshot');
});
