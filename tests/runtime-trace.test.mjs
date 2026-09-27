import test from 'node:test';
import assert from 'node:assert/strict';
import { DEMO_RUNTIME_EDGE_CASES } from '../src/demo.ts';

test('runtime fixture keeps control-flow facts separate from source lines', () => {
  const { source, controls } = DEMO_RUNTIME_EDGE_CASES;
  const kinds = new Set(controls.map((event) => event.kind));
  for (const kind of ['if', 'else', 'loop', 'switch', 'case', 'default', 'break', 'continue', 'goto', 'throw', 'catch', 'return']) {
    assert.ok(kinds.has(kind), `fixture covers ${kind}`);
  }
  for (const event of controls) {
    assert.equal(event.observed, true);
    assert.ok(event.range, `${event.id} has a source range`);
    const line = source.split('\n')[event.range.start.line - 1];
    const text = line.slice(event.range.start.column - 1, event.range.end.column - 1);
    assert.ok(text.trim().length > 0, `${event.id} range is not whitespace`);
    assert.ok(event.range.end.column > event.range.start.column, `${event.id} has a non-empty range`);
  }
  const exceptionEvents = controls.filter((event) => event.exceptionId === 'edge:exception-1');
  assert.deepEqual(exceptionEvents.map((event) => event.phase), ['before', 'unwind', 'caught']);
});

test('global primitive references retain declaration and use provenance', () => {
  const global = DEMO_RUNTIME_EDGE_CASES.globals[0];
  assert.equal(global.scope, 'global');
  assert.equal(global.qualifiedName, '::globalLimit');
  assert.equal(global.value, 3);
  assert.equal(global.locator, 'global::globalLimit');
  assert.equal(global.declarationRange.start.line, 1);
  assert.equal(global.useRange.start.line, 4);
  assert.deepEqual(JSON.parse(JSON.stringify(DEMO_RUNTIME_EDGE_CASES)), DEMO_RUNTIME_EDGE_CASES);
});
