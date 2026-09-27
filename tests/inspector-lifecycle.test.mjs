import { chromium } from 'playwright';
import assert from 'node:assert/strict';

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
  await page.route('**/inspector-lifecycle-harness', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body><main id="root"></main></body></html>' }));
  await page.goto(`${process.env.TEST_URL || 'http://127.0.0.1:5173'}/inspector-lifecycle-harness`);
  await page.evaluate(async () => {
    const react = await import('/node_modules/.vite/deps/react.js');
    const React = react.default || react;
    const dom = await import('/node_modules/.vite/deps/react-dom_client.js');
    const ReactDOM = dom.default || dom;
    const { default: InspectorScope } = await import('/src/InspectorScope.tsx');
    await import('/src/styles.css'); await import('/src/inspector-motion.css');
    const h = React.createElement;
    const main = (values = [null, null, null]) => ({ id: 'main', functionName: 'main()', scalars: [{ id: 'n', name: 'n', type: 'int', value: 3, kind: 'local', caption: 'length' }], arrays: [{ id: 'values', name: 'values', type: 'vector<int>', values, collapsible: true }] });
    const add = { id: 'add', functionName: 'add(a, b)', scalars: [{ id: 'a', name: 'a', type: 'int', value: 1, kind: 'argument', caption: 'argument' }, { id: 'b', name: 'b', type: 'int', value: 2, kind: 'argument', caption: 'argument' }], arrays: [] };
    function Fixture() {
      const [state, setState] = React.useState({ frame: main(), transition: undefined });
      window.move = (frame, transition) => setState({ frame, transition });
      return h(InspectorScope, { frame: state.frame, transition: state.transition, fileName: 'test.cpp', line: 4 });
    }
    ReactDOM.createRoot(document.getElementById('root')).render(h(Fixture));
    window.testFrames = { mainNull: main(), mainKnown: main([1, 2, 3]), add };
  });
  const scope = page.getByTestId('inspector-scope');
  assert.deepEqual(await page.locator('[data-variable]').evaluateAll(nodes => nodes.map(node => node.dataset.variable)), ['n', 'values']);
  await page.evaluate(() => window.move(window.testFrames.add, { kind: 'forward', departedFrame: false }));
  assert.deepEqual(await page.locator('[data-variable]').evaluateAll(nodes => nodes.map(node => node.dataset.variable)), ['a', 'b']);
  assert.equal(await page.locator('[data-retired-variable]').count(), 0, 'Entering a callee never leaves caller ghosts');
  await page.evaluate(() => window.move(window.testFrames.mainKnown, { kind: 'forward', departedFrame: true }));
  assert.deepEqual(await page.locator('[data-variable]').evaluateAll(nodes => nodes.map(node => node.dataset.variable)), ['n', 'values']);
  assert.equal(await page.locator('[data-retired-variable="a"]').count(), 1, 'Explicit return owns the retired subtree');
  assert.equal(await page.locator('[data-retired-variable="b"]').count(), 1);
  assert.equal(await page.locator('[data-retired-variable="a"]').getAttribute('aria-hidden'), null, 'Only the parent ghost is aria-hidden, descendants remain queryable for animation');
  assert.equal(await page.locator('[data-retired-frame]').getAttribute('aria-hidden'), 'true');
  await page.evaluate(() => window.move(window.testFrames.add, { kind: 'seek' }));
  assert.equal(await page.locator('[data-retired-frame]').count(), 0, 'Seek/back clears retired visuals without death animation');
  await page.evaluate(() => window.move(window.testFrames.mainNull, { kind: 'seek' }));
  await page.evaluate(() => window.move(window.testFrames.mainKnown, { kind: 'forward' }));
  assert.equal(await page.locator('[data-lifecycle="birth"]').count(), 3, 'Only null to known array cells receive birth choreography');
  await page.evaluate(() => window.move(window.testFrames.mainNull, { kind: 'seek' }));
  await page.waitForTimeout(30);
  assert.equal(await page.locator('[data-lifecycle="birth"]').count(), 0, 'Seek never flashes a birth/death transition');
  const partial = { id: 'partial', functionName: 'main()', scalars: [{ id: 'n', name: 'n', type: 'int', value: 3, kind: 'local', caption: 'length' }], arrays: [{ id: 'values', name: 'values', type: 'vector<int>', values: [1, 2, 3] }] };
  await page.evaluate(frame => window.move(frame, { kind: 'forward', departedVariables: ['n'] }), partial);
  assert.equal(await page.locator('[data-retired-variable="n"]').count(), 1, 'Explicit variable retirement is scoped to the named ID');
  assert.equal(await page.locator('[data-retired-array]').count(), 0, 'A scalar retirement never guesses an array death');
  const invalidated = { ...partial, id: 'invalidated', scalars: [{ ...partial.scalars[0], lifetime: { state: 'invalidated', invalidatedAt: 'test', reason: 'vector reallocation' } }] };
  await page.evaluate(frame => window.move(frame, { kind: 'seek' }), invalidated);
  assert.equal(await page.locator('[data-variable="n"][data-lifetime="invalidated"]').count(), 1, 'Lifetime zombie styling requires explicit metadata');
  assert.equal(await page.locator('[data-variable="n"].inspector-lifecycle-invalidated').count(), 1);
  const large = { id: 'large', functionName: 'large()', scalars: [], arrays: [{ id: 'large', name: 'largeArrayWithAnExtremelyLongNameThatStaysAccessible', type: 'vector<int>', values: Array.from({ length: 300 }, (_, index) => index), readingIndex: 260 }] };
  await page.evaluate(frame => window.move(frame, { kind: 'forward' }), large);
  await page.locator('[data-variable^="largeArray"] .array-cell').first().waitFor();
  assert.ok(await page.locator('[data-variable^="largeArray"] .array-cell').count() <= 128, 'Large arrays render a bounded page');
  assert.equal(await page.locator('[data-variable^="largeArray"] .array-cell').first().locator(':scope > span').textContent(), '256', 'Page follows the active index deterministically');
  assert.equal(await page.locator('[data-variable^="largeArray"] .array-cell').last().locator(':scope > span').textContent(), '299');
  assert.equal(await page.locator('[data-variable^="largeArray"] .variable-name').getAttribute('title'), 'largeArrayWithAnExtremelyLongNameThatStaysAccessible');
  console.log('PASS: explicit inspector lifetime transitions, active-frame semantic DOM, null-to-known births, seek reset and bounded large-array pages.');
} finally { await browser.close(); }
