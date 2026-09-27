import { chromium } from 'playwright';
import { strict as assert } from 'node:assert';
import { mkdir } from 'node:fs/promises';

await mkdir('previews', { recursive: true });
const browser = await chromium.launch({
  executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: true,
  args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader'],
});
const captureOnly = process.argv.includes('--capture-only');
const expressionOnly = process.argv.includes('--expressions-only') || process.argv.includes('--variants') || process.argv.includes('--rail');
const variantsOnly = process.argv.includes('--variants');
const railOnly = process.argv.includes('--rail');
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
const errors = [];
page.on('pageerror', (error) => errors.push(error.message));
page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
const readCamera = (canvas) => canvas.evaluate((element) => ({
  target: (element.dataset.cameraTarget || '').split(',').map(Number),
  position: (element.dataset.cameraPosition || '').split(',').map(Number),
  state: element.dataset.followState,
  motion: element.dataset.cameraMotion,
  line: Number(element.dataset.activeLine),
  resumeAt: Number(element.dataset.resumeAt),
  resumedAt: Number(element.dataset.resumedAt),
  interacting: element.dataset.interacting,
  panVelocity: (element.dataset.panVelocity || '0,0,0').split(',').map(Number),
}));
const waitSettled = () => page.waitForFunction(() => {
  const canvas = document.querySelector('.spatial-code__viewport canvas');
  return canvas?.dataset.cameraTarget && canvas.dataset.cameraMotion === 'still';
}, undefined, { timeout: 20000 });
const render = async (props) => {
  await page.evaluate((patch) => window.renderSpatialTest(patch), props);
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
};

async function runRailChecks() {
  const source = 'int add(int a, int b) {\n    return a + b;\n}\n\nint main() {\n    int prefix[2] = {0};\n    int values[1] = {3};\n    prefix[1] = add(prefix[0], values[0]);\n    return prefix[1];\n}';
  const range = (line, text) => {
    const column = source.split('\n')[line - 1].indexOf(text) + 1;
    assert.ok(column > 0);
    return { start: { line, column }, end: { line, column: column + text.length } };
  };
  const pending = { id: 'rail-call', line: 8, operator: 'call', label: 'add(prefix[0], values[0])', operands: [0, 3], result: null,
    operandLabels: ['prefix[0]', 'values[0]'], range: range(8, 'add(prefix[0], values[0])'), operandRanges: [range(8, 'prefix[0]'), range(8, 'values[0]')] };
  await render({ source, activeLine: 8, expression: null, expressionStyle: 'rail', isPlaying: false });
  await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
  await waitSettled();
  await page.clock.pauseAt(new Date(Date.now() + 100));
  const current = () => page.locator('.expression-card[data-presence="present"]');
  const tick = async (ms) => { await page.waitForTimeout(60); await page.clock.runFor(ms); };
  const patch = async (value, ms = 1000) => { await page.evaluate((data) => window.renderSpatialTest(data), value); await tick(ms); };
  const freezeCSS = async (at) => {
    await current().evaluate((element, ms) => {
      for (const animation of element.getAnimations({ subtree: true })) { animation.pause(); animation.currentTime = ms; }
    }, at);
    // Projection must observe the frozen frame positions before a screenshot.
    await page.clock.runFor(16);
  };
  await patch({ expression: pending });
  await freezeCSS(1000);
  assert.equal(await current().locator('.rail-argument').count(), 2);
  assert.deepEqual(await current().locator('.rail-argument-label').allTextContents(), ['prefix[0]', 'values[0]']);
  assert.deepEqual(await current().locator('.expression-operand').allTextContents(), ['0', '3']);
  assert.deepEqual(await current().locator('.expression-operator').allTextContents(), [','], 'Calls separate arguments with a comma, never an invented arithmetic sign');
  assert.equal(await current().locator('.rail-result').count(), 0);
  const links = await current().locator('.rail-operand-link').evaluateAll((elements) => elements.map((element) => ({ index: element.dataset.operandIndex, exact: element.dataset.exact, x: Number(element.dataset.sourceX), line: Number(element.dataset.sourceLine), column: Number(element.dataset.sourceColumn), width: parseFloat(getComputedStyle(element).strokeWidth), dash: getComputedStyle(element).strokeDasharray })));
  assert.equal(links.length, 2);
  assert.ok(links.every((link) => link.exact === 'true' && link.width >= 2.5 && link.dash !== 'none'));
  assert.deepEqual(links.map((link) => link.column), pending.operandRanges.map((item) => item.start.column));
  assert.ok(Math.abs(links[0].x - links[1].x) > 15, 'Every argument has its own projected source anchor');
  await page.screenshot({ path: 'previews/rail-pending.png' });

  const sum = { id: 'rail-add', line: 2, operator: '+', label: 'a + b', operands: [1, 2], result: 3, target: 'return',
    operandLabels: ['a', 'b'], range: range(2, 'a + b'), operandRanges: [range(2, 'a'), range(2, 'b')] };
  await patch({ expression: sum, activeLine: 2, executionKey: 'rail-add' }, 1200);
  await freezeCSS(1200);
  assert.equal(await current().getAttribute('data-phase'), 'rise', 'Manual arguments have at least one second of reading time before merging');
  assert.deepEqual(await current().locator('.expression-operator').allTextContents(), ['+']);
  const styles = await current().evaluate((element) => {
    const operand = element.querySelector('.expression-operand');
    const operator = element.querySelector('.expression-operator');
    const result = element.querySelector('.expression-result');
    return { colors: [operand, operator, result].map((node) => getComputedStyle(node).color), size: parseFloat(getComputedStyle(operand).fontSize), opacity: Number(getComputedStyle(operand.closest('.rail-argument')).opacity) };
  });
  assert.equal(new Set(styles.colors).size, 3, 'Operands, operation, and observed result use distinct colors');
  assert.ok(styles.size >= 26 && styles.opacity > .99);
  assert.ok(await current().evaluate((element) => [...element.querySelectorAll('.rail-operand-link')].every((path) => {
    const numbers = path.getAttribute('d').match(/-?\d+(?:\.\d+)?/g).map(Number);
    const [x, y] = numbers.slice(-2);
    const frame = element.querySelector(`.rail-argument[data-operand-index="${path.dataset.operandIndex}"]`).getBoundingClientRect();
    return Math.min(Math.abs(x - frame.left), Math.abs(x - frame.right), Math.abs(y - frame.top), Math.abs(y - frame.bottom)) < 1;
  })), 'Every dashed path ends on its actual argument frame');
  await page.screenshot({ path: 'previews/rail-arithmetic.png' });
  await tick(350);
  assert.equal(await current().getAttribute('data-phase'), 'merge');
  await tick(1300);
  await freezeCSS(2850);
  assert.equal(await current().getAttribute('data-phase'), 'result');
  assert.equal(await current().locator('.expression-result').textContent(), '3');
  await page.screenshot({ path: 'previews/rail-result.png' });

  // A later event cancels the entire slow sequence, including all pending groups.
  await patch({ expression: { ...sum, id: 'cancelled' } }, 300);
  await patch({ expression: { ...pending, id: 'replacement-call' }, activeLine: 8 }, 3500);
  assert.equal(await current().getAttribute('data-event-id'), 'replacement-call');
  assert.equal(await page.locator('.expression-card').count(), 1);
  assert.equal(await current().locator('.rail-result').count(), 0);

  // Reduced motion lets us inspect every supplied operation without running arithmetic.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await tick(100);
  for (const operator of ['+', '-', '*', '/', '%', '<', '>', '<=', '>=', '==', '!=', '^', '&', '|', '&&', '||', '<<', '>>']) {
    await patch({ expression: { ...sum, id: `operator-${operator}`, operator, result: null }, activeLine: 2 }, 50);
    assert.deepEqual(await current().locator('.expression-operator').allTextContents(), [operator]);
  }
  await patch({ expression: { ...sum, id: 'boolean-false', operator: '<', result: 0, resultKind: 'boolean' } }, 50);
  assert.equal(await current().locator('.expression-result').textContent(), 'false');
  await patch({ expression: { ...sum, id: 'overloaded-comparison', operator: '<', result: 'custom-ordering' } }, 50);
  assert.equal(await current().locator('.expression-result').textContent(), 'custom-ordering', 'An overloaded comparison never guesses a boolean result type');

  // Long exact values and four operands wrap inside a narrow editor viewport.
  await page.setViewportSize({ width: 560, height: 760 });
  const exact = '18446744073709551615';
  await patch({ expression: { ...sum, id: 'narrow-u64', result: null, operands: [exact, exact, exact], operandLabels: ['first', 'second', 'third'], operandRanges: [sum.operandRanges[0], sum.operandRanges[1], sum.operandRanges[0]] } }, 150);
  assert.deepEqual(await current().locator('.expression-operand').allTextContents(), [exact, exact, exact]);
  const narrowBounds = await current().locator('.rail-argument').evaluateAll((elements) => elements.map((element) => { const box = element.getBoundingClientRect(); return { left: box.left, right: box.right, top: box.top, bottom: box.bottom }; }));
  assert.ok(narrowBounds.every((box) => box.left >= 0 && box.right <= 560 && box.top >= 0 && box.bottom <= 760), 'Wrapped exact-value frames stay inside a narrow viewport');
  assert.equal(await current().locator('.expression-anchor').getAttribute('data-visible'), 'true');
  assert.ok(new Set(narrowBounds.map((box) => Math.round(box.top))).size > 1, 'Long arguments use multiple rows');
  await page.screenshot({ path: 'previews/rail-narrow.png' });
  await patch({ expression: { ...sum, id: 'four-operands', result: null, operands: [2, 3, 4, 5], operandLabels: ['a', 'b', 'c', 'd'] } }, 150);
  assert.equal(await current().locator('.rail-argument').count(), 4);
  assert.equal(await current().locator('.expression-anchor').getAttribute('data-visible'), 'true');

  await patch({ expression: { ...sum, id: 'missing-ranges', result: null, operandRanges: undefined } }, 50);
  assert.deepEqual(await current().locator('.rail-operand-link').evaluateAll((elements) => elements.map((element) => element.dataset.exact)), ['false', 'false'], 'Missing operand ranges never fabricate exact source connections');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await patch({ expression: { ...sum, id: 'autoplay-final', result: exact }, isPlaying: true }, 100);
  assert.equal(await current().locator('.rail-argument').count(), 0);
  assert.equal(await current().locator('.rail-operand-link').count(), 0);
  assert.equal(await current().locator('.expression-result').textContent(), exact);
  await page.evaluate((event) => { for (let index = 0; index < 24; index++) window.renderSpatialTest({ expression: { ...event, id: `rapid-${index}`, result: String(index) } }); }, sum);
  await tick(3500);
  assert.equal(await current().getAttribute('data-event-id'), 'rapid-23');
  assert.equal(await page.locator('.expression-card').count(), 1);
  assert.equal(await current().locator('.expression-result').textContent(), '23');
  assert.deepEqual(errors, []);
  console.log('Rail checks passed: separate labeled arguments, independent exact dashed anchors, readable slow sequence, supplied C++ operators, boolean metadata, exact values, cancellation, responsive wrapping, reduced motion, final-only playback.');
}

try {
  if (variantsOnly || railOnly) await page.clock.install();
  await page.goto('http://127.0.0.1:5173', { waitUntil: 'networkidle' });
  if (captureOnly) {
    await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
    await page.getByRole('tab', { name: 'Вид', exact: true }).click();
    await page.locator('.theme-option').filter({ hasText: 'Spectral' }).click();
    await page.keyboard.press('Escape');
    await page.locator('.editor-view-switch button').filter({ hasText: '3D' }).click();
    await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
    await page.evaluate(async () => {
      await document.fonts.load('18px "Monaspace Krypton"');
      await document.fonts.ready;
    });
    await waitSettled();
    await page.getByRole('button', { name: 'Кадр 22', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.activeLine === '5');
    await waitSettled();
    await page.getByRole('button', { name: 'Кадр 23', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.activeLine === '16');
    await waitSettled();
    await page.screenshot({ path: 'previews/spectral.png', fullPage: true });
    assert.deepEqual(errors, []);
    console.log('App camera wiring passed (caller → function → caller); 3D preview captured at 1440 × 1000 with local fonts loaded.');
  } else {
    // Mount the actual production component with controlled execution events. This isolates
    // camera timing from the presentation trace and exercises arbitrary function jumps.
    await page.evaluate(async () => {
      const [ReactModule, DOM, spatial, palette, demo] = await Promise.all([
        import('/node_modules/.vite/deps/react.js'),
        import('/node_modules/.vite/deps/react-dom_client.js'),
        import('/src/SpatialCode.tsx'),
        import('/src/xcode-palette.json?import'),
        import('/src/demo.ts'),
      ]);
      const source = demo.DEMO_SOURCE + '\n'.repeat(38) + 'int distant(int x) {\n    return x * 2;\n}';
      window.spatialTestSource = source;
      window.distantSpatialLine = source.split('\n').findIndex((line) => line.includes('return x * 2')) + 1;
      const host = document.createElement('div');
      host.style.cssText = 'position:fixed;inset:0;z-index:10000;background:#08090d';
      document.body.appendChild(host);
      const root = DOM.default.createRoot(host);
      let props = { source, palette: palette.default.dark.colors, activeLine: 16, executionKey: 0, followExecution: true, depth: .56, light: 3.4, wireframe: false, resetKey: 0, expression: null };
      window.renderSpatialTest = (patch) => {
        props = { ...props, ...patch };
        root.render(ReactModule.default.createElement(spatial.default, props));
      };
      window.renderSpatialTest({});
    });
    await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
    await waitSettled();
    const canvas = page.locator('.spatial-code__viewport canvas');
    const box = await canvas.boundingBox();
    assert.ok(box && box.width > 600 && box.height > 400);
    assert.equal(await page.locator('.spatial-code__controls').count(), 0, 'The 3D viewport must not contain the removed bottom settings panel');
    assert.equal((await readCamera(canvas)).state, 'follow');
    assert.equal(await page.locator('.spatial-code__fallback').count(), 0);

    if (!expressionOnly) {
    // Acceleration and release are measured from the rendered camera, not key-repeat counts.
    await canvas.focus();
    await page.keyboard.down('ArrowRight');
    await page.waitForFunction(() => Number(document.querySelector('canvas')?.dataset.panVelocity?.split(',')[0]) > .05);
    const accelerating = await readCamera(canvas);
    await page.waitForTimeout(300);
    const cruising = await readCamera(canvas);
    assert.ok(cruising.panVelocity[0] > accelerating.panVelocity[0], 'Holding an arrow must smoothly accelerate toward cruising speed');
    await canvas.evaluate((element) => {
      for (let index = 0; index < 30; index++) element.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', repeat: true, bubbles: true }));
    });
    await page.keyboard.up('ArrowRight');
    const atRelease = await readCamera(canvas);
    await page.waitForTimeout(350);
    const coasting = await readCamera(canvas);
    assert.ok(coasting.target[0] > atRelease.target[0], 'The camera should coast gently after release');
    assert.ok(coasting.panVelocity[0] > 0 && coasting.panVelocity[0] < atRelease.panVelocity[0] * .65, 'Inertia must decay rather than stop or gain momentum');
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.followState === 'follow');
    await waitSettled();

    // A single key tap must move; a held key must never snap back after two seconds.
    await canvas.focus();
    const beforeArrow = await readCamera(canvas);
    await page.keyboard.press('ArrowDown');
    await page.waitForFunction((y) => Number(document.querySelector('canvas')?.dataset.cameraTarget?.split(',')[1]) < y - .1, beforeArrow.target[1], { timeout: 1800 });
    const afterArrow = await readCamera(canvas);
    assert.ok(afterArrow.target[1] < beforeArrow.target[1] - .1, JSON.stringify({ beforeArrow, afterArrow, focused: await canvas.evaluate((element) => document.activeElement === element) }));
    await page.keyboard.down('ArrowRight');
    await page.waitForTimeout(2200);
    assert.equal((await readCamera(canvas)).state, 'manual');
    assert.equal((await readCamera(canvas)).interacting, 'true');
    await page.keyboard.up('ArrowRight');
    const released = await readCamera(canvas);
    assert.ok(Number.isFinite(released.resumeAt));
    await page.waitForTimeout(1550);
    assert.equal((await readCamera(canvas)).state, 'manual', 'Following must not restart before the two-second idle period');
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.followState === 'follow');
    const resumed = await readCamera(canvas);
    assert.ok(resumed.resumedAt >= released.resumeAt - 2, 'The return must not start early');
    assert.ok(resumed.resumedAt - released.resumeAt < 250, 'The return starts at the two-second deadline, within browser scheduling tolerance');
    await waitSettled();

    // Dragging longer than two seconds is still an active interaction.
    await page.mouse.move(box.x + box.width * .48, box.y + box.height * .48);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * .57, box.y + box.height * .53, { steps: 8 });
    await page.waitForTimeout(2200);
    assert.equal((await readCamera(canvas)).state, 'manual');
    assert.equal((await readCamera(canvas)).interacting, 'true');
    await page.mouse.up();
    const mouseReleased = await readCamera(canvas);
    await page.waitForTimeout(300);
    const beforeZoom = await readCamera(canvas);
    await page.mouse.wheel(0, -160);
    await page.waitForTimeout(200);
    const afterZoom = await readCamera(canvas);
    assert.notDeepEqual(beforeZoom.position, afterZoom.position, 'The wheel still changes camera distance');
    assert.ok(afterZoom.resumeAt > mouseReleased.resumeAt + 200, 'A wheel gesture restarts the idle deadline');
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.followState === 'follow');
    await waitSettled();

    const caller = await readCamera(canvas);
    const distantLine = await page.evaluate(() => window.distantSpatialLine);
    await render({ activeLine: distantLine, executionKey: 1, isPlaying: true });
    await page.waitForFunction((line) => Number(document.querySelector('canvas')?.dataset.activeLine) === line, distantLine);
    const duringJump = await readCamera(canvas);
    assert.equal(duringJump.motion, 'flying');
    assert.ok(Math.abs(duringJump.target[1] - caller.target[1]) < 10, 'The function jump starts from the current view without teleporting');
    await waitSettled();
    const callee = await readCamera(canvas);
    assert.ok(callee.target[1] < caller.target[1] - 30, 'Following reaches the function in a distant part of the source');
    assert.ok(callee.position[2] > callee.target[2]);
    await render({ activeLine: 5, executionKey: 2 });
    await waitSettled();
    assert.ok((await readCamera(canvas)).target[1] > caller.target[1], 'Return flights can travel back to earlier functions');

    await render({ followExecution: false });
    await page.waitForTimeout(50);
    await canvas.focus();
    await page.keyboard.press('ArrowLeft');
    await waitSettled();
    const freePosition = await readCamera(canvas);
    await render({ activeLine: 16, executionKey: 3 });
    await page.waitForTimeout(2200);
    assert.equal((await readCamera(canvas)).state, 'free');
    assert.deepEqual((await readCamera(canvas)).target, freePosition.target, 'Disabling follow preserves the manual view across execution steps');
    await render({ followExecution: true });
    await waitSettled();
    assert.equal((await readCamera(canvas)).state, 'follow');

    const beforeInput = await readCamera(canvas);
    await page.evaluate(() => {
      const input = document.createElement('input');
      input.id = 'camera-keyboard-isolation';
      input.style.cssText = 'position:fixed;top:10px;left:10px;z-index:20000';
      document.body.appendChild(input);
      input.focus();
    });
    await page.keyboard.press('ArrowDown');
    await page.waitForTimeout(120);
    assert.deepEqual((await readCamera(canvas)).target, beforeInput.target, 'Typing controls outside the viewport must not pan the camera');
    await page.evaluate(() => document.getElementById('camera-keyboard-isolation').remove());

    await canvas.evaluate((element) => { element.dataset.liveIdentity = 'same-geometry'; });
    await render({ highlightBrightness: 0 });
    const unhighlighted = await canvas.screenshot();
    assert.equal(await canvas.getAttribute('data-highlight-opacity'), '0');
    await render({ highlightBrightness: 2 });
    const highlighted = await canvas.screenshot();
    assert.notDeepEqual(highlighted, unhighlighted, 'The brightness setting must visibly update the active-line stripe');
    assert.equal(await canvas.getAttribute('data-highlight-opacity'), '0.09');
    assert.equal(await canvas.getAttribute('data-live-identity'), 'same-geometry', 'Brightness must update live without recreating the scene');
    await render({ highlightBrightness: 1 });
    const beforeAppearance = await canvas.screenshot();
    await render({ depth: 1.1, light: 5.7, wireframe: true });
    await page.waitForTimeout(250);
    assert.notDeepEqual(await canvas.screenshot(), beforeAppearance, 'Controlled appearance settings update the actual rendered geometry');
    await render({ depth: .56, light: 3.4, wireframe: false });
    await canvas.focus();
    await page.keyboard.press('ArrowUp');
    await render({ resetKey: 1 });
    await waitSettled();
    assert.equal((await readCamera(canvas)).state, 'follow', 'Reset resumes following immediately');

    }
    if (railOnly) {
      await runRailChecks();
    } else if (variantsOnly) {
      const source = 'int add(int a, int b) {\n    return a + b;\n}\n\nint main() {\n    int pref[1] = {};\n    pref[0] = add(1, 2) + add(3, 4);\n    return pref[0];\n}';
      const range = (text) => {
        const column = source.split('\n')[6].indexOf(text) + 1;
        return { start: { line: 7, column }, end: { line: 7, column: column + text.length } };
      };
      const expression = { id: 'two-calls', line: 7, label: 'add(1, 2) + add(3, 4)', operator: '+', operands: [3, 7], result: 10,
        range: range('add(1, 2) + add(3, 4)'), operandLabels: ['add(1, 2)', 'add(3, 4)'], operandRanges: [range('add(1, 2)'), range('add(3, 4)')],
        groups: [{ id: 'independent-calls', stages: [
          { id: 'add-left', label: 'add(1, 2)', operator: 'call', operands: [1, 2], result: 3, range: range('add(1, 2)'), operandLabels: ['1', '2'], operandRanges: [range('1'), range('2')] },
          { id: 'add-right', label: 'add(3, 4)', operator: 'call', operands: [3, 4], result: 7, range: range('add(3, 4)'), operandLabels: ['3', '4'], operandRanges: [range('3'), range('4')] },
        ] }],
      };
      await render({ source, activeLine: 7, expression: null, isPlaying: false });
      await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
      await waitSettled();
      await page.clock.pauseAt(new Date(Date.now() + 100));
      for (const style of ['float', 'rail', 'inline']) {
        await page.evaluate(({ expression, style }) => window.renderSpatialTest({ expression: { ...expression, id: `variant-${style}` }, expressionStyle: style }), { expression, style });
        await page.waitForTimeout(80);
        await page.clock.runFor(850);
        const active = page.locator('.expression-card[data-presence="present"]');
        assert.equal(await active.getAttribute('data-group-id'), 'independent-calls');
        assert.equal(await active.locator('.expression-anchor[data-visible="true"]').count(), 2, `${style}: both independent function results should be visible: ${await active.locator('.expression-anchor').evaluateAll((elements) => elements.map((element) => JSON.stringify(element.dataset)))}`);
        assert.deepEqual(await active.locator('.expression-anchor').evaluateAll((elements) => elements.map((element) => element.dataset.glyphOverlap)), ['false', 'false']);
        await active.evaluate((element) => { for (const animation of element.getAnimations({ subtree: true })) { animation.pause(); animation.currentTime = 850; } });
        await page.clock.runFor(16);
        await page.screenshot({ path: `previews/variant-${style}.png` });
      }
      assert.deepEqual(errors, []);
      console.log('Three projected variants captured with two independent add calls and exact source ranges.');
    } else {
    const expressionSource = 'int main() {\n    const int a = 2;\n    const int b = 3;\n    const int c = 4;\n    const int d = 5;\n\n    const int total = a + b + c + d;\n    return total;\n}';
    await render({ source: expressionSource, isPlaying: false, activeLine: 7, expression: null });
    await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
    await waitSettled();
    const expression = {
      id: 'sum-four', line: 7, range: { start: { line: 7, column: 23 }, end: { line: 7, column: 36 } }, operands: [2, 3, 4, 5], operator: '+', result: 14, label: 'a + b + c + d', target: 'total',
      operandRanges: [23, 27, 31, 35].map((column) => ({ start: { line: 7, column }, end: { line: 7, column: column + 1 } })),
    };
    const viewportBeforeExpression = await canvas.boundingBox();
    await render({ expression });
    const card = page.locator('.expression-card[data-presence="present"]');
    await card.waitFor();
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').count(), 4, 'Every recorded operand is presented');
    assert.equal(await canvas.getAttribute('data-operand-guide-count'), '4', 'Only the four supplied source ranges receive an underline');
    await page.waitForFunction(() => document.querySelector('.expression-card[data-presence="present"]')?.getAttribute('data-phase') === 'merge');
    const viewportWithExpression = await canvas.boundingBox();
    await card.locator('.expression-anchor[data-visible="true"] .expression-chip').waitFor();
    assert.equal(await card.locator('.expression-anchor').getAttribute('data-glyph-overlap'), 'false', 'Projected calculation avoids code glyphs');
    assert.equal(viewportWithExpression.y, 0, 'No top strip is reserved above the code');
    assert.deepEqual(viewportWithExpression, viewportBeforeExpression, 'Showing an expression must not move or resize the code viewport');
    await card.evaluate((element) => {
      for (const animation of element.getAnimations({ subtree: true })) { animation.pause(); animation.currentTime = 220; }
    });
    await page.screenshot({ path: 'previews/expression-manual.png' });
    await card.evaluate((element) => { for (const animation of element.getAnimations({ subtree: true })) animation.play(); });
    await page.waitForFunction(() => {
      const result = document.querySelector('.expression-result');
      return result && Number(getComputedStyle(result).opacity) > .99;
    });
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').textContent(), '14', 'The result comes directly from the trace');
    await page.screenshot({ path: 'previews/expression-result.png' });

    // Disappearance keeps the old value while opacity eases out, without reserving space.
    await render({ expression: null });
    const departing = page.locator('.expression-card[data-presence="exiting"]');
    assert.equal(await departing.count(), 1, 'The previous result is retained for its exit transition');
    await page.waitForTimeout(140);
    const exitingOpacity = await departing.evaluate((element) => Number(getComputedStyle(element).opacity));
    assert.ok(exitingOpacity > 0 && exitingOpacity < 1, 'Disappearance has a real intermediate opacity');
    await page.waitForTimeout(450);
    assert.equal(await departing.count(), 0, 'Finished exits are disposed');

    const variantCenters = [];
    for (const style of ['float', 'rail', 'inline']) {
      await render({ expression: { ...expression, id: `live-${style}` }, expressionStyle: style });
      await page.waitForTimeout(700);
      const anchor = card.locator('.expression-anchor');
      assert.equal(await anchor.getAttribute('data-visible'), 'true', `${style} remains visible near the expression`);
      assert.equal(await anchor.getAttribute('data-anchor-kind'), 'range');
      assert.equal(await anchor.getAttribute('data-glyph-overlap'), 'false');
      const position = JSON.parse(await anchor.getAttribute('data-box'));
      variantCenters.push([(position.left + position.right) / 2, (position.top + position.bottom) / 2]);
      if (style === 'inline') {
        const matrix = await anchor.locator('.expression-plane').evaluate((element) => new DOMMatrix(getComputedStyle(element).transform).toFloat64Array());
        assert.ok(Math.abs(matrix[1]) > .0001 || Math.abs(matrix[4]) > .0001, 'Inline uses the projected plane orientation');
      }
    }
    assert.notDeepEqual(variantCenters[0], variantCenters[1], 'Floating and margin layouts have different placements');
    assert.notDeepEqual(variantCenters[0], variantCenters[2], 'Inline results sit on the other side of the code');

    // Camera motion continuously reprojects anchors. Relative layout changes are eased.
    await render({ expressionStyle: 'float', followExecution: false });
    await page.waitForTimeout(600);
    await page.evaluate(() => {
      window.anchorMotionSamples = [];
      window.sampleAnchorMotion = true;
      const sample = (time) => {
        const element = document.querySelector('.expression-card[data-presence="present"] .expression-anchor');
        if (element?.dataset.box) {
          const box = JSON.parse(element.dataset.box);
          const anchor = [Number(element.dataset.anchorX), Number(element.dataset.anchorY)];
          window.anchorMotionSamples.push({ time, anchor, offset: [(box.left + box.right) / 2 - anchor[0], (box.top + box.bottom) / 2 - anchor[1]], opacity: Number(element.style.opacity), visible: element.dataset.visible, overlap: element.dataset.glyphOverlap });
        }
        if (window.sampleAnchorMotion) requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    });
    await page.mouse.move(box.width * .52, box.height * .49);
    await page.mouse.down();
    await page.mouse.move(box.width * .59, box.height * .53, { steps: 18 });
    await page.mouse.up();
    await page.mouse.wheel(0, -90);
    await page.waitForTimeout(500);
    const samples = await page.evaluate(() => { window.sampleAnchorMotion = false; return window.anchorMotionSamples; });
    assert.ok(samples.length > 8);
    assert.ok(samples.some((sample) => Math.hypot(sample.anchor[0] - samples[0].anchor[0], sample.anchor[1] - samples[0].anchor[1]) > 8), 'Source anchors move with the actual camera');
    assert.ok(samples.every((sample) => sample.visible !== 'true' || sample.overlap === 'false'), 'Moving overlays never cover glyphs');
    for (let index = 1; index < samples.length; index++) {
      const previous = samples[index - 1], current = samples[index];
      if (current.opacity > .7 && previous.opacity > .7 && current.time - previous.time < 70) {
        assert.ok(Math.hypot(current.offset[0] - previous.offset[0], current.offset[1] - previous.offset[1]) < 40, 'Layout retargeting has no opaque frame-sized jump');
      }
    }
    await canvas.focus();
    await page.keyboard.down('Shift');
    await page.keyboard.down('ArrowRight');
    await page.waitForTimeout(2300);
    await page.keyboard.up('ArrowRight');
    await page.keyboard.up('Shift');
    await page.waitForTimeout(400);
    assert.equal(await card.locator('.expression-anchor').getAttribute('data-visible'), 'false', 'An offscreen source anchor is culled');
    await render({ followExecution: true, resetKey: 12 });
    await waitSettled();

    const exactInteger = '18446744073709551615';
    await render({ expression: { ...expression, id: 'exact-u64', operands: ['9007199254740993'], result: exactInteger }, isPlaying: true });
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').textContent(), exactInteger, 'Backend decimal strings are displayed without a lossy Number conversion');
    await render({ isPlaying: false });

    const grouped = {
      ...expression, id: 'grouped', operands: [10, 5], result: 15, label: 'add(add(1, 2), add(3, 4)) + 5', operandRanges: undefined,
      groups: [
        { id: 'inner-calls', stages: [
          { id: 'left-call', operands: [1, 2], operator: 'call', result: 3, label: 'add(1, 2)' },
          { id: 'right-call', operands: [3, 4], operator: 'call', result: 7, label: 'add(3, 4)' },
        ] },
        { id: 'outer-call', stages: [{ id: 'outer-result', operands: [3, 7], operator: 'call', result: 10, label: 'add(3, 7)' }] },
      ],
    };
    await render({ expression: grouped });
    assert.equal(await canvas.getAttribute('data-operand-guide-count'), '0', 'No underlines are inferred when ranges are absent');
    assert.equal(await card.getAttribute('data-group-id'), 'inner-calls');
    assert.equal(await card.locator('.expression-substage[data-presence="present"]').count(), 2, 'Independent calls appear together in their recorded group');
    await page.waitForFunction(() => document.querySelector('.expression-card[data-presence="present"]')?.getAttribute('data-phase') === 'merge');
    assert.deepEqual(await card.locator('.expression-stage-presence[data-presence="present"] [data-stage-phase]').evaluateAll((elements) => elements.map((element) => element.dataset.stagePhase)), ['merge', 'merge'], 'Stages within one group merge simultaneously without an invented order');
    await page.waitForFunction(() => document.querySelector('.expression-card[data-presence="present"]')?.getAttribute('data-group-id') === 'outer-call');
    assert.deepEqual(await card.locator('.expression-stage-presence[data-presence="present"] [data-stage-id]').evaluateAll((elements) => elements.map((element) => element.dataset.stageId)), ['outer-result'], 'The next recorded group follows both inner calls');
    await page.waitForFunction(() => document.querySelector('.expression-card[data-presence="present"]')?.getAttribute('data-group-id') === 'final');
    assert.equal(await card.locator('.expression-substage[data-presence="present"]').count(), 0);
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').textContent(), '15', 'The final expression uses its recorded overall result');

    await render({ expression: { ...grouped, id: 'grouped-replaced' } });
    await render({ expression: { ...expression, id: 'replacement', operandRanges: [] } });
    await page.waitForTimeout(900);
    assert.equal(await card.getAttribute('data-event-id'), 'replacement', 'Replacing a grouped event cancels all pending group transitions');
    assert.equal(await card.getAttribute('data-group-id'), 'final');
    await render({ expression: { ...grouped, id: 'grouped-autoplay' }, isPlaying: true });
    assert.equal(await card.getAttribute('data-group-id'), 'final', 'Autoplay skips intermediate groups');
    assert.equal(await card.locator('.expression-substage[data-presence="present"]').count(), 0);
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').textContent(), '15');

    const pending = { ...expression, id: 'pending-call', operator: 'call', operands: [3, 7], result: null, label: 'add(3, 7)', operandRanges: [] };
    await render({ expression: pending, isPlaying: false });
    await page.waitForTimeout(850);
    assert.equal(await card.getAttribute('data-phase'), 'pending');
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').count(), 0, 'A pending call must not invent a result');
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').count(), 2);
    assert.ok(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').first().evaluate((element) => Number(getComputedStyle(element).opacity) > .99), 'Pending arguments remain visible rather than merging into an unknown result');
    await render({ expression: { ...pending, id: 'pending-autoplay' }, isPlaying: true });
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').count(), 0);
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').count(), 0);
    assert.equal(await card.locator('.expression-pending-note').textContent(), 'вызов…');

    await render({ expression: { ...expression, id: 'fast-1', result: 99 }, isPlaying: true, stepDurationMs: 30 });
    assert.equal(await card.getAttribute('data-phase'), 'result');
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').count(), 0, 'Autoplay displays only the ready result');
    await page.evaluate((event) => {
      for (let index = 2; index <= 12; index++) window.renderSpatialTest({ expression: { ...event, id: `fast-${index}`, result: index } });
    }, expression);
    await page.waitForFunction(() => document.querySelector('.expression-card[data-presence="present"]')?.getAttribute('data-event-id') === 'fast-12');
    await page.waitForTimeout(800);
    assert.equal(await card.count(), 1);
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').textContent(), '12', 'Fast playback replaces previous animations without a queue');

    await render({ activeLine: 0 });
    assert.equal(await card.count(), 0, 'Leaving the execution view clears the displayed calculation');
    await render({ activeLine: 7 });
    assert.equal(await card.count(), 0, 'The old event must not reappear when returning to execution');
    await render({ expression: { ...expression, id: 'fresh-before-source' } });
    assert.equal(await card.count(), 1);
    const changedSource = expressionSource + '\n// source revision';
    await render({ source: changedSource });
    await page.locator('.spatial-code[data-ready="true"]').waitFor({ timeout: 30000 });
    assert.equal(await card.count(), 0, 'A source revision discards the stale calculation even after the scene reloads');
    await render({ expression: { ...expression, id: 'fresh-source' } });
    assert.equal(await card.count(), 1);

    await page.emulateMedia({ reducedMotion: 'reduce' });
    await render({ activeLine: 5, executionKey: 4, isPlaying: false, expression: { ...expression, id: 'reduced', line: 5 } });
    await page.waitForFunction(() => document.querySelector('canvas')?.dataset.activeLine === '5');
    assert.equal((await readCamera(canvas)).motion, 'still', 'Reduced motion uses an immediate stable view');
    assert.equal(await card.getAttribute('data-phase'), 'result');
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-operand').count(), 0);
    assert.equal(await card.locator('.expression-stage-presence[data-presence="present"] .expression-result').evaluate((element) => getComputedStyle(element).animationName), 'none', 'Reduced motion skips operand and result animation');
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.waitForTimeout(200);
    const resized = await canvas.boundingBox();
    assert.ok(resized.width < box.width && resized.height < box.height);
    const resizedChip = await card.locator('.expression-chip').boundingBox();
    assert.ok(resizedChip.x >= resized.x && resizedChip.x + resizedChip.width <= resized.x + resized.width && resizedChip.y >= resized.y && resizedChip.y + resizedChip.height <= resized.y + resized.height, 'The projected calculation stays inside the viewport after resizing');
    assert.deepEqual(errors, [], 'Browser should not report errors');
    console.log('Spatial checks passed: camera arrows/inertia/2-second follow, all three projected layouts, geometry collision avoidance, camera tracking without opaque jumps, offscreen culling, 520ms retained exits, exact u64 strings, observed operand guides, ordered/parallel groups, pending values, rapid playback, stale-event clearing, reduced motion, resize.');
    }
  }
} finally {
  await browser.close();
}
