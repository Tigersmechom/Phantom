import { chromium } from 'playwright';
import assert from 'node:assert/strict';

const browser = await chromium.launch({
  executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: true,
});
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(process.env.TEST_URL || 'http://127.0.0.1:5173/', { waitUntil: 'networkidle' });
  const scope = page.getByTestId('inspector-scope');
  const frame = number => page.getByRole('button', { name: `Кадр ${number}`, exact: true }).click();
  const names = () => scope.locator('[data-variable]').evaluateAll(nodes => nodes.map(node => node.dataset.variable));
  const value = name => scope.locator(`[data-variable="${name}"] .motion-value`).first().getAttribute('data-value');
  const contents = () => scope.locator('[data-variable]').evaluateAll(nodes => Object.fromEntries(nodes.map(node => [node.dataset.variable, [...node.querySelectorAll('.motion-value')].map(value => value.dataset.value)])));
  async function assertMain() {
    assert.equal(await scope.getAttribute('data-function'), 'main()');
    assert.equal(await page.locator('.scope-indicator').textContent(), 'main');
    assert.deepEqual(await names(), ['i', 'n', 'values', 'prefix']);
    assert.equal(await scope.locator('[data-variable-kind="argument"]').count(), 0);
  }
  async function assertAdd(a, b) {
    assert.equal(await scope.getAttribute('data-function'), 'add(a, b)');
    assert.equal(await page.locator('.scope-indicator').textContent(), 'add');
    assert.deepEqual(await names(), ['a', 'b'], 'The active frame has only its two parameters');
    assert.equal(await value('a'), String(a));
    assert.equal(await value('b'), String(b));
    assert.equal(await scope.locator('[data-variable-kind="argument"]').count(), 2);
    assert.equal(await page.locator('.variables-panel .array-section,.variables-panel .array-note,.variables-panel [data-variable="i"],.variables-panel [data-variable="n"]').count(), 0, 'Caller values must be absent from the DOM, including fading content');
    assert.doesNotMatch(await page.locator('.variables-panel').textContent(), /CALLER|вызывающий кадр|main\(\)|Σ/);
    assert.equal(await page.getByTestId('stdin-editor').inputValue(), '3  1  4  1  5  9');
    assert.equal(await page.locator('[data-input-state="consumed"]').count(), 6);
    assert.equal(await page.locator('.timeline-track button').count(), 57);
  }
  async function assertAllocationHistory() {
    for (const [name, before, allocated, count] of [['values', 2, 3, 6], ['prefix', 16, 17, 7]]) {
      for (const [number, expected] of [[before, 'ND'], [allocated, '0'], [before, 'ND'], [allocated, '0']]) {
        await frame(number);
        const cells = scope.locator(`[data-variable="${name}"] .array-cell .motion-value`);
        assert.deepEqual(await cells.evaluateAll(nodes => nodes.map(node => node.dataset.value)), Array(count).fill(expected), `${name} at frame ${number} restores every ${expected} slot`);
        assert.deepEqual(await cells.allTextContents(), Array(count).fill(expected), 'Rendered glyphs agree with the restored snapshot');
        assert.equal(await scope.locator(`[data-variable="${name}"] .array-cell .is-unavailable`).count(), expected === 'ND' ? count : 0);
      }
    }
  }

  assert.deepEqual(await names(), ['n', 'values', 'prefix']);
  await assertAllocationHistory();
  await frame(4);
  assert.deepEqual(await names(), ['n', 'value', 'values', 'prefix']);
  assert.equal(await value('value'), '0', 'The range-for reference displays the actual element before cin');
  await frame(5);
  assert.equal(await value('value'), '3');
  await frame(16);
  assert.equal(await scope.locator('[data-variable="value"]').count(), 0, 'The range-for alias leaves scope at loop end');

  const inputs = [3, 1, 4, 1, 5, 9];
  let sum = 0;
  for (let index = 0; index < inputs.length; index++) {
    const callFrame = 20 + index * 6;
    await frame(callFrame);
    await assertMain();
    const before = await contents();
    await page.keyboard.press('F10');
    await assertAdd(sum, inputs[index]);
    await page.keyboard.press('F10');
    await assertAdd(sum, inputs[index]);
    await page.keyboard.press('F10');
    await assertMain();
    assert.equal(await value('i'), String(index));
    const after = await contents();
    assert.equal(after.prefix[index + 1], String(sum + inputs[index]));
    await page.keyboard.press('Shift+F10');
    await assertAdd(sum, inputs[index]);
    await page.keyboard.press('Shift+F10');
    await assertAdd(sum, inputs[index]);
    await page.keyboard.press('Shift+F10');
    await assertMain();
    assert.deepEqual(await contents(), before, 'Backward stepping restores the same main values');
    await frame(callFrame + 3);
    assert.deepEqual(await contents(), after, 'Returning forward restores the current main snapshot');
    sum += inputs[index];
  }
  await assertAllocationHistory();
  await frame(21);
  await page.waitForTimeout(800);
  await assertAdd(0, 3);
  await page.screenshot({ path: '/private/tmp/phantom-inspector-add.png' });
  await frame(56);
  assert.equal(await scope.locator('[data-variable="i"]').count(), 0, 'Loop-local i is absent after its loop');
  assert.equal(await page.locator('.has-output').textContent(), 'sum = 23\n');
  await page.getByRole('button', { name: 'Basic', exact: true }).click();
  assert.equal(await scope.count(), 0, 'No local values appear without the demo debug session');
  assert.deepEqual(errors, []);
  console.log('PASS: current-frame-only inspector, all six add calls forward/backward, immediate caller removal, argument values, main restoration, loop scopes, ND/zero DOM allocation roundtrips and unchanged stdin/output/history.');
} finally {
  await browser.close();
}
