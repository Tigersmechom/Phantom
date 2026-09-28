import { chromium } from 'playwright';
import assert from 'node:assert/strict';

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 1000 } });
  await page.route('**/input-values-harness', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body><div id="fixture" class="app theme-noir"></div></body></html>' }));
  await page.goto(`${process.env.TEST_URL || 'http://127.0.0.1:5173'}/input-values-harness`);
  await page.evaluate(async () => {
    const reactModule = await import('/node_modules/.vite/deps/react.js'), React = reactModule.default || reactModule;
    const domModule = await import('/node_modules/.vite/deps/react-dom_client.js'), ReactDOM = domModule.default || domModule;
    const { default: InputPanel } = await import('/src/InputPanel.tsx');
    const { default: AnimatedValue } = await import('/src/AnimatedValue.tsx');
    await import('/src/styles.css'); await import('/src/inspector-motion.css');
    const { createElement: h, useState } = React;
    const initial = '  12\t-7\n\n  1000  5';
    function Fixture() {
      const [data, setData] = useState({ value: initial, trace: { revision: initial, consumedRanges: [{ start: 2, end: 4 }], activeRange: { start: 5, end: 7 }, status: 'reading' }, font: 'neon', size: 14, width: 260, valueNumber: null, scale: 1 });
      window.updateFixture = patch => setData(previous => ({ ...previous, ...patch }));
      window.fixtureData = data;
      return h('aside', { className: 'inspector', style: { display: 'block', padding: 30, width: 650, '--input-font-size': `${data.size}px`, '--debug-number-scale': data.scale } },
        h('div', { className: 'input-fixture io-content', style: { width: data.width, height: 180, padding: 0 } }, h(InputPanel, { value: data.value, onChange: value => setData(previous => ({ ...previous, value })), trace: data.trace, font: data.font })),
        h('div', { className: 'scalar-grid', style: { marginTop: 35 } },
          h('div', { className: 'scalar-card', 'data-value-cell': true }, h('div', {}, h('span', { className: 'variable-name' }, 'i'), h('span', { className: 'type-label' }, 'int')), h('strong', {}, h(AnimatedValue, { value: data.valueNumber }), h('span', { className: 'value-unit' }, '/ 6')), h('small', {}, 'текущий индекс')),
          h('div', { className: 'scalar-card', 'data-value-cell': true }, h('div', {}, h('span', { className: 'variable-name' }, 'n')), h('strong', {}, h(AnimatedValue, { value: data.valueNumber })), h('small', {}, 'длина массива'))),
        h('div', { className: 'array-cells', style: { width: 340 } }, ...Array.from({ length: 6 }, (_, index) => h('div', { className: 'array-cell', key: index, 'data-value-cell': true }, h('span', {}, index), h('strong', {}, h(AnimatedValue, { value: data.valueNumber }))))));
    }
    ReactDOM.createRoot(document.getElementById('fixture')).render(h(Fixture));
  });
  const input = page.getByLabel('Входные данные');
  await input.waitFor(); await page.evaluate(() => document.fonts.ready);
  assert.equal(await input.inputValue(), '  12\t-7\n\n  1000  5');
  assert.equal(await page.locator('[data-input-state="active"]').count(), 1);
  assert.equal(await page.locator('[data-input-state="consumed"]').count(), 1);
  async function assertInputGeometry() {
    const geometry = await page.evaluate(() => {
      const { trace } = window.fixtureData;
      const text = document.querySelector('.input-trace-mirror span').firstChild;
      const range = document.createRange(); range.setStart(text, trace.activeRange.start); range.setEnd(text, trace.activeRange.end);
      const glyphs = [...range.getClientRects()].filter(rect => rect.height && rect.bottom >= document.querySelector('.input-trace-editor').getBoundingClientRect().top && rect.top <= document.querySelector('.input-trace-editor').getBoundingClientRect().bottom);
      const fills = [...document.querySelectorAll('[data-input-state="active"]')].map(element => element.getBoundingClientRect());
      const a = getComputedStyle(document.querySelector('.input-trace-textarea')), b = getComputedStyle(document.querySelector('.input-trace-mirror'));
      return { pairs: fills.map((rect, index) => ({ fill: { left: rect.left, top: rect.top, width: rect.width }, glyph: { left: glyphs[index]?.left, top: glyphs[index]?.top, width: glyphs[index]?.width } })), count: fills.length, expected: glyphs.length, inputFont: a.fontFamily, mirrorFont: b.fontFamily, inputSize: a.fontSize, mirrorSize: b.fontSize, inputLine: a.lineHeight, mirrorLine: b.lineHeight };
    });
    assert.equal(geometry.count, geometry.expected);
    assert.equal(geometry.inputFont, geometry.mirrorFont); assert.equal(geometry.inputSize, geometry.mirrorSize); assert.equal(geometry.inputLine, geometry.mirrorLine);
    for (const { fill, glyph } of geometry.pairs) { assert.ok(Math.abs(fill.left - glyph.left + 1) < .05); assert.ok(Math.abs(fill.top - glyph.top + 1) < .05); assert.ok(Math.abs(fill.width - Math.max(3, glyph.width + 2)) < .05); }
    return geometry;
  }
  await assertInputGeometry();
  await input.evaluate(element => { element.focus(); element.setSelectionRange(2, 7); });
  assert.equal(await input.evaluate(element => element.value.slice(element.selectionStart, element.selectionEnd)), '12\t-7');
  await input.fill('edited stdin');
  await page.waitForFunction(() => !document.querySelector('[data-input-state]'));
  assert.equal(await page.getByTestId('input-panel').getAttribute('data-trace-status'), 'idle');

  const wrapped = '12 -700\n\n' + '1234567890'.repeat(12) + '\n  5';
  await page.evaluate(value => window.updateFixture({ value, trace: { revision: value, consumedRanges: [{ start: 0, end: 2 }], activeRange: { start: 3, end: value.length }, status: 'reading' }, width: 180 }), wrapped);
  await page.waitForTimeout(40);
  assert.ok((await assertInputGeometry()).count >= 4, 'Multiline/wrapped active token gets multiple measured rectangles');
  for (const font of ['neon', 'krypton', 'xcode']) {
    await page.evaluate(font => window.updateFixture({ font, size: 22, width: 240 }), font); await page.evaluate(() => document.fonts.ready); await page.waitForTimeout(25); await assertInputGeometry();
    const point = await page.evaluate(() => {
      const range = document.createRange(), text = document.querySelector('.input-trace-mirror span').firstChild;
      range.setStart(text, 32); range.collapse(true); const rect = range.getBoundingClientRect();
      return { x: rect.left + .2, y: rect.top + rect.height / 2 };
    });
    await page.mouse.click(point.x, point.y);
    assert.equal(await input.evaluate(element => element.selectionStart), 32, `Visible textarea caret must match measured overlay with ${font}`);
  }
  const multiline = Array.from({ length: 35 }, (_, index) => `  token_${index}`).join('\n');
  const start = multiline.indexOf('token_20');
  await page.evaluate(({ value, start }) => window.updateFixture({ value, trace: { revision: value, consumedRanges: [{ start: 2, end: 9 }], activeRange: { start, end: start + 8 }, status: 'reading' }, size: 14 }), { value: multiline, start });
  await input.evaluate(element => { element.scrollTop = 20 * 14 * 1.8; }); await page.waitForTimeout(30); assert.equal((await assertInputGeometry()).count, 1);
  await page.evaluate(() => { const value = window.fixtureData.value; window.updateFixture({ trace: { revision: value, consumedRanges: [], activeRange: { start: value.length, end: value.length }, status: 'waiting' } }); });
  await input.evaluate(element => { element.scrollTop = element.scrollHeight; }); await page.waitForTimeout(30); assert.equal((await assertInputGeometry()).count, 1);

  await page.evaluate(() => { const value = '  12\t-7\n\n  1000  5'; window.updateFixture({ value, trace: { revision: value, consumedRanges: [{ start: 2, end: 4 }], activeRange: { start: 5, end: 7 }, status: 'reading' } }); });

  for (const [value, scale] of [[1, 1], [9, .7], [-1000000, 1.8], [null, 1], ['-1234567890123456789012345', 1.8]]) {
    await page.evaluate(([valueNumber, scale]) => window.updateFixture({ valueNumber, scale }), [value, scale]);
    await page.waitForTimeout(25);
    const checks = await page.locator('.motion-value').evaluateAll(nodes => nodes.map(node => {
      const animation = node.getAnimations().find(animation => animation.effect.getKeyframes().some(frame => frame.transform));
      const peak = animation?.effect.getKeyframes()[1];
      if (!peak) return { value: node.dataset.value, skipped: true };
      animation.cancel(); node.style.transform = peak.transform; node.dataset.testPeak = peak.transform;
      const amount = Number(node.dataset.motionScale), rect = node.getBoundingClientRect(), style = getComputedStyle(node);
      const canvas = document.createElement('canvas'), context = canvas.getContext('2d');
      context.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`; context.letterSpacing = style.letterSpacing === 'normal' ? '0px' : style.letterSpacing;
      const metrics = context.measureText(node.dataset.value), baseline = node.querySelector('.motion-value-baseline').getBoundingClientRect().top;
      const ink = { left: Math.min(rect.left, rect.left - metrics.actualBoundingBoxLeft * amount), right: Math.max(rect.right, rect.left + metrics.actualBoundingBoxRight * amount), top: baseline - metrics.actualBoundingBoxAscent * amount, bottom: baseline + metrics.actualBoundingBoxDescent * amount };
      const strong = node.closest('strong'), strongRect = strong.getBoundingClientRect(), border = parseFloat(getComputedStyle(strong).borderTopWidth) || 0;
      const cell = node.closest('[data-value-cell]');
      const bounds = cell.classList.contains('scalar-card') ? { left: strongRect.left + 3, right: Math.min(strongRect.right - 3, strong.querySelector('.value-unit')?.getBoundingClientRect().left - 4 || Infinity), top: cell.querySelector(':scope > div').getBoundingClientRect().bottom + 3, bottom: cell.querySelector('small').getBoundingClientRect().top - 3 } : { left: strongRect.left + border + 3, right: strongRect.right - border - 3, top: strongRect.top + border + 3, bottom: strongRect.bottom - border - 3 };
      node.style.transform = '';
      return { value: node.dataset.value, scale: amount, ink, bounds };
    }));
    for (const check of checks) {
      assert.ok(!check.skipped, `Expected motion for changed value: ${JSON.stringify(check)}`);
      assert.ok(check.scale > 0 && Number.isFinite(check.scale));
      assert.ok(check.ink.left >= check.bounds.left - .3 && check.ink.right <= check.bounds.right + .3 && check.ink.top >= check.bounds.top - .3 && check.ink.bottom <= check.bounds.bottom + .3, JSON.stringify(check));
      if (value === 1 || value === 9) assert.ok(check.scale > 1.28, JSON.stringify(check));
    }
    if (value === 1) {
      await page.locator('.motion-value').evaluateAll(nodes => nodes.forEach(node => { node.style.transform = node.dataset.testPeak; }));
      await page.screenshot({ path: '/private/tmp/phantom-input-values-peak.png' });
      await page.locator('.motion-value').evaluateAll(nodes => nodes.forEach(node => { node.style.transform = ''; }));
    }
  }
  console.log('Input/value UI verified: multiline/tabs/wrap, all fonts, active+consumed geometry, edit reset, scroll/EOF waiting cursor, dynamic pop bounds for small/long/negative/ND values and font scales.');
} finally { await browser.close(); }
