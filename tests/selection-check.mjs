import { chromium } from 'playwright';
import assert from 'node:assert/strict';

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const errors = [];
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(process.env.TEST_URL || 'http://127.0.0.1:5173');
  const editor = page.getByTestId('source-editor');
  await editor.waitFor();
  const source = '// Xcode selection · café\n#include <vector>\n\nint main() {\n    std::vector<int> values = {3, 1, 4};\n\n    return values[0];\n}\n';
  const selectionStart = source.indexOf('std::vector');
  const selectionEnd = source.indexOf(' = {');
  const setSelection = async (start, end) => {
    await editor.evaluate((element, [start, end]) => { element.focus(); element.setSelectionRange(start, end); }, [start, end]);
    await page.waitForFunction(([start, end]) => {
      const layer = document.querySelector('.editor-selection-layer');
      return layer?.getAttribute('data-start') === String(start) && layer?.getAttribute('data-end') === String(end);
    }, [start, end]);
    await page.evaluate(() => new Promise(requestAnimationFrame));
  };
  const assertGlyphAlignment = async () => {
    const geometry = await page.evaluate(() => {
      const selected = [...document.querySelectorAll('.editor-selected-glyphs')];
      const rectangles = selected.flatMap(element => [...element.getClientRects()]);
      const selection = document.querySelector('.editor-selection-rect');
      const box = selection.getBoundingClientRect();
      return { selected: selected.map(element => element.textContent).join(''), left: box.left, right: box.right, glyphLeft: Math.min(...rectangles.map(rect => rect.left)), glyphRight: Math.max(...rectangles.map(rect => rect.right)), shadow: selected.map(element => getComputedStyle(element).textShadow), background: getComputedStyle(selection).backgroundColor, nativeBackground: getComputedStyle(document.querySelector('.editor-textarea'), '::selection').backgroundColor };
    });
    assert.ok(Math.abs(geometry.left - geometry.glyphLeft) < .05, JSON.stringify(geometry));
    assert.ok(Math.abs(geometry.right - geometry.glyphRight) < .05, JSON.stringify(geometry));
    assert.equal(geometry.selected, source.slice(selectionStart, selectionEnd));
    assert.ok(geometry.shadow.every(value => value === 'none'));
    assert.equal(geometry.nativeBackground, 'rgba(0, 0, 0, 0)');
    return geometry;
  };

  for (const theme of ['Obsidian', 'Porcelain']) {
    await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
    await page.getByRole('button', { name: new RegExp(theme) }).click();
    await page.getByRole('button', { name: 'Закрыть настройки типографики', exact: true }).click();
    await editor.fill(source);
    for (const font of ['neon', 'krypton', 'xcode']) {
      await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
      await page.getByLabel('Гарнитура').selectOption(font);
      await page.getByRole('button', { name: 'Закрыть настройки типографики' }).click();
      await page.evaluate(() => document.fonts.ready);
      await setSelection(selectionStart, selectionEnd);
      const geometry = await assertGlyphAlignment();
      assert.equal(geometry.background, theme === 'Obsidian' ? 'rgb(81, 91, 112)' : 'rgb(164, 205, 255)');
      await page.screenshot({ path: `/tmp/frame-selection-${theme.toLowerCase()}-${font}.png` });
      await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
      const inactive = await page.locator('.editor-selection-rect').evaluate(element => getComputedStyle(element).backgroundColor);
      assert.notEqual(inactive, geometry.background, 'Unfocused selection gets a neutral fill');
      await page.getByRole('button', { name: 'Закрыть настройки типографики' }).click();
    }
  }

  await setSelection(selectionStart, selectionStart);
  for (let index = 0; index < 11; index++) await page.keyboard.press('Shift+ArrowRight');
  assert.equal(await editor.evaluate(element => element.value.slice(element.selectionStart, element.selectionEnd)), 'std::vector');
  assert.equal(await page.locator('.editor-selected-glyphs').allTextContents().then(parts => parts.join('')), 'std::vector');

  await setSelection(selectionStart, selectionEnd);
  await page.keyboard.press('Meta+c');
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), source.slice(selectionStart, selectionEnd));
  await page.keyboard.type('auto values');
  assert.equal(await editor.inputValue(), source.slice(0, selectionStart) + 'auto values' + source.slice(selectionEnd));
  await page.waitForFunction(() => document.querySelectorAll('.editor-selection-rect').length === 0);
  assert.equal(await editor.evaluate(element => element.selectionStart === element.selectionEnd), true);

  await editor.fill(source);
  const multilineStart = source.indexOf('values =');
  const multilineEnd = source.indexOf('return') + 6;
  await setSelection(multilineStart, multilineEnd);
  const multiline = await page.locator('.editor-selection-rect').evaluateAll(elements => elements.map(element => ({ line: element.getAttribute('data-line'), x: element.getBoundingClientRect().x, y: element.getBoundingClientRect().y, right: element.getBoundingClientRect().right, height: element.getBoundingClientRect().height })));
  assert.deepEqual(multiline.map(rect => rect.line), ['5', '6', '7']);
  assert.ok(Math.abs(multiline[0].y + multiline[0].height - multiline[1].y) < .05);
  assert.ok(Math.abs(multiline[1].y + multiline[1].height - multiline[2].y) < .05);
  assert.equal(multiline[0].right, multiline[1].right, 'Selected newlines and empty lines fill through the same right edge');

  await setSelection(selectionStart, selectionStart);
  const drag = await page.evaluate(() => {
    const line = document.querySelectorAll('.editor-line-content')[4];
    const nodes = [];
    const walker = document.createTreeWalker(line, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) nodes.push(walker.currentNode);
    function point(offset) {
      for (const node of nodes) {
        if (offset <= node.textContent.length) { const range = document.createRange(); range.setStart(node, offset); range.collapse(true); const rect = range.getBoundingClientRect(); return { x: rect.left, y: rect.top + rect.height / 2 }; }
        offset -= node.textContent.length;
      }
    }
    return { start: point(4), end: point(15) };
  });
  await page.mouse.move(drag.start.x, drag.start.y);
  await page.mouse.down();
  await page.mouse.move(drag.end.x, drag.end.y, { steps: 8 });
  await page.waitForTimeout(50);
  assert.ok(await page.locator('.editor-selection-rect').count(), 'Selection paints while mouse is still down');
  await page.mouse.up();
  assert.equal(await editor.evaluate(element => element.value.slice(element.selectionStart, element.selectionEnd)), 'std::vector');

  const long = source + Array.from({ length: 50 }, (_, index) => `int item_${index} = ${index}; // ${'very long line '.repeat(14)}`).join('\n');
  await editor.fill(long);
  const longStart = long.indexOf('int item_15');
  await setSelection(longStart, longStart + 90);
  await editor.evaluate(element => { element.scrollTop = 700; element.scrollLeft = 240; });
  await page.waitForTimeout(50);
  const scrolled = await page.evaluate(() => {
    const selected = document.querySelector('.editor-selected-glyphs').getBoundingClientRect(), rect = document.querySelector('.editor-selection-rect').getBoundingClientRect();
    return { selectedX: selected.left, rectangleX: rect.left };
  });
  assert.ok(Math.abs(scrolled.selectedX - scrolled.rectangleX) < .05);
  await page.setViewportSize({ width: 1250, height: 880 });
  await page.waitForTimeout(50);
  assert.ok(await page.locator('.editor-selection-rect').count());
  await editor.fill('int new_file = 1;');
  await page.waitForFunction(() => document.querySelectorAll('.editor-selection-rect').length === 0);
  assert.deepEqual(errors, []);
  console.log('Selection verified: exact Xcode colours in 6 font/theme combinations; glyph geometry; inactive fill; keyboard/drag; copy/type; blank/newline rows; scrolling; resize; source replacement.');
} finally {
  await browser.close();
}
