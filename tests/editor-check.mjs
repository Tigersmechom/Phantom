import { chromium } from 'playwright';
import assert from 'node:assert/strict';

if (process.argv.includes('--selection')) {
  await import('./selection-check.mjs');
  process.exit(0);
}

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(process.env.TEST_URL || 'http://127.0.0.1:5173');
  await page.evaluate(() => document.fonts.ready);
  const editor = page.getByTestId('source-editor');
  await editor.waitFor();
  const originalSource = await editor.inputValue();

  await editor.fill('int main() {\nreturn 0;\n}');
  await editor.evaluate(element => { element.focus(); element.setSelectionRange(13, 13); });
  await page.keyboard.press('Tab');
  assert.equal(await editor.inputValue(), 'int main() {\n    return 0;\n}');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await editor.inputValue(), 'int main() {\nreturn 0;\n}');
  await page.keyboard.type('// edited\n');
  assert.ok((await editor.inputValue()).includes('// edited\nreturn 0;'));

  const sourceBeforeConsole = await editor.inputValue();
  await page.keyboard.press('Control+Backquote');
  await page.getByTestId('native-terminal').waitFor({ state: 'visible' });
  assert.equal(await editor.inputValue(), sourceBeforeConsole, 'Console shortcut must not insert a backtick');
  await page.keyboard.press('Control+Backquote');
  await page.getByTestId('native-terminal').waitFor({ state: 'hidden' });

  await editor.fill('one\ntwo\nthree');
  await editor.evaluate(element => { element.focus(); element.setSelectionRange(0, 8); });
  await page.keyboard.press('Tab');
  assert.equal(await editor.inputValue(), '    one\n    two\nthree', 'A selection ending at the start of a line must leave that following line unchanged');
  await page.keyboard.press('Shift+Tab');
  assert.equal(await editor.inputValue(), 'one\ntwo\nthree');

  await editor.fill(originalSource);
  await page.clock.install();
  await page.clock.pauseAt(new Date());
  const gutter = page.locator('.editor-line-number[data-line="5"]');
  await gutter.hover();
  await page.clock.runFor(999);
  assert.equal(await page.getByTestId('asm-preview').count(), 0);
  await page.clock.runFor(1);
  assert.equal(await page.getByTestId('asm-preview').count(), 1, 'ASM tooltip opens at the 1000 ms boundary');
  assert.ok((await page.getByTestId('asm-preview').textContent()).includes('не дизассемблирование'));
  await page.mouse.move(800, 500);
  assert.equal(await page.getByTestId('asm-preview').count(), 0);
  await gutter.hover();
  await page.clock.runFor(400);
  await page.mouse.move(800, 500);
  await page.clock.runFor(800);
  assert.equal(await page.getByTestId('asm-preview').count(), 0, 'Leaving a gutter line cancels the pending tooltip');
  await gutter.click();
  assert.equal(await gutter.getAttribute('aria-pressed'), 'true');
  await gutter.click();
  assert.equal(await gutter.getAttribute('aria-pressed'), 'false');
  await page.clock.resume();

  await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
  await page.getByRole('button', { name: /Porcelain/ }).click();
  await page.getByRole('button', { name: 'Закрыть настройки типографики', exact: true }).click();
  const lightAppearance = await editor.evaluate(element => ({ caret: getComputedStyle(element).caretColor, expected: getComputedStyle(document.querySelector('.app')).getPropertyValue('--text-bright').trim(), shadow: getComputedStyle(document.querySelector('.token-keyword')).textShadow }));
  assert.equal(lightAppearance.caret, 'rgb(34, 41, 33)');
  assert.ok(!lightAppearance.shadow.includes('rgba(0, 0, 0, 0.7)'), 'Light theme must have light relief instead of dark extrusion');

  const longSource = Array.from({ length: 70 }, (_, i) => `int line_${i} = ${i}; // ${'alignment '.repeat(24)}`).join('\n');
  await editor.fill(longSource);
  await editor.evaluate(element => { element.scrollTop = 137; element.scrollLeft = 290; element.dispatchEvent(new Event('scroll')); });
  await page.waitForTimeout(50);
  const alignment = await page.evaluate(() => {
    const textarea = document.querySelector('.editor-textarea');
    const highlight = document.querySelector('.editor-highlight');
    const line = document.querySelectorAll('.editor-source-line')[6];
    const gutter = document.querySelector('.editor-line-number[data-line="7"]');
    const a = getComputedStyle(textarea), b = getComputedStyle(highlight);
    return { lineY: line.getBoundingClientRect().top, gutterY: gutter.getBoundingClientRect().top, expectedY: textarea.getBoundingClientRect().top + parseFloat(a.paddingTop) + 6 * parseFloat(a.lineHeight) - textarea.scrollTop, transform: b.transform, scrollLeft: textarea.scrollLeft, scrollTop: textarea.scrollTop, textFont: a.fontFamily, syntaxFont: b.fontFamily, textLine: a.lineHeight, syntaxLine: b.lineHeight };
  });
  assert.ok(Math.abs(alignment.lineY - alignment.gutterY) < .1, JSON.stringify(alignment));
  assert.ok(Math.abs(alignment.lineY - alignment.expectedY) < .2, JSON.stringify(alignment));
  assert.equal(alignment.textFont, alignment.syntaxFont);
  assert.equal(alignment.textLine, alignment.syntaxLine);
  assert.ok(alignment.transform.includes(`-${alignment.scrollLeft}, -${alignment.scrollTop}`), JSON.stringify(alignment));
  await page.getByRole('button', { name: 'Настройки типографики', exact: true }).click();
  for (const font of ['krypton', 'xcode', 'neon']) {
    await page.getByLabel('Гарнитура').selectOption(font);
    await page.evaluate(() => document.fonts.ready);
    const metrics = await page.evaluate(() => {
      const textarea = document.querySelector('.editor-textarea'), highlight = document.querySelector('.editor-highlight');
      const a = getComputedStyle(textarea), b = getComputedStyle(highlight);
      return { textFont: a.fontFamily, syntaxFont: b.fontFamily, textSize: a.fontSize, syntaxSize: b.fontSize, textLine: a.lineHeight, syntaxLine: b.lineHeight, lineY: document.querySelectorAll('.editor-source-line')[6].getBoundingClientRect().top, gutterY: document.querySelector('.editor-line-number[data-line="7"]').getBoundingClientRect().top };
    });
    assert.equal(metrics.textFont, metrics.syntaxFont);
    assert.equal(metrics.textSize, metrics.syntaxSize);
    assert.equal(metrics.textLine, metrics.syntaxLine);
    assert.ok(Math.abs(metrics.lineY - metrics.gutterY) < .1);
    assert.equal(await editor.inputValue(), longSource, 'Changing typography preserves the source');
  }
  console.log('Editor UI verified: typing, indentation, Ctrl+`, tooltip 1000ms/cancellation, breakpoints, light caret/relief, scroll alignment.');
} finally {
  await browser.close();
}
