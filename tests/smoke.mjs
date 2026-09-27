import { chromium } from 'playwright';
import assert from 'node:assert/strict';
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5173/',{waitUntil:'networkidle'});await page.evaluate(()=>document.fonts.ready);
 assert.equal(await page.locator('.design-dock').count(),0,'Bottom design strip removed');
 await page.keyboard.press('Control+Backquote');assert.equal(await page.getByTestId('native-terminal').isVisible(),true);assert.match(await page.getByTestId('native-terminal').innerText(),/настольном приложении/);await page.keyboard.press('Control+Backquote');assert.equal(await page.getByTestId('native-terminal').isVisible(),false);
 const sep=page.getByRole('separator',{name:'Ширина переменных'});const before=await page.locator('.inspector').boundingBox();const sb=await sep.boundingBox();await page.mouse.move(sb.x+2,sb.y+100);await page.mouse.down();await page.mouse.move(sb.x-60,sb.y+100,{steps:8});await page.mouse.up();assert.ok((await page.locator('.inspector').boundingBox()).width>before.width+40);
 for(const name of ['Высота переменных','Ширина ввода и вывода']){const s=page.getByRole('separator',{name});const old=Number(await s.getAttribute('aria-valuenow'));await s.focus();await page.keyboard.press('ArrowRight');assert.equal(Number(await s.getAttribute('aria-valuenow')),old+2)}
 await page.getByRole('button',{name:'Кадр 22',exact:true}).click();assert.equal(await page.locator('.editor-line-number.is-active').getAttribute('data-line'),'5');
 await page.getByRole('button',{name:'Кадр 23',exact:true}).click();assert.equal(await page.locator('.editor-line-number.is-active').getAttribute('data-line'),'16');
 await page.getByLabel('Входные данные').fill('1 2');await page.locator('#run-button').click();assert.match(await page.getByRole('status').innerText(),/ровно 6/);
 await page.getByLabel('Входные данные').fill('1 2 3 4 5 6');await page.locator('#run-button').click();await page.locator('#run-button').click();await page.getByRole('button',{name:'Кадр 57',exact:true}).click();assert.equal(await page.locator('.has-output').innerText(),'sum = 21\n');
 const completedSource=await page.getByTestId('source-editor').inputValue();await page.getByTestId('source-editor').fill(completedSource+'\n// edited');assert.equal(await page.locator('.has-output').count(),0,'Editing clears old demo output');
 await page.getByLabel('Настройки типографики').click();await page.getByRole('button',{name:/Porcelain/}).click();assert.equal(await page.locator('.theme-porcelain').count(),1);
 await page.getByRole('tab',{name:'3D и камера',exact:true}).click();await page.getByLabel('Глубина 3D').fill('0.9');await page.getByLabel('Свет 3D').fill('5');await page.getByRole('switch',{name:'Каркас букв'}).click();
 await page.getByRole('tab',{name:'Сборка',exact:true}).click();assert.ok(await page.getByLabel('Флаги компиляции').inputValue());assert.equal(await page.getByLabel('Флаги компиляции').isDisabled(),true,'No pretend filesystem writes in browser');assert.equal(await page.getByRole('button',{name:'Сохранить build.json'}).count(),0);await page.getByLabel('Закрыть настройки типографики').click();
 await page.reload();assert.equal(await page.locator('.theme-porcelain').count(),1);await page.getByLabel('Настройки типографики').click();await page.getByRole('tab',{name:'3D и камера',exact:true}).click();assert.equal(await page.getByLabel('Глубина 3D').inputValue(),'0.9');await page.getByLabel('Закрыть настройки типографики').click();
 await page.getByRole('button',{name:'Basic',exact:true}).click();assert.equal(await page.locator('.editor-active-line').count(),0);await page.getByLabel('Архитектура').selectOption('x86_64');
 await page.setViewportSize({width:1024,height:768});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth===innerWidth));await page.screenshot({path:'previews/current-browser.png'});
 assert.deepEqual(errors,[]);console.log('PASS: application layout, native terminal fallback, resize, function-call trace, settings relocation/persistence and build form.');
}finally{await browser.close()}
