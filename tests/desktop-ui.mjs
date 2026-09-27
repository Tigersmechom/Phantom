import {_electron as electron} from 'playwright';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,mkdir,realpath} from 'node:fs/promises';
import path from 'node:path';import os from 'node:os';
import {DEMO_SOURCE,DEFAULT_INPUT} from '../src/demo.ts';
const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'frame-desktop-ui-')));
const source='#include <iostream>\n#ifndef FRAME_VALUE\n#define FRAME_VALUE 1\n#endif\nint main(){int n=0;std::cin>>n;std::cout<<FRAME_VALUE+n<<"\\n";}\n';
await writeFile(path.join(root,'main.cpp'),source);
const env={...process.env,FRAME_DEV_URL:''};delete env.ELECTRON_RUN_AS_NODE;
const packaged=process.argv.includes('--packaged');
const profile=path.join(root,'.electron-test-profile');
let app;
try{
 app=await electron.launch({...(packaged?{executablePath:path.resolve('release/phantom-darwin-arm64/phantom.app/Contents/MacOS/phantom'),args:[`--user-data-dir=${profile}`,'--workspace',root]}:{args:[path.resolve('electron/main.cjs'),`--user-data-dir=${profile}`,'--workspace',root]}),env});
 const page=await app.firstWindow();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.locator('.app.native').waitFor();await page.getByTestId('source-editor').waitFor();await page.waitForFunction(()=>document.querySelector('.native-file-name')?.textContent==='main.cpp');
 assert.equal(await page.locator('.design-dock').count(),0);
 await page.getByLabel('Настройки типографики').click();await page.getByRole('tab',{name:'Сборка',exact:true}).click();await page.getByLabel('Флаги компиляции').fill('-std=c++20\n-g\n-O0\n-Wall\n-DFRAME_VALUE=42');await page.getByLabel('Флаги компиляции').blur();await page.locator('#build-flags-status').filter({hasText:'Сохранено'}).waitFor();assert.equal(await page.getByLabel('Каталог результата').count(),0);assert.equal(await page.locator('.config-file').count(),0);
 const config=JSON.parse(await readFile(path.join(root,'.frame/build.json'),'utf8'));assert.ok(config.flags.includes('-DFRAME_VALUE=42'));
 await page.screenshot({path:packaged?'previews/native-build-settings.png':'previews/native-build-settings-dev.png'});
 await page.getByLabel('Закрыть настройки типографики').click();await page.getByRole('button',{name:'Basic',exact:true}).click();await page.getByLabel('Входные данные').fill('5\n');await page.locator('#run-button').click();
 await page.waitForFunction(()=>document.querySelector('.has-output')?.textContent==='47\n',null,{timeout:20000});assert.match(await page.getByRole('log',{name:'Результат сборки'}).innerText(),/DFRAME_VALUE=42/);
 await page.evaluate(()=>{window.__uiData='';window.frameNative.terminal.onData(e=>window.__uiData+=e.data)});
 await page.keyboard.press('Control+Backquote');if(!(await page.getByTestId('native-terminal').isVisible()))await page.keyboard.press('Control+Backquote');
 await page.waitForFunction(()=>document.querySelector('[data-testid="native-terminal"]')?.getAttribute('data-connected')==='true');const tty=page.locator('.xterm-helper-textarea');await tty.focus();await page.keyboard.type("printf '__UI_CWD__'; pwd");await page.keyboard.press('Enter');await page.waitForFunction(root=>window.__uiData.includes('__UI_CWD__'+root),root,{timeout:10000});
 await page.keyboard.type('export FRAME_PERSIST=kept');await page.keyboard.press('Enter');await page.keyboard.press('Control+Backquote');assert.equal(await page.getByTestId('native-terminal').isVisible(),false);await page.keyboard.press('Control+Backquote');await tty.focus();await page.keyboard.type("printf '__PERSIST_%s__\\n' \"$FRAME_PERSIST\"");await page.keyboard.press('Enter');await page.waitForFunction(()=>window.__uiData.includes('__PERSIST_kept__'));
 await page.keyboard.type('sleep 20');await page.keyboard.press('Enter');await page.waitForTimeout(150);await page.keyboard.press('Control+c');await page.keyboard.type("printf '__UI_INTERRUPT_OK__\\n'");await page.keyboard.press('Enter');await page.waitForFunction(()=>window.__uiData.includes('\r\n__UI_INTERRUPT_OK__\r\n'));
 const oldId=(await page.evaluate(()=>window.frameNative.terminal.open({cols:80,rows:20}))).id;
 await page.getByRole('button',{name:'Пересоздать терминал'}).click();await page.waitForFunction(async previous=>(await window.frameNative.terminal.open({cols:80,rows:20})).id!==previous,oldId);await page.waitForFunction(()=>document.querySelector('[data-testid="native-terminal"]')?.getAttribute('data-connected')==='true');await tty.focus();await page.keyboard.type("printf '__NEW_ENV_%s__\\n' \"$FRAME_PERSIST\"");await page.keyboard.press('Enter');await page.waitForFunction(()=>window.__uiData.includes('\r\n__NEW_ENV___\r\n'));
 await page.screenshot({path:packaged?'previews/native-terminal.png':'previews/native-terminal-dev.png'});
 // Actual file save travels through renderer → preload → main process.
 await page.getByTestId('source-editor').fill(source+'// saved from FRAME\n');await page.getByLabel('Сохранить файл',{exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.unsaved-indicator'));assert.match(await readFile(path.join(root,'main.cpp'),'utf8'),/saved from FRAME/);
 if(packaged){
  await page.getByTestId('source-editor').fill(DEMO_SOURCE);await page.getByRole('button',{name:'Debug',exact:true}).click();
  await page.getByLabel('Входные данные').fill(DEFAULT_INPUT);
  await page.getByRole('button',{name:'Кадр 4',exact:true}).click();assert.equal(await page.locator('[data-input-state="active"]').count(),1);
  await page.getByRole('button',{name:'Кадр 5',exact:true}).click();assert.equal(await page.locator('[data-input-state="consumed"]').count(),1);
  if(await page.getByTestId('native-terminal').isVisible())await page.keyboard.press('Control+Backquote');
  await page.getByRole('button',{name:'3D',exact:true}).click();await page.locator('.spatial-code[data-ready="true"]').waitFor({timeout:30000});
  await page.getByRole('button',{name:'Кадр 20',exact:true}).click();
  const liveRail=page.locator('.expression-card[data-presence="present"][data-style="rail"]');
  await liveRail.locator('.rail-argument[data-operand-index="0"]').waitFor();
  await liveRail.locator('.rail-argument[data-operand-index="1"]').waitFor();
  assert.deepEqual(await liveRail.locator('.rail-argument-label').allTextContents(),['prefix[i]','values[i]']);
  assert.deepEqual(await liveRail.locator('.rail-argument .expression-operand').allTextContents(),['0','3']);
  await page.waitForFunction(()=>Array.from(document.querySelectorAll('.expression-card[data-presence="present"] .rail-operand-link')).every(link=>link.getAttribute('data-source-line')==='16'));
  const linkStyle=await liveRail.locator('.rail-operand-link').first().evaluate(el=>({width:parseFloat(getComputedStyle(el).strokeWidth),dash:getComputedStyle(el).strokeDasharray}));
  assert.ok(linkStyle.width>=2.5&&linkStyle.dash!=='none','Rail links are thick and dashed in the packaged renderer');
  await page.waitForFunction(()=>document.querySelector('canvas')?.dataset.cameraMotion==='still');
  await page.screenshot({path:'previews/native-rail-arguments.png'});
  await page.getByRole('button',{name:'Кадр 21',exact:true}).click();
  assert.deepEqual(await page.locator('.variables-panel [data-variable]').evaluateAll(nodes=>nodes.map(node=>node.getAttribute('data-variable'))),['a','b']);
  assert.equal(await page.locator('.variables-panel .array-section').count(),0,'Caller arrays leave the inspector immediately');
  await page.getByRole('button',{name:'Кадр 22',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.expression-result')?.textContent==='3');await page.waitForFunction(()=>document.querySelector('canvas')?.dataset.cameraMotion==='still');
  await page.waitForFunction(()=>{const result=document.querySelector('.expression-card[data-presence="present"] .rail-result');return result&&Number(getComputedStyle(result).opacity)>.98});
  assert.equal(await page.locator('.spatial-code__fallback').count(),0);await page.screenshot({path:'previews/phantom-native-3d.png'});
  for(const [style,label] of [['float','Над выражением'],['rail','На полях'],['inline','В плоскости']]){
   await page.getByLabel('Настройки типографики').click();await page.getByRole('tab',{name:'3D и камера',exact:true}).click();
   const option=page.getByRole('button',{name:`Результаты: ${label}`,exact:true});await option.click();assert.equal(await option.getAttribute('aria-pressed'),'true');
   await page.getByLabel('Закрыть настройки типографики').click();
   await page.locator(`.expression-card[data-presence="present"][data-style="${style}"][data-phase="result"] .expression-anchor[data-visible="true"] .expression-chip`).first().waitFor();
   await page.waitForFunction(variant=>{const result=document.querySelector(`.expression-card[data-presence="present"][data-style="${variant}"] .expression-anchor[data-visible="true"] .expression-result`);return result&&[result,result.closest('.rail-result'),result.closest('.expression-chip-motion'),result.closest('.expression-anchor')].filter(Boolean).every(node=>Number(getComputedStyle(node).opacity)>.98)},style);
   assert.equal(await page.evaluate(()=>JSON.parse(localStorage.getItem('phantom.preferences')).expressionStyle),style);
   await page.screenshot({path:`previews/native-variant-${style}.png`});
  }
  await page.getByRole('button',{name:'Код',exact:true}).click();
 }
 await app.evaluate(({BrowserWindow})=>BrowserWindow.getAllWindows()[0].setSize(900,700));
 await page.waitForFunction(()=>innerWidth===900);const toolbarEdge=await page.getByLabel('Помощь',{exact:true}).boundingBox();assert.ok(toolbarEdge.x+toolbarEdge.width<=900,'Compact native toolbar keeps all controls visible');
 // Unsaved renderer edits must reach the native close guard automatically.
 const pendingSource=source+'// saved on closing FRAME\n';await page.getByTestId('source-editor').fill(pendingSource);await page.locator('.unsaved-indicator').waitFor();
 const stillOpen=await app.evaluate(async({BrowserWindow,dialog})=>{dialog.showMessageBox=async()=>({response:2,checkboxChecked:false});BrowserWindow.getAllWindows()[0].close();await new Promise(resolve=>setTimeout(resolve,80));return BrowserWindow.getAllWindows().length});assert.equal(stillOpen,1);
 assert.deepEqual(errors,[]);
 await app.evaluate(({dialog})=>{dialog.showMessageBox=async()=>({response:0,checkboxChecked:false})});await app.close();app=null;assert.equal(await readFile(path.join(root,'main.cpp'),'utf8'),pendingSource);
 console.log('PASS:',packaged?'packaged phantom.app':'Electron renderer','build settings persisted, actual Basic compile/run, PTY input/cwd/persistence/Ctrl+C, save file and unsaved-close guard.');
}finally{if(app){await app.evaluate(({dialog})=>{dialog.showMessageBox=async()=>({response:1,checkboxChecked:false})}).catch(()=>{});await app.close()}await rm(root,{recursive:true,force:true})}
