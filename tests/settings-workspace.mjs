import { _electron as electron } from 'playwright';
import { mkdtemp, mkdir, writeFile, readFile, rm, realpath } from 'node:fs/promises';
import path from 'node:path';import os from 'node:os';import assert from 'node:assert/strict';
const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'phantom-flags-')));
const a=path.join(root,'a'),b=path.join(root,'b');await mkdir(a);await mkdir(b);
await writeFile(path.join(a,'main.cpp'),'int main(){return 0;}\n');await writeFile(path.join(b,'other.cpp'),'int main(){return 1;}\n');
const env={...process.env};delete env.ELECTRON_RUN_AS_NODE;delete env.FRAME_DEV_URL;
let app;
try {
 app=await electron.launch({args:[path.resolve('electron/main.cjs'),`--user-data-dir=${root}/profile`,'--workspace',a],env});
 const page=await app.firstWindow();await page.waitForFunction(()=>document.querySelector('.native-file-name')?.textContent==='main.cpp');
 await page.getByLabel('Настройки типографики').click();await page.getByRole('tab',{name:'Сборка',exact:true}).click();
 const flags=page.getByLabel('Флаги компиляции');await flags.fill('-std=c++20\n-g\n-DON_FIRST_PROJECT=1');
 await app.evaluate(({dialog},file)=>{dialog.showOpenDialog=async()=>({canceled:false,filePaths:[file]})},path.join(b,'other.cpp'));
 await page.keyboard.press('Meta+o');await page.waitForFunction(()=>document.querySelector('.native-file-name')?.textContent==='other.cpp');
 const first=JSON.parse(await readFile(path.join(a,'.frame/build.json'),'utf8'));const second=JSON.parse(await readFile(path.join(b,'.frame/build.json'),'utf8'));
 assert.ok(first.flags.includes('-DON_FIRST_PROJECT=1'),'Unblurred flags save in the old project before Cmd+O');assert.ok(!second.flags.includes('-DON_FIRST_PROJECT=1'),'Flags never leak into the newly opened project');
 await page.getByLabel('Настройки типографики').click();await page.getByRole('tab',{name:'Сборка',exact:true}).click();await flags.fill('-std=c++20\n-g\n-DON_SECOND_PROJECT=2');await page.keyboard.press('Meta+b');
 await page.waitForFunction(()=>document.querySelector('.build-output')?.textContent.includes('✓ Сборка завершена'),null,{timeout:20000});
 assert.match(await page.locator('.build-output').textContent(),/DON_SECOND_PROJECT=2/,'Cmd+B saves focused flags before compilation');
 assert.ok(JSON.parse(await readFile(path.join(b,'.frame/build.json'),'utf8')).flags.includes('-DON_SECOND_PROJECT=2'));
 console.log('PASS: flags flush before Cmd+O and Cmd+B; no cross-workspace leakage.');
} finally {if(app){await app.evaluate(({dialog})=>{dialog.showMessageBox=async()=>({response:1,checkboxChecked:false})}).catch(()=>{});await app.close()}await rm(root,{recursive:true,force:true})}
