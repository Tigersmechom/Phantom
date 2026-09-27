import { _electron as electron } from 'playwright';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
const root = await mkdtemp(path.join(os.tmpdir(), 'frame-electron-'));
let app;
try {
  await writeFile(path.join(root, 'main.cpp'), '#include <iostream>\nint main(){int n;std::cin>>n;std::cout<<n+1<<"\\n";}\n');
  const env = { ...process.env, FRAME_DEV_URL: '' }; delete env.ELECTRON_RUN_AS_NODE;
  app = await electron.launch({ args: [path.resolve('electron/main.cjs'), '--workspace', root, `--user-data-dir=${path.join(root, '.electron-test-profile')}`], env });
  const page = await app.firstWindow();
  await page.waitForFunction(() => Boolean(window.frameNative));
  const secure = await page.evaluate(() => ({ node: typeof window.require, bridge: Boolean(window.frameNative) }));
  assert.deepEqual(secure, { node: 'undefined', bridge: true });
  const workspace = await page.evaluate(() => window.frameNative.getWorkspace());
  assert.equal(workspace.document.name, 'main.cpp');
  await page.evaluate(() => {
    window.__terminalData = '';
    window.frameNative.terminal.onData(event => { window.__terminalData += event.data; });
  });
  let session = await page.evaluate(() => window.frameNative.terminal.open({ cols: 100, rows: 20 }));
  await page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: "printf '__FRAME_PWD__'; pwd\r" }), session);
  await page.waitForFunction(expected => window.__terminalData.includes('__FRAME_PWD__' + expected), workspace.root, { timeout: 10000 });
  const repeated = await page.evaluate(() => window.frameNative.terminal.open({ cols: 110, rows: 22 }));
  assert.equal(repeated.id, session.id, 'reopening keeps the actual shell alive');
  assert.ok(repeated.history.includes('__FRAME_PWD__'));
  await page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: 'sleep 10\r' }), session);
  await new Promise(resolve => setTimeout(resolve, 200));
  await page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: '\x03' }), session);
  await page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: "printf '__FRAME_INTERRUPT_OK__\\n'\r" }), session);
  await page.waitForFunction(() => window.__terminalData.includes('\r\n__FRAME_INTERRUPT_OK__\r\n'), null, { timeout: 10000 });
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const terminalChildPath = path.join(root, 'terminal-child.pid'), terminalShellPath = path.join(root, 'terminal-shell.pid');
  const childScript = path.join(root, 'terminal-child.zsh');
  await writeFile(childScript, `trap '' HUP TERM\nprint -r -- $$ > ${quote(terminalChildPath)}\nwhile true; do /bin/sleep 10; done\n`);
  await page.evaluate(({ id, data }) => window.frameNative.terminal.write({ id, data }), { id: session.id, data: `export PHANTOM_RESTART_SENTINEL=old; cd /; print -r -- $$ > ${quote(terminalShellPath)}; /bin/zsh ${quote(childScript)} &\r` });
  let terminalChildPid, terminalShellPid;
  for (let i = 0; i < 50; i++) {
    try { terminalChildPid = Number(await readFile(terminalChildPath, 'utf8')); terminalShellPid = Number(await readFile(terminalShellPath, 'utf8')); if (terminalChildPid && terminalShellPid) break; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(terminalChildPid && terminalShellPid, 'Old shell and stubborn background child started');
  const previousSession = session;
  session = await page.evaluate(() => window.frameNative.terminal.restart({ cols: 100, rows: 20 }));
  assert.notEqual(session.id, previousSession.id, 'Restart returns a fresh shell identity');
  assert.equal(session.cwd, workspace.root, 'Restart restores project cwd');
  assert.equal(session.history, '', 'Restart starts without old output');
  assert.equal(session.sequence, 0);
  await assert.rejects(page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: 'pwd\r' }), previousSession), /уже завершена/);
  await page.evaluate(() => { window.__terminalData = ''; });
  await page.evaluate(({ id }) => window.frameNative.terminal.write({ id, data: "printf '__PHANTOM_ENV__%s\\n' \"${PHANTOM_RESTART_SENTINEL-unset}\"; printf '__PHANTOM_CWD__'; pwd\r" }), session);
  await page.waitForFunction(expected => window.__terminalData.includes('\r\n__PHANTOM_ENV__unset\r\n') && window.__terminalData.includes('__PHANTOM_CWD__' + expected), workspace.root, { timeout: 10000 });
  for (const pid of [terminalShellPid, terminalChildPid]) {
    for (let i = 0; i < 30; i++) { try { process.kill(pid, 0); } catch { break; } await new Promise(resolve => setTimeout(resolve, 50)); }
    assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH', 'Restart cleans the previous shell and its stubborn background job');
  }
  const build = await page.evaluate(content => window.frameNative.compile({ content, architecture: 'arm64' }), workspace.document.content);
  assert.equal(build.success, true, build.stderr);
  const output = await page.evaluate(() => window.frameNative.execute({ stdin: '41\n' }));
  assert.equal(output.stdout, '42\n');
  assert.equal(output.exitCode, 0);
  const stubborn = '#include <csignal>\n#include <fstream>\n#include <unistd.h>\nint main(){signal(SIGTERM,SIG_IGN); std::ofstream("running.pid") << getpid(); for(;;) pause();}\n';
  assert.equal((await page.evaluate(content => window.frameNative.compile({ content, architecture: 'arm64' }), stubborn)).success, true);
  await page.evaluate(() => { window.__running = window.frameNative.execute({ stdin: '' }).catch(() => {}); });
  let childPid;
  for (let i = 0; i < 50; i++) {
    try { childPid = Number(await readFile(path.join(root, 'running.pid'), 'utf8')); if (childPid) break; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(childPid, 'Native executable started');
  const unsaved = '// Saved by close guard\n' + stubborn;
  await page.evaluate(content => window.frameNative.updateDocumentState({ dirty: true, content }), unsaved);
  const stillOpen = await app.evaluate(async ({ BrowserWindow, dialog }) => {
    dialog.showMessageBox = async () => ({ response: 2, checkboxChecked: false });
    BrowserWindow.getAllWindows()[0].close();
    await new Promise(resolve => setTimeout(resolve, 50));
    return BrowserWindow.getAllWindows().length;
  });
  assert.equal(stillOpen, 1, 'Cancel refuses window close');
  assert.doesNotThrow(() => process.kill(childPid, 0), 'Cancel leaves running program alive');
  assert.equal((await page.evaluate(() => window.frameNative.terminal.open({ cols: 100, rows: 20 }))).id, session.id, 'Cancel retains terminal');
  await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 0, checkboxChecked: false }); });
  await app.close(); app = null;
  assert.equal(await readFile(path.join(root, 'main.cpp'), 'utf8'), unsaved, 'Save persists latest renderer content before quit');
  assert.throws(() => process.kill(childPid, 0), error => error.code === 'ESRCH', 'App quit cleans even a process that ignores SIGTERM');
  console.log('Native phantom: isolated bridge, workspace cwd, persistent PTY, clean restart and job cleanup, Ctrl+C, real compile+stdin run, Cancel/Save close guard, quit cleanup passed.');
} finally {
  if (app) { await app.evaluate(({ dialog }) => { dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false }); }).catch(() => {}); await app.close(); }
  await rm(root, { recursive: true, force: true });
}
