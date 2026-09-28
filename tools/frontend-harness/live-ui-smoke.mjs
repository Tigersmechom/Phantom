#!/usr/bin/env node
// Execute the actual browser application against the actual HTTP server and
// GDB backend. A tiny DOM substitute avoids a display/browser dependency.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const backend = path.resolve(process.argv[2] || path.join(root, 'backend/out/linux-debug/phantom-backend'));
const workspace = await mkdtemp(path.join(tmpdir(), 'phantom-live-ui-'));
const reservation = createServer();
await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, [path.join(root, 'tools/frontend-harness/server.mjs'),
  '--backend', backend, '--workspace', workspace, '--port', String(port)], {cwd: root, stdio: ['ignore', 'pipe', 'pipe']});
let serverLog = '';
server.stdout.on('data', data => { serverLog += data; });
server.stderr.on('data', data => { serverLog += data; });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
const elements = new Map(ids.map(id => [id, {
  value: '', checked: false, textContent: '', disabled: false, readOnly: false,
  style: {}, dataset: {}, selectedOptions: [], classList: {add() {}, remove() {}},
  addEventListener(type, handler) { this[`on${type}`] = handler; },
  dispatchEvent(event) { this[`on${event.type}`]?.(event); },
}]));
const buttons = [...html.matchAll(/data-action="([^"]+)"/g)].map(match => ({
  dataset: {action: match[1]}, disabled: false,
  addEventListener(type, handler) { this[`on${type}`] = handler; },
}));
const requests = [];
const context = {
  document: {getElementById: id => elements.get(id), querySelectorAll: () => buttons},
  async fetch(url, options) {
    if (options?.body && url === '/api/request') requests.push(JSON.parse(options.body));
    return fetch(origin + url, options);
  },
  crypto: webcrypto, TextEncoder, Uint8Array, JSON, Date, console,
  setTimeout, clearTimeout, setInterval() {}, location: {reload() {}},
};
context.window = context;
let debug;
async function until(predicate, label, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await debug.refresh();
    if (predicate()) return;
    await sleep(25);
  }
  throw new Error(`${label}: ${elements.get('status').textContent}\n${JSON.stringify(debug.state())}\n${serverLog}`);
}
async function buildLaunch(source, mode) {
  elements.get('source').value = source;
  elements.get('input-mode').value = mode;
  await debug.action('build');
  assert.match(elements.get('status').textContent, /Build: успешно/);
  await debug.action('launch');
  await until(() => debug.state().phase === 'stopped', 'launch at main');
}
try {
  for (let i = 0; i < 100; ++i) {
    try { if ((await fetch(origin)).ok) break; } catch {}
    if (server.exitCode !== null) throw new Error(serverLog);
    await sleep(20);
  }
  vm.runInNewContext(app, context, {filename: 'app.js'});
  debug = context.__phantomHarnessDebug;
  await debug.refresh();
  await buildLaunch('#include <iostream>\nint main() {\n int a=0, b=0;\n std::cin >> a;\n std::cin >> b;\n std::cout << a << "+" << b << "=" << a+b << "\\n";\n}\n', 'token');
  await debug.action('continue');
  await until(() => debug.state().activeExecution?.waiting, 'first integer wait');
  const emptyCount = requests.length;
  await sleep(200);
  await debug.refresh();
  assert.equal(requests.length, emptyCount, 'empty stdin never spins execution');
  debug.setDraft('12 34 ');
  await until(() => debug.state().phase === 'terminated', 'two integer input/resume cycles');
  assert.equal(elements.get('stdout').textContent, '12+34=46\n');
  assert.deepEqual(requests.filter(x => x.command.kind === 'appendInput').map(x => x.command.text), ['12 ', '34 ']);

  await buildLaunch('#include <iostream>\n#include <string>\nint main() {\n std::string line;\n std::getline(std::cin, line);\n std::cout << "[" << line << "]";\n}\n', 'line');
  await debug.action('continue');
  await until(() => debug.state().activeExecution?.waiting, 'getline wait');
  debug.setDraft('exact  spaces');
  const unfinishedCount = requests.length;
  await debug.refresh();
  assert.equal(requests.length, unfinishedCount, 'getline draft without Enter stays local');
  debug.eof();
  await until(() => debug.state().phase === 'terminated', 'getline EOF resume');
  assert.equal(elements.get('stdout').textContent, '[exact  spaces]');
  assert.equal(requests.filter(x => x.command.kind === 'appendInput').at(-1).command.text, 'exact  spaces');
  assert.equal(requests.filter(x => x.command.kind === 'closeInput').length, 1);
  console.log('PASS live browser app → HTTP → GDB: two cin waits, exact chunks, getline draft and EOF');
} finally {
  if (server.exitCode === null) {
    server.kill('SIGTERM');
    await new Promise(resolve => server.once('close', resolve));
  }
  await rm(workspace, {recursive: true, force: true});
}
