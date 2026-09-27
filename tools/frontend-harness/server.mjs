#!/usr/bin/env node
import http from 'node:http';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import readline from 'node:readline';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const value = (name, fallback) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] ? args[i + 1] : fallback; };
const backend = value('--backend', path.resolve(here, '../../backend/out/linux-debug/phantom-backend'));
const workspace = path.resolve(value('--workspace', process.cwd()));
const port = Number(value('--port', '4177'));

let child;
let seq = 0;
let connectResult = null;
let workspaceRef = null;
let session = null;
const pending = new Map();
const events = [];
let eventCursor = 0;
const stderr = [];
let connectWaiter = null;
const maxBodyBytes = 20 * 1024 * 1024;

function hash(text) { return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex'); }
function id(prefix) { seq += 1; return `${prefix}-${Date.now().toString(36)}-${seq}`; }
function pushEvent(frame) {
  events.push({cursor: ++eventCursor, frame});
  if (events.length > 500) events.splice(0, events.length - 500);
}
function rejectPending(error) {
  for (const [requestId, entry] of pending) {
    clearTimeout(entry.timer);
    entry.reject(error);
    pending.delete(requestId);
  }
  if (connectWaiter) {
    const reject = connectWaiter.reject;
    clearTimeout(connectWaiter.timer);
    connectWaiter = null;
    reject(error);
  }
}
function waitForExit(process) {
  if (process.exitCode !== null) return Promise.resolve();
  return new Promise(resolve => process.once('close', resolve));
}
async function stopChild(reason = 'backend stopped') {
  const current = child;
  if (!current) return;
  rejectPending(new Error(reason));
  if (current.exitCode === null) current.kill('SIGTERM');
  await Promise.race([waitForExit(current), new Promise(resolve => setTimeout(resolve, 2000))]);
  if (current.exitCode === null) current.kill('SIGKILL');
  await waitForExit(current);
  if (child === current) child = null;
}
function ensureChild() {
  if (child && child.exitCode === null) return;
  child = spawn(backend, ['--stdio', '--workspace', workspace], {stdio: ['pipe', 'pipe', 'pipe']});
  const current = child;
  current.on('error', error => {
    pushEvent({kind:'harnessError', message:error.message});
    rejectPending(error);
  });
  current.on('exit', (code, signal) => {
    pushEvent({kind:'harnessExit', code, signal});
    if (child === current) {
      child = null;
      connectResult = null;
      workspaceRef = null;
      session = null;
    }
    rejectPending(new Error(`backend exited${signal ? ` with ${signal}` : ` with code ${code}`}`));
  });
  const out = readline.createInterface({input: current.stdout});
  out.on('line', line => {
    let frame;
    try { frame = JSON.parse(line); } catch { pushEvent({kind:'harnessError', message:'Backend emitted invalid JSON', line}); return; }
    if (frame.payload) pushEvent(frame);
    else if (frame.kind === 'connectResult') {
      connectResult = frame; workspaceRef = frame.workspace; session = frame.session; pushEvent(frame);
      if (connectWaiter) { const resolve = connectWaiter.resolve; clearTimeout(connectWaiter.timer); connectWaiter = null; resolve(frame); }
    }
    else if (frame.requestId && pending.has(frame.requestId)) {
      const entry = pending.get(frame.requestId);
      pending.delete(frame.requestId);
      clearTimeout(entry.timer);
      if (frame.ok && frame.result?.kind === 'launchAccepted') session = frame.result.session;
      entry.resolve(frame);
    }
    else pushEvent(frame);
  });
  const err = readline.createInterface({input: current.stderr});
  err.on('line', line => { stderr.push(line); if (stderr.length > 100) stderr.shift(); });
  current.stdin.on('error', error => rejectPending(error));
}
function connect() {
  ensureChild();
  if (connectResult) return Promise.resolve(connectResult);
  if (connectWaiter) return connectWaiter.promise;
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const timer = setTimeout(() => {
    if (connectWaiter?.promise === promise) connectWaiter = null;
    rejectPromise(new Error('connect timeout'));
  }, 5000);
  connectWaiter = {promise, resolve:resolvePromise, reject:rejectPromise, timer};
  // Prevent an unhandled rejected promise while clearing the waiter after a
  // successful or failed handshake.
  void promise.then(() => clearTimeout(timer), () => clearTimeout(timer));
  try { child.stdin.write(JSON.stringify({kind:'connect', supportedProtocolVersions:[1]}) + '\n'); }
  catch (error) { rejectPending(error); }
  return promise;
}
function request(command, expectedSession = session, expectedStop) {
  return connect().then(() => new Promise((resolve, reject) => {
    const requestId = id('request');
    const frame = {protocolVersion:1, requestId, workspace:workspaceRef, session:expectedSession, ...(expectedStop ? {expectedStop} : {}), command};
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error('request timeout')); }, 125000);
    pending.set(requestId, {timer, resolve, reject});
    try { child.stdin.write(JSON.stringify(frame) + '\n'); }
    catch (error) { clearTimeout(timer); pending.delete(requestId); reject(error); }
  }));
}
function json(res, status, body) { const data = JSON.stringify(body); res.writeHead(status, {'content-type':'application/json; charset=utf-8','content-length':Buffer.byteLength(data),'cache-control':'no-store'}); res.end(data); }
async function body(req) { let data=''; let bytes=0; for await (const chunk of req) { bytes += chunk.length; if (bytes > maxBodyBytes) throw new Error('request body exceeds 20 MiB harness limit'); data += chunk; } return data ? JSON.parse(data) : {}; }
const html = await readFile(path.join(here, 'index.html'), 'utf8');
const css = await readFile(path.join(here, 'style.css'), 'utf8');
const js = await readFile(path.join(here, 'app.js'), 'utf8');
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/') { res.writeHead(200, {'content-type':'text/html; charset=utf-8'}); return res.end(html); }
    if (req.method === 'GET' && req.url === '/style.css') { res.writeHead(200, {'content-type':'text/css; charset=utf-8'}); return res.end(css); }
    if (req.method === 'GET' && req.url === '/app.js') { res.writeHead(200, {'content-type':'text/javascript; charset=utf-8'}); return res.end(js); }
    if (req.method === 'GET' && req.url?.startsWith('/api/events')) {
      const url = new URL(req.url, 'http://127.0.0.1');
      const after = Number(url.searchParams.get('after') || 0);
      const first = events.length ? events[0].cursor : eventCursor + 1;
      const copy = events.filter(item => item.cursor > after).map(item => item.frame);
      return json(res, 200, {events:copy, nextCursor:eventCursor, gap:after < first - 1, stderr:stderr.slice(-20), connected:!!connectResult, workspace:workspaceRef, session});
    }
    if (req.method === 'POST' && req.url === '/api/connect') return json(res, 200, await connect());
    if (req.method === 'POST' && req.url === '/api/request') { const payload = await body(req); return json(res, 200, await request(payload.command, payload.session === undefined ? session : payload.session, payload.expectedStop)); }
    if (req.method === 'POST' && req.url === '/api/reset') { await stopChild('backend reset'); connectResult = null; workspaceRef = null; session = null; events.length = 0; eventCursor = 0; return json(res,200,{ok:true}); }
    json(res, 404, {error:'not found'});
  } catch (error) { json(res, 500, {ok:false,error:{message:error.message, backend, workspace, stderr:stderr.slice(-20)}}); }
});
server.listen(port, '127.0.0.1', () => console.log(`Phantom backend harness: http://127.0.0.1:${port}`));
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  await stopChild(`harness ${signal}`);
  server.close(() => process.exit(0));
}
process.on('SIGINT', () => { void shutdown('SIGINT'); });
process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
