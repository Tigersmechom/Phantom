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
const stderr = [];

function hash(text) { return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex'); }
function id(prefix) { seq += 1; return `${prefix}-${Date.now().toString(36)}-${seq}`; }
function pushEvent(frame) { events.push(frame); if (events.length > 500) events.splice(0, events.length - 500); }
function ensureChild() {
  if (child && child.exitCode === null) return;
  child = spawn(backend, ['--stdio', '--workspace', workspace], {stdio: ['pipe', 'pipe', 'pipe']});
  child.on('error', error => pushEvent({kind:'harnessError', message:error.message}));
  child.on('exit', (code, signal) => pushEvent({kind:'harnessExit', code, signal}));
  const out = readline.createInterface({input: child.stdout});
  out.on('line', line => {
    let frame;
    try { frame = JSON.parse(line); } catch { pushEvent({kind:'harnessError', message:'Backend emitted invalid JSON', line}); return; }
    if (frame.payload) pushEvent(frame);
    else if (frame.kind === 'connectResult') { connectResult = frame; workspaceRef = frame.workspace; session = frame.session; pushEvent(frame); }
    else if (frame.requestId && pending.has(frame.requestId)) pending.get(frame.requestId)(frame);
    else pushEvent(frame);
  });
  const err = readline.createInterface({input: child.stderr});
  err.on('line', line => { stderr.push(line); if (stderr.length > 100) stderr.shift(); });
  child.stdin.on('error', () => {});
}
function connect() {
  ensureChild();
  if (connectResult) return Promise.resolve(connectResult);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('connect timeout')), 5000);
    const old = connectResult;
    const check = () => { if (connectResult && connectResult !== old) { clearTimeout(timer); resolve(connectResult); } else setTimeout(check, 10); };
    check();
    child.stdin.write(JSON.stringify({kind:'connect', supportedProtocolVersions:[1]}) + '\n');
  });
}
function request(command, expectedSession = session, expectedStop) {
  return connect().then(() => new Promise((resolve, reject) => {
    const requestId = id('request');
    const frame = {protocolVersion:1, requestId, workspace:workspaceRef, session:expectedSession, ...(expectedStop ? {expectedStop} : {}), command};
    const timer = setTimeout(() => { pending.delete(requestId); reject(new Error('request timeout')); }, 125000);
    pending.set(requestId, response => { clearTimeout(timer); pending.delete(requestId); if (response.ok && response.result?.kind === 'launchAccepted') session = response.result.session; resolve(response); });
    child.stdin.write(JSON.stringify(frame) + '\n');
  }));
}
function json(res, status, body) { const data = JSON.stringify(body); res.writeHead(status, {'content-type':'application/json; charset=utf-8','content-length':Buffer.byteLength(data),'cache-control':'no-store'}); res.end(data); }
async function body(req) { let data=''; for await (const chunk of req) data += chunk; return data ? JSON.parse(data) : {}; }
const html = await readFile(path.join(here, 'index.html'), 'utf8');
const css = await readFile(path.join(here, 'style.css'), 'utf8');
const js = await readFile(path.join(here, 'app.js'), 'utf8');
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/') { res.writeHead(200, {'content-type':'text/html; charset=utf-8'}); return res.end(html); }
    if (req.method === 'GET' && req.url === '/style.css') { res.writeHead(200, {'content-type':'text/css; charset=utf-8'}); return res.end(css); }
    if (req.method === 'GET' && req.url === '/app.js') { res.writeHead(200, {'content-type':'text/javascript; charset=utf-8'}); return res.end(js); }
    if (req.method === 'GET' && req.url === '/api/events') { const copy = events.splice(0); return json(res, 200, {events:copy, stderr:stderr.slice(-20), connected:!!connectResult, workspace:workspaceRef, session}); }
    if (req.method === 'POST' && req.url === '/api/connect') return json(res, 200, await connect());
    if (req.method === 'POST' && req.url === '/api/request') { const payload = await body(req); return json(res, 200, await request(payload.command, payload.session === undefined ? session : payload.session, payload.expectedStop)); }
    if (req.method === 'POST' && req.url === '/api/reset') { if (child && child.exitCode === null) child.kill('SIGTERM'); child = null; connectResult = null; workspaceRef = null; session = null; events.length = 0; return json(res,200,{ok:true}); }
    json(res, 404, {error:'not found'});
  } catch (error) { json(res, 500, {ok:false,error:{message:error.message, backend, workspace, stderr:stderr.slice(-20)}}); }
});
server.listen(port, '127.0.0.1', () => console.log(`Phantom backend harness: http://127.0.0.1:${port}`));
process.on('SIGINT', () => { if (child && child.exitCode === null) child.kill('SIGTERM'); server.close(() => process.exit(0)); });
