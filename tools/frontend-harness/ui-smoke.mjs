#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

const ids = ['source', 'argv', 'input', 'environment', 'input-eof', 'theoretical-cout',
  'stdin-live', 'input-newline', 'input-status', 'build-status', 'state-status',
  'state', 'observation', 'variables', 'buffered-cout', 'buffer-status',
  'stdout', 'stdout-check', 'stderr', 'history', 'log', 'status', 'connection', 'reset'];
const elements = new Map(ids.map(id => [id, {
  id,
  value: id === 'source' ? '#include <iostream>\nint main() { std::cout << "ready\\n"; return 0; }' : id === 'buffered-cout' ? 'Ожидание runtime остановки процесса.' : '',
  textContent: '',
  checked: id === 'input-newline',
  disabled: false,
  dataset: {},
  classList: {add() {}, remove() {}},
  addEventListener(type, callback) { this[`on${type}`] = callback; },
}]));
const actions = ['build', 'launch', 'step', 'continue', 'pause', 'stop', 'state', 'history'].map(kind => ({
  dataset: {action: kind},
  disabled: false,
  addEventListener(type, callback) { this[`on${type}`] = callback; },
}));

let requestPayload;
const context = {
  document: {
    getElementById: id => elements.get(id),
    querySelectorAll: selector => selector === 'button[data-action]' ? actions : [],
  },
  fetch: async (url, options = {}) => ({
    ok: true,
    async json() {
      if (url === '/api/request') {
        requestPayload = JSON.parse(options.body);
        return {ok: true, result: {kind: 'build', success: true, artifact: {id: 'ui-smoke-artifact'}}};
      }
      return {events: [], nextCursor: 0, connected: false, session: null, stderr: []};
    },
  }),
  crypto: webcrypto,
  TextEncoder,
  Uint8Array,
  JSON,
  Date,
  console,
  setInterval() {},
  location: {reload() {}},
};
context.window = context;
vm.runInNewContext(await readFile(new URL('./app.js', import.meta.url), 'utf8'), context, {filename: 'app.js'});
await new Promise(resolve => setTimeout(resolve, 20));

if (!actions.find(button => button.dataset.action === 'step').disabled)
  throw new Error('Step must be disabled before Launch');
if (elements.get('theoretical-cout').value !== 'ready\n')
  throw new Error(`Theoretical cout preview did not initialize from source: ${elements.get('theoretical-cout').value}`);
if (!elements.get('buffered-cout').value.includes('runtime'))
  throw new Error('Runtime buffered cout field did not initialize honestly');
await actions.find(button => button.dataset.action === 'build').onclick();
const hash = requestPayload?.command?.source?.documents?.[0]?.sha256;
if (!/^[0-9a-f]{64}$/.test(hash || '')) throw new Error(`Build sent an invalid SHA-256 digest: ${hash}`);
console.log('PASS frontend app digest and pre-launch controls');
