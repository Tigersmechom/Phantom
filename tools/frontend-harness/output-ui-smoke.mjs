#!/usr/bin/env node
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([,id]) => [id, {
  value:'', textContent:'', innerHTML:'', style:{}, classList:{add(){},remove(){}},
  addEventListener(){}, checked:false, dataset:{}, selectedOptions:[],
}]));
const context = {
  document:{getElementById:id=>elements.get(id),querySelectorAll:()=>[]},
  crypto:webcrypto, TextEncoder, Uint8Array, JSON, Date, console,
  setInterval(){},setTimeout,clearTimeout,
  fetch:async()=>({ok:true,json:async()=>({events:[],nextCursor:0,connected:false,session:null})}),
};
context.window=context;
vm.runInNewContext(await readFile(new URL('./app.js',import.meta.url),'utf8'),context);
await context.__phantomHarnessDebug.refresh();
const buffer = (text, association='cout-unsynchronized', stream='cout') => ({
  available:true,source:stream==='cout'?'libstdc++-stdio_filebuf':'glibc-_IO_FILE',
  stream,association,text,pendingBytes:Buffer.byteLength(text),totalBytes:Buffer.byteLength(text),
  writeWindowCapacityBytes:8191,writeWindowRemainingBytes:8191-Buffer.byteLength(text),
  storageCapacityBytes:8192,mode:'full',flushPolicy:'buffer-full-or-explicit',
});
const show = (stdout, processInstanceId='run-1', ordinal=1, branchId='main') => context.__phantomHarnessDebug.applyObservation({
  stdout, processInstanceId,buildId:'binary',point:{branchId,eventOrdinal:ordinal},
  stop:{stopId:`stop-${ordinal}`,stateRevision:ordinal},reason:'step',stack:[],
});
const out = (text, extra={}) => ({text,totalBytes:Buffer.byteLength(text),retainedFromByte:0,truncated:false,...extra});
const pending = () => elements.get('output-pending').innerHTML;
show(out('sent\n',{buffered:buffer('one','cout-if-synchronized','stdout'),
  coutBuffered:buffer('one','cout-synchronized')}));
assert.equal((pending().match(/one/g)||[]).length,1,'synchronized aliases rendered once');
assert.match(pending(),/output-unflushed/,'pending bytes have red-background class');
show(out('sent\n',{buffered:buffer('same','cout-if-synchronized','stdout'),coutBuffered:buffer('same')}));
assert.equal((pending().match(/same/g)||[]).length,2,'independent identical buffers are not deduplicated by text');
assert.match(elements.get('output-note').textContent,/порядок.*неизвестен/);
show(out('sent\n',{coutBuffered:buffer('<img src=x onerror=alert(1)> & 😀')}));
assert.ok(!pending().includes('<img'),'inferior text must not create DOM markup');
assert.ok(pending().includes('&lt;img') && pending().includes('&amp; 😀'));
show(out('sent\n',{coutBuffered:{...buffer(''),pendingBytes:90000,textStatus:'unavailable'}}));
assert.match(pending(),/90000 байт: текст недоступен/);
show(out('sent\nmore\n',{coutBuffered:buffer('')}) ,'run-1',2);
assert.equal(pending(),'','flushed pending bytes disappear');
assert.equal(elements.get('stdout').textContent,'sent\nmore\n');
show(out('sent\n',{coutBuffered:buffer('more\n')}) ,'run-1',1);
assert.equal(elements.get('stdout').textContent,'sent\nmore\n','history selection does not erase emitted bytes');
assert.match(elements.get('output-note').textContent,/более поздней остановки/);
show(out('sent\nmore\nbranch\n',{coutBuffered:buffer('current pending')}) ,'run-1',3,'branch-1');
assert.equal(elements.get('stdout').textContent,'sent\nmore\nbranch\n');
show(out('sent\n',{coutBuffered:buffer('old')}) ,'run-1',1,'main');
assert.equal(elements.get('stdout').textContent,'sent\nmore\nbranch\n',
  'selecting a parent branch cannot erase physical output already emitted in the same process');
assert.match(pending(),/>old<\/span>/,'pending bytes follow the selected historical stop');
assert.ok(!pending().includes('current pending'),'historical pending bytes can shrink across branches');
assert.match(elements.get('output-note').textContent,/более поздней остановки/);
show(out('',{coutBuffered:buffer('new')}) ,'run-2',1);
assert.equal(elements.get('stdout').textContent,'','new process resets terminal view');
show(out('',{coutBuffered:{available:false,reason:'cout-custom-streambuf-unsupported'}}),'run-2',2);
assert.equal(pending(),'');
assert.match(elements.get('output-note').textContent,/cout-custom-streambuf-unsupported/);
console.log('PASS output UI: aliases, independent buffers, escaping, flush, historical pending across branches, process reset');
