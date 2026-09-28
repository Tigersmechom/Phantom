#!/usr/bin/env node
/*
 * Browser-free contract test for app.js.  It exercises the hard part of the
 * harness: two input waits, response/event ordering, an unfinished final
 * token, duplicate-safe append retries, and EOF.  Keeping it in a VM makes
 * this test run in the repository's minimal Node environment.
 */
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';

const ids = ['source','argv','input','environment','input-eof','sample-program',
  'stdin-live','input-status','build-status','state-status','state','observation',
  'variables','buffered-cout','buffer-status','buffer-metrics','stdout','stdout-check',
  'stderr','history','log','status','connection','reset','input-badge','input-ranges',
  'input-locked','input-mode','input-meter-exposed','input-meter-consumed',
  'commit-token','commit-line','close-input'];
const elements = new Map(ids.map(id => [id, {
  id, value: id === 'source' ? '#include <iostream>\nint main(){int n; std::cin >> n; std::cout << n;}' : '',
  textContent:'', checked:false, disabled:false, style:{}, dataset:{}, selectedOptions:[],
  classList:{add(){},remove(){}},
  addEventListener(type, callback){ this[`on${type}`] = callback; },
  dispatchEvent(event){ this[`on${event.type}`]?.(event); },
}]));
const buttons = ['build','launch','step','continue','pause','stop','state','history']
  .map(kind => ({dataset:{action:kind},disabled:false,addEventListener(type,cb){this[`on${type}`]=cb;}}));
const session = {id:'session-test',generation:1};
const events = [];
const requests = [];
let stepCount = 0;
let requestSequence = 0;
let lastFakeEventSequence = 0;
let forceNextWait = false;
let executionErrorBudget = 0;
let failedExecutionAttempts = 0;
let failNextCloseInput = false;
let resolveStateReply;
let holdStateReply = false;
const stop = ordinal => ({stateRevision:ordinal,stopId:`stop-${ordinal}`});
const input = (status='idle', deliveredBytes=0, eof='open') => ({
  status, eof, tracking:'transport-only', deliveredBytes,
  submitted:{id:'input-1',text:'',encoding:'utf-8',closeAfterWrite:false},
});
function frame(sequence, payload) { return {session,sequence,payload}; }
function waitEvents(ordinal, requestId) {
  const s = stop(ordinal);
  const sequence = Math.max(lastFakeEventSequence + 1, ordinal * 3 - 2);
  lastFakeEventSequence = sequence + 2;
  events.push(frame(sequence, {kind:'observation', observation:{
    id:`observation-${ordinal}`, reason:'input-wait', point:{branchId:'main',eventOrdinal:ordinal},
    stop:s, input:input('waiting', ordinal === 2 ? 3 : 0), stdout:{text:'',totalBytes:0},
    stderr:{text:'',totalBytes:0}, stack:[],
  }}));
  events.push(frame(sequence + 1, {kind:'state', state:{phase:'waitingForInput',
    live:{point:{branchId:'main',eventOrdinal:ordinal},stop:s}}}));
  // commandFinished intentionally follows observation/state.  This is the
  // normal server order; the VM test below also injects a duplicate frame.
  events.push(frame(sequence + 2, {kind:'commandFinished',requestId, outcome:'waiting',
    error:{code:'INPUT_WAIT',message:'program is waiting for stdin',retryable:true}}));
}
const context = {
  document:{getElementById:id=>elements.get(id),querySelectorAll:selector=>selector==='button[data-action]'?buttons:[]},
  fetch: async (url, options={}) => {
    if (url.startsWith('/api/events')) {
      const next = events.splice(0);
      return {ok:true,json:async()=>({events:next,nextCursor:1000,connected:true,session})};
    }
    if (url === '/api/request') {
      const body = JSON.parse(options.body); const command = body.command; requests.push(body);
      const requestId = `request-${++requestSequence}`;
      if (command.kind === 'build') return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'build',success:true,artifact:{id:'artifact-test'}}})};
      if (command.kind === 'launch') return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'launchAccepted',session}})};
      if (command.kind === 'appendInput') {
        // The first append gets a transient transport failure. app.js must
        // retry with the exact same id and text, never minting a new revision.
        const matching = requests.filter(x=>x.command.kind==='appendInput' && x.command.id===command.id);
        if (matching.length === 1) return {ok:false,status:503,json:async()=>({ok:false,error:{code:'TEMPORARY',message:'network timeout',retryable:true}})};
        return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'input',input:input('idle',command.text.length)}})};
      }
      if (command.kind === 'closeInput') {
        if (failNextCloseInput) {
          failNextCloseInput = false;
          return {ok:false,status:503,json:async()=>({ok:false,error:{code:'TEMPORARY',message:'EOF network timeout',retryable:true}})};
        }
        return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'input',input:input('complete',3,'observed')}})};
      }
      if (command.kind === 'getState' && holdStateReply) return await new Promise(resolve => { resolveStateReply = resolve; });
      if (command.kind === 'step' || command.kind === 'continue') {
        if (executionErrorBudget > 0) {
          executionErrorBudget -= 1;
          failedExecutionAttempts += 1;
          return {ok:false,status:409,json:async()=>({ok:false,error:{code:'STALE_CONTEXT',message:'expectedStop is no longer current',retryable:false}})};
        }
        stepCount += 1;
        if (stepCount <= 2 || forceNextWait) {
          forceNextWait = false;
          waitEvents(stepCount + 1, requestId);
        } else {
          lastFakeEventSequence = Math.max(lastFakeEventSequence + 1, 100 + stepCount);
          events.push(frame(lastFakeEventSequence, {kind:'commandFinished',requestId,outcome:'completed'}));
        }
        return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'accepted'}})};
      }
      return {ok:true,json:async()=>({ok:true,requestId,result:{kind:'accepted'}})};
    }
    return {ok:true,json:async()=>({events:[],nextCursor:0,connected:true,session})};
  },
  crypto:webcrypto, TextEncoder, Uint8Array, JSON, Date, console,
  setInterval(){}, setTimeout, clearTimeout, location:{reload(){throw new Error('unexpected reload');}},
};
context.window = context;
vm.runInNewContext(await readFile(new URL('./app.js', import.meta.url),'utf8'), context,{filename:'app.js'});
const debug = context.__phantomHarnessDebug;
assert.ok(debug, 'debug seam is present for VM checks');

await buttons.find(x=>x.dataset.action==='build').onclick();
await buttons.find(x=>x.dataset.action==='launch').onclick();
debug.applyEvent(frame(1,{kind:'observation',observation:{reason:'entry',point:{branchId:'main',eventOrdinal:1},stop:stop(1),input:input(),stdout:{text:'',totalBytes:0},stderr:{text:'',totalBytes:0},stack:[]}}));
debug.applyEvent(frame(2,{kind:'state',state:{phase:'stopped',live:{point:{branchId:'main',eventOrdinal:1},stop:stop(1)}}}));
debug.setDraft('12 34');
// Simulate a commandFinished frame overtaking the HTTP accepted response.
// The request id is deterministic in this fake transport (build=1,
// launch=2, step=3); app.js must retain it until the accepted response binds
// the execution to that already-finished command.
debug.finishPending({requestId:'request-3',outcome:'waiting',error:{code:'INPUT_WAIT',message:'stdin',retryable:true}});
await buttons.find(x=>x.dataset.action==='step').onclick();
// Editing while the request is in flight must not erase the user's new draft
// when the immutable prefix eventually succeeds.
await new Promise(resolve=>setTimeout(() => { debug.setDraft('edited_pending'); resolve(); }, 25));
assert.equal(buttons.find(x=>x.dataset.action==='step').disabled, true, 'Step stays disabled during an input retry');
await debug.action('step');
assert.equal(stepCount,1, 'manual Step cannot race an in-flight append');
// Poll the scheduled wait and allow the append/retry/resume chain to settle.
await new Promise(resolve=>setTimeout(resolve,500));
let state = debug.state();
assert.equal(state.ledger,'12 ', 'only the confirmed first token was exposed');
assert.equal(state.draft,'edited_pending', 'edits during append remain a local draft');
assert.equal(stepCount,2, 'one wait caused exactly one automatic resume');
const appends = requests.filter(x=>x.command.kind==='appendInput');
assert.equal(appends.length,2, 'transient append failure retried once');
assert.equal(appends[0].command.id,appends[1].command.id, 'retry keeps the same input revision id');
assert.equal(appends[0].command.text,appends[1].command.text, 'retry keeps the same immutable bytes');
assert.ok(requests.filter(x=>x.command.kind==='step').every(x=>x.command.stepKind==='over'));

// Confirm the second token, then explicitly finish stdin. No empty append is
// allowed between the token and closeInput.
debug.setDraft('34');
await new Promise(resolve=>setTimeout(resolve,30));
assert.equal(stepCount,2,'empty/unconfirmed waits never trigger another resume');
debug.eof();
await new Promise(resolve=>setTimeout(resolve,300));
const eofRequests = requests.filter(x=>x.command.kind==='closeInput');
assert.equal(eofRequests.length,1,'EOF is sent once');
assert.equal(requests.filter(x=>x.command.kind==='appendInput').at(-1).command.text,'34','EOF flushes exact remaining text');
assert.equal(stepCount,3,'a second wait resumes after EOF without a sticky resumed flag');
assert.equal(requests.some(x=>x.command.kind==='appendInput' && x.command.text===''), false, 'no empty stdin append');

// Reload/Get state has a known stopped checkpoint but no owned execution to
// resume. Manual commit must work and must not invent an automatic Continue.
const checkpoint = {
  kind:'state', throughSequence:1000,
  state:{phase:'waitingForInput',live:{point:{branchId:'main',eventOrdinal:9},stop:stop(9)}},
  observation:{reason:'input-wait',point:{branchId:'main',eventOrdinal:9},stop:stop(9),
    input:input('waiting'),stdout:{text:'',totalBytes:0},stderr:{text:'',totalBytes:0},stack:[]},
};
lastFakeEventSequence = checkpoint.throughSequence;
debug.applyResult({result:checkpoint});
debug.applyEvent(frame(999,{kind:'state',state:{phase:'terminated'}}));
assert.equal(debug.state().phase,'waitingForInput','queued old events cannot overwrite an authoritative Get state');
debug.applyResult({result:{...checkpoint,observation:{...checkpoint.observation,
  stdout:{text:'',totalBytes:0,buffered:{available:true,pendingBytes:9,text:'',textStatus:'unavailable'}}}}});
assert.match(elements.get('buffered-cout').textContent,/9 байт; текст недоступен/,'nonempty unreadable buffer is not rendered as empty');
debug.applyResult({result:{kind:'input',input:{...input('waiting',4),
  revision:{id:'unicode-revision',parentId:null,text:'😀ab'},exposedRanges:[{start:0,end:2}]}}});
assert.equal(elements.get('input-meter-exposed').style.width,'50%','exposed meter compares UTF-16 ranges with UTF-16 revision length');
assert.equal(elements.get('input-locked').value,'😀','authoritative revision restores exactly the exposed journal after reload');
debug.applyResult({result:{kind:'input',input:{...input('complete',4,'requested'),
  revision:{id:'unicode-revision',parentId:null,text:'😀ab'},exposedRanges:[{start:0,end:2}]}}});
debug.applyResult({result:checkpoint});
assert.equal(elements.get('input-locked').value,'😀','same-stop immutable observation cannot roll back acknowledged input');
assert.match(elements.get('input-ranges').textContent,/EOF: requested/,'same-stop Get state cannot reopen acknowledged EOF');
debug.applyResult({result:{kind:'input',input:input('waiting',4)}});
assert.equal(elements.get('input-meter-exposed').style.width,'0%','transport bytes do not stand in for missing exposed ranges');
assert.equal(debug.state().activeExecution,null, 'recovered checkpoint has no owned execution');
const beforeManual = stepCount;
elements.get('input-mode').value = 'manual';
debug.setDraft('70 ');
await debug.commitToken();
await new Promise(resolve=>setTimeout(resolve,220));
assert.equal(requests.filter(x=>x.command.kind==='appendInput').at(-1).command.text,'70 ', 'manual append works after Get state');
assert.equal(debug.state().draft,'', 'successful manual append consumes its draft prefix');
assert.equal(stepCount,beforeManual,'manual append after reload does not resume unknown execution');

await debug.action('pause');
debug.finishPending({requestId:`request-${requestSequence}`,outcome:'completed'});
assert.equal(debug.state().inputWait,true,'Pause at input wait preserves the authoritative wait');
assert.equal(debug.state().autoResumeBlocked,true,'Pause only blocks automatic continuation');
debug.setDraft('tail without delimiter');
debug.eof();
await new Promise(resolve=>setTimeout(resolve,220));
assert.equal(requests.filter(x=>x.command.kind==='appendInput').at(-1).command.text,'tail without delimiter','manual EOF flushes exact draft after Pause');
assert.equal(requests.filter(x=>x.command.kind==='closeInput').length,2,'manual EOF closes stdin after reload/Pause');
assert.equal(stepCount,beforeManual,'manual EOF does not auto resume after Pause');

// Execution requests are not idempotent input chunks. A rejected automatic
// resume must stop the pump, rather than repeatedly executing stale state.
debug.applyResult({result:{...checkpoint,throughSequence:lastFakeEventSequence}});
forceNextWait = true;
await debug.action('step');
executionErrorBudget = 100;
debug.setDraft('99 ');
await debug.commitToken();
await new Promise(resolve=>setTimeout(resolve,250));
assert.equal(failedExecutionAttempts,1,'failed automatic resume is attempted only once');
assert.equal(debug.state().autoResumeBlocked,true,'failed automatic resume requires an explicit action');
assert.equal(debug.state().ledger.endsWith('99 '),true,'confirmed input remains committed after resume failure');
executionErrorBudget = 0;

// EOF is part of the requested input transaction. If its response fails after
// the last chunk was delivered, do not resume with an unexpectedly open pipe.
debug.applyResult({result:{...checkpoint,throughSequence:lastFakeEventSequence}});
forceNextWait = true;
await debug.action('step');
const beforeFailedEof = stepCount;
const eofCountBeforeFailure = requests.filter(x=>x.command.kind==='closeInput').length;
debug.setDraft('123');
failNextCloseInput = true;
debug.eof();
await new Promise(resolve=>setTimeout(resolve,250));
assert.equal(stepCount,beforeFailedEof,'failed EOF never resumes an execution after a successful append');
assert.equal(requests.filter(x=>x.command.kind==='closeInput').length,eofCountBeforeFailure + 1,'failed EOF does not retry itself');
assert.equal(debug.state().autoResumeBlocked,true,'failed EOF blocks automatic continuation');
debug.eof();
await new Promise(resolve=>setTimeout(resolve,30));
assert.equal(requests.filter(x=>x.command.kind==='closeInput').length,eofCountBeforeFailure + 2,'EOF can be retried explicitly');
assert.equal(stepCount,beforeFailedEof,'retrying EOF still requires explicit execution after the failure');

// A reset during an HTTP request invalidates its response even when the
// response arrives after the reset endpoint succeeded.
holdStateReply = true;
const oldEpoch = debug.state().epoch;
const staleRequest = debug.action('state');
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(typeof resolveStateReply,'function');
await elements.get('reset').onclick();
const beforeLateResponse = JSON.stringify(debug.state().stop);
resolveStateReply({ok:true,json:async()=>({ok:true,result:{...checkpoint,
  state:{phase:'waitingForInput',live:{point:{branchId:'main',eventOrdinal:99},stop:stop(99)}}}})});
await staleRequest;
assert.ok(debug.state().epoch > oldEpoch,'reset advances the client epoch');
assert.equal(JSON.stringify(debug.state().stop),beforeLateResponse,'late Get state response cannot restore an old checkpoint after reset');

console.log('PASS interactive UI: waits, retry identity, races, reload, Pause, resume/EOF failures, stale reset response');
