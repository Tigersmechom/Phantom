const $ = id => document.getElementById(id);

let artifact = null;
let session = null;
let stop = null;
let phase = null;
let busy = false;
let log = [];
let eventCursor = 0;
let refreshing = false;
let actualStdout = '';
const pendingRequests = new Map();
const failedCommands = new Set();

const pretty = value => JSON.stringify(value, null, 2);

function addLog(direction, value) {
  log.push(`${new Date().toLocaleTimeString()} ${direction}\n${pretty(value)}`);
  if (log.length > 80) log.shift();
  $('log').textContent = log.join('\n\n');
}

async function post(url, payload = {}) {
  addLog('→', {endpoint: url, payload});
  const response = await fetch(url, {
    method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(payload),
  });
  const value = await response.json();
  addLog('←', value);
  if (!response.ok || value.ok === false) throw new Error(value.error?.message || `HTTP ${response.status}`);
  return value;
}

function parseLines(text) { return text ? text.replace(/\r\n/g, '\n').split('\n') : []; }
function commonSource(text, hash) {
  return {id: 'source-bundle-1', documents: [{documentId: 'main.cpp', revisionId: 'source-revision-1', path: 'main.cpp', text, sha256: hash}]};
}
function theoreticalCoutPreview(source) {
  const statements = [...source.matchAll(/\b(?:std::)?cout\b\s*<<([\s\S]*?);/g)];
  if (!statements.length) return 'В исходнике std::cout не найден.';
  let output = '';
  let unknown = false;
  for (const statement of statements) {
    for (const token of statement[1].split('<<').map(value => value.trim()).filter(Boolean)) {
      if (token === 'std::endl' || token === 'endl') { output += '\n'; continue; }
      if (token === 'std::flush' || token === 'flush' || token === 'std::ends' || token === 'ends') continue;
      const literal = token.match(/^"((?:\\.|[^"\\])*)"/);
      if (!literal) { unknown = true; continue; }
      try { output += JSON.parse(`"${literal[1]}"`); }
      catch { unknown = true; }
    }
  }
  if (unknown) output += `${output ? '\n' : ''}[динамическая часть не вычисляется]`;
  return output || '[cout найден, но его значение не удалось вывести эвристически]';
}
async function digest(text) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function environment() {
  const result = {};
  for (const line of parseLines($('environment').value)) {
    if (!line) continue;
    const separator = line.indexOf('=');
    if (separator > 0) result[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return result;
}

function updateOutputCheck() {
  const check = $('stdout-check');
  check.textContent = actualStdout
    ? 'Фактический сброшенный stdout отображён ниже.'
    : 'Пока нет сброшенных байтов stdout; это не доказывает, что cout ничего не записал.';
  check.className = actualStdout ? 'check match' : 'check pending';
}
function updateTheoreticalCout() { $('theoretical-cout').value = theoreticalCoutPreview($('source').value); }
function updateBufferedCout(snapshot) {
  const buffered = snapshot?.buffered;
  if (buffered?.available === true) {
    $('buffered-cout').value = buffered.text || '(буфер пуст)';
    return;
  }
  $('buffered-cout').value = buffered?.reason
    ? `Недоступно: ${buffered.reason}`
    : 'Точный runtime-снимок внутреннего буфера недоступен в этой остановке.';
}

function renderHistory(items) {
  $('history').textContent = items?.length
    ? items.map(item => `#${item.point?.eventOrdinal ?? '?'}  ${item.label}  ${item.stop?.stopId ?? '?'}${item.retained ? '' : '  (evicted)'}`).join('\n')
    : 'История пока пуста.';
}
function finishPending(frame) {
  const requestId = frame.payload?.requestId;
  if (!requestId) return;
  pendingRequests.delete(requestId);
  if (frame.payload.outcome === 'failed') failedCommands.add(requestId);
  if (frame.payload.outcome === 'failed' && frame.payload.error)
    $('status').textContent = `${frame.payload.error.code}: ${frame.payload.error.message}`;
  refreshControls();
}
function applyState(state) {
  phase = state?.phase || null;
  $('state').textContent = pretty(state);
  updateOutputCheck();
  refreshControls();
}
function applyObservation(observation) {
  stop = observation.stop;
  actualStdout = observation.stdout?.text || '';
  $('observation').textContent = pretty(observation);
  $('stdout').textContent = actualStdout || '(empty)';
  $('stderr').textContent = observation.stderr?.text || '(empty)';
  updateBufferedCout(observation.stdout);
  updateOutputCheck();
  refreshControls();
}
function apply(frame) {
  const payload = frame.payload;
  const result = frame.result;
  if (payload?.kind === 'state') applyState(payload.state);
  if (payload?.kind === 'observation') applyObservation(payload.observation);
  if (payload?.kind === 'commandFinished') finishPending(frame);
  if (result?.kind === 'state') {
    session = frame.session || session;
    applyState(result.state);
    if (result.observation) applyObservation(result.observation);
  }
  if (result?.kind === 'history') renderHistory(result.items);
  if (result?.kind === 'build') {
    $('status').textContent = `Build ${result.success ? 'succeeded' : 'failed'}: ${result.command?.join(' ')}`;
    artifact = result.artifact;
    if (result.stderr) $('stderr').textContent = result.stderr;
  }
  if (frame.ok === false) $('status').textContent = `${frame.error.code}: ${frame.error.message}`;
  refreshControls();
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const value = await (await fetch(`/api/events?after=${eventCursor}`)).json();
    if (value.gap) {
      addLog('event-gap', {after: eventCursor, nextCursor: value.nextCursor});
      $('status').textContent = 'Some harness events were evicted; refresh the backend state.';
    }
    eventCursor = value.nextCursor ?? eventCursor;
    for (const item of value.events) { addLog('event', item); apply(item); }
    if (value.stderr?.length) $('stderr').textContent = value.stderr.join('\n');
    if (value.connected) {
      session = value.session;
      $('connection').textContent = 'connected';
      $('connection').classList.add('ok');
    } else if (session) {
      session = null; stop = null; phase = null; pendingRequests.clear();
    }
    refreshControls();
  } catch (error) { $('status').textContent = `event polling: ${error.message}`; }
  finally { refreshing = false; }
}
function refreshControls() {
  const executionPending = [...pendingRequests.values()].some(kind => kind === 'step' || kind === 'continue');
  const controlsPending = pendingRequests.size > 0;
  const stopped = Boolean(session && stop && phase === 'stopped');
  const canExecute = stopped && !executionPending;
  const canControl = Boolean(session && (stopped || executionPending));
  const canLaunch = Boolean(artifact && (!session || phase === 'terminated' || phase === 'failed'));
  const canBuild = !session || phase === 'terminated' || phase === 'failed';
  for (const button of document.querySelectorAll('button[data-action]')) {
    const kind = button.dataset.action;
    const enabled = kind === 'build' ? canBuild : kind === 'launch' ? canLaunch :
      kind === 'step' || kind === 'continue' ? canExecute : kind === 'pause' || kind === 'stop' ? canControl : Boolean(session) && !controlsPending;
    button.disabled = busy || !enabled;
  }
}

async function action(kind) {
  const liveCommand = ['step', 'continue', 'pause', 'stop'].includes(kind);
  const executionPending = [...pendingRequests.values()].some(value => value === 'step' || value === 'continue');
  if (busy && kind !== 'pause' && kind !== 'stop') return;
  if (liveCommand && !(session && stop && (phase === 'stopped' || executionPending))) {
    $('status').textContent = 'Сначала выполните Launch и дождитесь остановки процесса.';
    return;
  }
  if (['state', 'history'].includes(kind) && !session) {
    $('status').textContent = 'Сначала выполните Launch.';
    return;
  }
  if ((kind === 'step' || kind === 'continue') && executionPending) return;
  if (busy) return;
  if (!liveCommand) busy = true;
  refreshControls();
  try {
    const sourceText = $('source').value;
    let command;
    if (kind === 'build') command = {kind: 'build', source: commonSource(sourceText, await digest(sourceText)), configuration: {revisionId: 'config-revision-1', compiler: 'clang++', flags: ['-std=c++20', '-g', '-O0'], outputDirectory: '.phantom/harness-build'}, architecture: 'x86_64'};
    else if (kind === 'launch') {
      if (!artifact) throw new Error('Сначала выполните Build');
      command = {kind: 'launch', buildId: artifact.id, input: {id: 'input-1', text: $('input').value, encoding: 'utf-8', closeAfterWrite: true}, argv: parseLines($('argv').value), environment: await environment(), stopAtEntry: true};
    } else if (kind === 'history') command = {kind: 'listHistory', branchId: stop?.point?.branchId || 'main', afterOrdinal: null, limit: 100};
    else if (kind === 'state') command = {kind: 'getState'};
    else if (kind === 'step') command = {kind: 'step', stepKind: 'over'};
    else command = {kind};
    const expectedStop = liveCommand ? stop : undefined;
    const value = await post('/api/request', {command, session, ...(expectedStop ? {expectedStop} : {})});
    if (value.result?.kind === 'launchAccepted') {
      session = value.result.session; phase = null; stop = null; actualStdout = '';
      $('buffered-cout').value = 'Ожидание первой остановки процесса.';
    }
    if (value.result?.kind === 'accepted' && liveCommand) pendingRequests.set(value.requestId, kind);
    if (value.result?.kind === 'state') { session = value.session; apply(value); }
    if (value.result?.kind === 'build') { apply(value); artifact = value.result.artifact; }
    if (value.result?.kind === 'observation') applyObservation(value.result.observation);
    if (value.ok === false) apply(value);
    await refresh();
    if (value.ok === false || !failedCommands.has(value.requestId))
      $('status').textContent = `${kind}: ${value.ok === false ? 'error' : 'accepted'}`;
  } catch (error) { $('status').textContent = error.message; }
  finally { if (!liveCommand) busy = false; refreshControls(); }
}

document.querySelectorAll('button[data-action]').forEach(button => button.addEventListener('click', () => action(button.dataset.action)));
$('source').addEventListener('input', updateTheoreticalCout);
$('reset').addEventListener('click', async () => { await post('/api/reset'); location.reload(); });
setInterval(refresh, 500);
updateTheoreticalCout();
refresh();
