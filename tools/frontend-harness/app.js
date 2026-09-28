const $ = id => document.getElementById(id);
const pretty = value => JSON.stringify(value, null, 2);
const executionKinds = ['step', 'continue'];
const controlKinds = ['pause', 'stop'];
const inputKinds = ['appendInput', 'closeInput'];
let artifact = null, builtSource = null, session = null, stop = null, phase = null;
// Every launch/reset creates a new UI epoch.  HTTP responses and event frames
// can arrive after that boundary; they must never mutate the new session.
let sessionEpoch = 0;
let eventCursor = 0, refreshPromise = null, launchEvents = null, lastSequence = 0;
let inputOpen = false, inputCounter = 0, branchId = 'main';
const inputIdPrefix = `input-${crypto.randomUUID()}`;
let inputLedger = '';
let inputMutationStop = null;
let inputWait = false, inputWaitStop = null;
let appendFlight = null, appendQueue = null;
let activeExecution = null, autoResumeInFlight = false, autoResumeBlocked = false;
let eofRequested = false, eofClosing = false;
const log = [], pendingRequests = new Map(), finishedRequests = new Map(), sending = new Set();
const sameSession = (a, b) => a && b && a.id === b.id && a.generation === b.generation;
const sameStop = (a, b) => a && b && a.stopId === b.stopId && a.stateRevision === b.stateRevision;
const executing = () => executionKinds.some(kind => sending.has(kind)) ||
  [...pendingRequests.values()].some(kind => executionKinds.includes(kind));

function addLog(direction, value) {
  log.push(`${new Date().toLocaleTimeString()} ${direction}\n${pretty(value)}`);
  if (log.length > 80) log.shift();
  $('log').textContent = log.join('\n\n');
}
async function post(url, payload = {}) {
  addLog('→', {endpoint: url, payload});
  const response = await fetch(url, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(payload)});
  const value = await response.json();
  addLog('←', value);
  if (!response.ok || value.ok === false)
    throw new Error(`${value.error?.code ? value.error.code + ': ' : ''}${value.error?.message || `HTTP ${response.status}`}`);
  return value;
}
function parseLines(text) { return text ? text.replace(/\r\n/g, '\n').split('\n') : []; }
async function digest(text) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function environment() {
  const result = Object.create(null);
  for (const line of parseLines($('environment').value)) {
    if (!line) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) throw new Error('Environment: каждая строка должна иметь вид KEY=value.');
    result[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return result;
}
function renderBuildStatus() {
  $('build-status').textContent = !artifact ? 'Нет успешной сборки. Выполните Build.' :
    builtSource !== $('source').value ? 'Исходник изменён после сборки. Для Launch нужен новый Build.' :
    `Сборка соответствует редактору: ${artifact.id.slice(0, 12)}.`;
}
function renderBuffer(snapshot) {
  const buffered = snapshot?.buffered;
  if (!buffered?.available) {
    $('buffered-cout').textContent = 'Недоступно';
    if ($('buffer-metrics')) $('buffer-metrics').textContent = 'Метрики: ND (ABI/режим не подтверждён)';
    $('buffer-status').textContent = buffered?.reason || 'На этой остановке буфер не подтверждён.';
    return;
  }
  const capacity = buffered.writeWindowCapacityBytes ?? buffered.capacityBytes;
  const remaining = buffered.writeWindowRemainingBytes ?? buffered.remainingCapacityBytes;
  const storage = buffered.storageCapacityBytes;
  const pending = buffered.pendingBytes ?? buffered.totalBytes ?? 0;
  $('buffered-cout').textContent = buffered.text || (pending > 0 ?
    `(в буфере ${pending} байт; текст ${buffered.textStatus === 'truncated' || buffered.truncated ? 'показан не полностью' : 'недоступен'})` :
    '(буфер пуст)');
  if ($('buffer-metrics')) $('buffer-metrics').innerHTML = [
    metric('pending', `${pending} B`),
    metric('window', capacity == null ? 'ND' : `${capacity} B`),
    metric('free', remaining == null ? 'ND' : `${remaining} B`),
    metric('storage', storage == null ? 'ND' : `${storage} B`),
    metric('flush', buffered.flushPolicy || 'ND'),
  ].join('');
  $('buffer-status').textContent = `${buffered.source || 'Runtime'}: в буфере ${pending} байт` +
    (capacity == null ? '; активное окно неизвестно' : ` из активного окна ${capacity}`) +
    (remaining == null ? '' : `; свободно ${remaining} байт`) +
    (storage == null ? '' : `; физическое хранилище ${storage} байт`) +
    (buffered.mode ? `; режим: ${buffered.mode}` : '') +
    (buffered.truncated ? '; текст показан частично.' : '.');
}
function metric(label, value) { return `<span class="metric"><b>${label}</b><code>${String(value)}</code></span>`; }
function renderVariables(stack) {
  const lines = [];
  for (const frame of stack || []) {
    lines.push(`${frame.functionName} (${frame.id})`);
    for (const variable of frame.variables || []) {
      const value = variable.value;
      const scalar = value?.value;
      const unavailable = value?.availability !== 'available' || value?.availability === 'notDeclared' || variable.notDeclared;
      const text = unavailable ? `ND (${value?.reason || 'notDeclared'})` :
        scalar?.decimal ?? scalar?.text ?? scalar?.addressHex ?? scalar?.summary ?? String(scalar?.value ?? '?');
      lines.push(`  ${variable.name}: ${variable.type} = ${text}`);
      lines.push(`    адрес: ${variable.addressHex || 'недоступен'}`);
      if (variable.storage) {
        const lifetime = variable.storage.lifetime === 'unknown' ?
          'C++ lifetime не подтверждён обычным DWARF/GDB' : variable.storage.lifetime;
        lines.push(`    память: ${pretty(variable.storage)}; ${lifetime}`);
      }
    }
  }
  $('variables').textContent = lines.join('\n') || 'Нет доступных локальных переменных.';
}
function renderHistory(result) {
  $('history').textContent = result.items?.length ? result.items.map(item =>
    `#${item.point.eventOrdinal}  ${item.label}  ${item.stop.stopId}${item.retained ? '' : ' (снимок вытеснен)'}`
  ).join('\n') + (result.hasMore ? '\nПоказаны первые 100 остановок.' : '') : 'История пока пуста.';
}
function rangeText(range) {
  if (!range) return '—';
  if (Array.isArray(range)) return range.map(item => `[${item.start}, ${item.end})`).join(', ') || '—';
  return `[${range.start}, ${range.end})`;
}
function inputWaiting() {
  return inputWait;
}
function currentEpoch() { return sessionEpoch; }
function currentInputContext(epoch, expectedSession) {
  return epoch === currentEpoch() && sameSession(expectedSession, session) && phase !== 'terminated' && phase !== 'failed';
}
function exposedInputText(input) {
  const text = input?.revision?.text;
  const ranges = input?.exposedRanges;
  if (typeof text !== 'string' || !Array.isArray(ranges) || !ranges.every(range =>
    Number.isInteger(range.start) && Number.isInteger(range.end) &&
    range.start >= 0 && range.end >= range.start && range.end <= text.length)) return null;
  return ranges.map(range => text.slice(range.start, range.end)).join('');
}
function applyInput(input, {markWait = true} = {}) {
  if (!input) return;
  const restoredLedger = exposedInputText(input);
  if (restoredLedger !== null) {
    inputLedger = restoredLedger;
    if ($('input-locked')) $('input-locked').value = inputLedger;
  }
  inputOpen = input.eof ? input.eof !== 'observed' && input.eof !== 'requested' : input?.submitted?.closeAfterWrite === false;
  const status = input.status || (inputOpen ? 'idle' : 'complete');
  const tracking = input.tracking || 'none';
  const wait = status === 'waiting' || input.reason === 'input-wait';
  if (markWait && (input.reason === 'input-wait' || status === 'waiting')) inputWait = true;
  const badge = $('input-badge');
  if (badge) { badge.textContent = wait ? 'ожидает ввод' : status; badge.className = `state-pill ${wait ? 'waiting' : status}`; }
  $('input-status').textContent = `${wait ? 'Программа ожидает данные.' : `stdin: ${status}`}` +
    ` ${inputOpen ? 'Поток открыт' : input.eof === 'observed' ? 'EOF наблюдён программой' : 'Закрытие stdin запрошено'}. ` +
    `Передано ${input.deliveredBytes ?? 0} B; consumed: ${tracking === 'semantic' ? rangeText(input.consumedRanges) : 'ND'}; tracking=${tracking}.`;
  const revision = input.revision;
  if ($('input-ranges')) $('input-ranges').textContent = [
    `revision: ${revision?.id || 'ND'}${revision?.parentId ? ` ← ${revision.parentId}` : ''}`,
    `text: ${revision?.text == null ? 'ND' : JSON.stringify(revision.text)}`,
    `exposed: ${rangeText(input.exposedRanges)}`,
    `consumed: ${tracking === 'semantic' ? rangeText(input.consumedRanges) : 'ND'}`,
    `active: ${rangeText(input.activeRange)}`,
    `EOF: ${input.eof || (inputOpen ? 'open' : 'requested')}`,
  ].join('\n');
  const exposed = Array.isArray(input.exposedRanges) ? input.exposedRanges.reduce((n, r) => n + Math.max(0, r.end-r.start), 0) : 0;
  const consumed = tracking === 'semantic' && Array.isArray(input.consumedRanges) ? input.consumedRanges.reduce((n, r) => n + Math.max(0, r.end-r.start), 0) : 0;
  const revisionLength = typeof revision?.text === 'string' ? revision.text.length : 0;
  if ($('input-meter-exposed')) $('input-meter-exposed').style.width = `${revisionLength ? Math.min(100, exposed / revisionLength * 100) : 0}%`;
  if ($('input-meter-consumed')) $('input-meter-consumed').style.width = `${Math.min(100, consumed ? Math.max(3, consumed / Math.max(exposed, consumed) * 100) : 0)}%`;
}
function inputMode() { return $('input-mode')?.value || 'token'; }
function confirmedEnd(value, mode, allowPartial = false) {
  if (!value) return 0;
  if (mode === 'line') {
    const at = value.search(/[\r\n]/);
    if (at < 0) return allowPartial ? value.length : 0;
    return at + (value[at] === '\r' && value[at + 1] === '\n' ? 2 : 1);
  }
  const at = value.search(/[ \t\r\n]/);
  if (at < 0) return allowPartial ? value.length : 0;
  return at + (value[at] === '\r' && value[at + 1] === '\n' ? 2 : 1);
}
function canAppendNow() {
  return Boolean(session && inputWait && inputOpen && (inputWaitStop || stop) &&
    !executing() && pendingRequests.size === 0 && !sending.has('pause') && !sending.has('stop'));
}
function queueAppend(text, explicit = false) {
  if (!text || appendQueue || appendFlight) return;
  appendQueue = {
    id: `${inputIdPrefix}-${++inputCounter}`,
    text,
    explicit,
    attempts: 0,
    epoch: currentEpoch(),
    session,
  };
  maybeSendAppend();
}
function maybeSendAppend() {
  if (!appendQueue || appendFlight || !canAppendNow()) return;
  if (!appendQueue.explicit && (!activeExecution?.finished || !activeExecution.waiting || autoResumeBlocked)) return;
  appendQueue.execution = activeExecution;
  appendFlight = appendQueue;
  appendQueue = null;
  refreshControls();
  void sendAppendCommit(appendFlight);
}
function appendRetryable(error) {
  const text = String(error?.message || error || '').toLowerCase();
  return /network|fetch|http 5|timeout|temporar|econn|reset/.test(text);
}
async function sendAppendCommit(commit) {
  commit.attempts += 1;
  const epoch = commit.epoch;
  if (!currentInputContext(epoch, commit.session) || !inputWait) {
    if (appendFlight === commit) appendFlight = null;
    return;
  }
  try {
    const value = await post('/api/request', {
      command: {kind: 'appendInput', id: commit.id, text: commit.text},
      session,
      expectedStop: inputWaitStop || stop,
    });
    // A reset/relaunch may have happened while the request was in flight.
    if (!currentInputContext(epoch, commit.session)) {
      if (appendFlight === commit) appendFlight = null;
      return;
    }
    applyResult(value);
    // Remove only the exact prefix we sent. If the user edited that prefix
    // while the request was in flight, preserve their edit rather than
    // deleting unrelated text; the sent bytes remain visible in the locked
    // journal and the user can explicitly confirm the edited draft.
    const current = $('stdin-live').value;
    if (current.startsWith(commit.text)) {
      $('stdin-live').value = current.slice(commit.text.length);
    } else if ($('input-status')) {
      $('input-status').textContent = 'Ввод изменён во время передачи; черновик сохранён, отправленный фрагмент не удалён автоматически.';
    }
    // Native input snapshots restore the authoritative exposed prefix above.
    // The fallback supports older adapters that do not report revised ranges.
    if (exposedInputText(value.result?.input) === null) inputLedger += commit.text;
    if ($('input-locked')) $('input-locked').value = inputLedger;
    appendFlight = null;
    if (activeExecution && activeExecution === commit.execution) activeExecution.suppliedInput = true;
    if ($('input-status')) $('input-status').textContent = `Передан фрагмент ${JSON.stringify(commit.text)}; ожидается продолжение.`;
    if (eofRequested) {
      const remaining = $('stdin-live').value;
      if (remaining && !appendQueue) queueAppend(remaining, true);
      if (!remaining && !appendQueue && !appendFlight) void sendCloseInput();
    } else if (!autoResumeBlocked) maybeResumeExecution();
    refreshControls();
  } catch (error) {
    if (!currentInputContext(epoch, commit.session)) return;
    if (commit.attempts < 3 && appendRetryable(error)) {
      if ($('input-status')) $('input-status').textContent = `Повтор передачи stdin ${commit.attempts}/3 с тем же ID…`;
      setTimeout(() => sendAppendCommit(commit), 150 * commit.attempts);
      return;
    }
    appendFlight = null;
    appendQueue = commit;
    if ($('input-status')) $('input-status').textContent = `Ввод не передан: ${error.message}. Черновик сохранён.`;
    refreshControls();
  }
}
async function sendCloseInput() {
  if (eofClosing || !canAppendNow() || appendFlight || appendQueue) return;
  const epoch = currentEpoch();
  const requestSession = session;
  const execution = activeExecution;
  eofClosing = true;
  refreshControls();
  try {
    const value = await post('/api/request', {
      command: {kind: 'closeInput'}, session, expectedStop: inputWaitStop || stop,
    });
    if (!currentInputContext(epoch, requestSession)) return;
    applyResult(value);
    if (activeExecution === execution && execution) execution.suppliedInput = true;
    eofRequested = false;
    if ($('input-status')) $('input-status').textContent = activeExecution?.waiting && !autoResumeBlocked ?
      'Закрытие stdin запрошено; исполнение продолжается.' : 'Закрытие stdin запрошено. Продолжите исполнение кнопкой Step или Continue.';
    if (activeExecution?.finished && activeExecution.waiting && !autoResumeBlocked) maybeResumeExecution();
    else { inputWait = false; inputWaitStop = null; }
  } catch (error) {
    if (!currentInputContext(epoch, requestSession)) return;
    autoResumeBlocked = true;
    if ($('input-status')) $('input-status').textContent = `EOF не передан: ${error.message}.`;
  } finally { if (epoch === currentEpoch()) { eofClosing = false; refreshControls(); maybeCommitAndResume(); } }
}
function requestEof() {
  if (!canAppendNow()) {
    if ($('input-status')) $('input-status').textContent = 'EOF доступен только в состоянии ожидания ввода.';
    return;
  }
  eofRequested = true;
  const draft = $('stdin-live').value;
  if (draft && !appendQueue && !appendFlight) queueAppend(draft, true);
  if (appendQueue) appendQueue.explicit = true;
  maybeSendAppend();
  if (!draft && !appendQueue && !appendFlight) void sendCloseInput();
}
function maybeResumeExecution() {
  if (appendFlight || appendQueue || eofRequested || eofClosing || autoResumeInFlight || autoResumeBlocked || !inputWait) return;
  const execution = activeExecution;
  if (!execution?.finished || !execution.waiting || execution.resumed || !execution.suppliedInput || !enabled(execution.kind)) return;
  execution.resumed = true;
  autoResumeInFlight = true;
  inputWait = false;
  inputWaitStop = null;
  void action(execution.kind, null, {autoResume: true, previous: execution})
    .finally(() => { autoResumeInFlight = false; refreshControls(); maybeCommitAndResume(); });
}
function maybeCommitAndResume() {
  if (!inputWait || autoResumeBlocked || !activeExecution?.finished || !activeExecution.waiting) return;
  if (activeExecution.suppliedInput && !eofRequested) {
    maybeResumeExecution();
    return;
  }
  const value = $('stdin-live')?.value || '';
  if (!appendQueue && !appendFlight && inputMode() !== 'manual') {
    const end = confirmedEnd(value, inputMode(), false);
    if (end > 0) queueAppend(value.slice(0, end));
  }
  maybeSendAppend();
  maybeResumeExecution();
}
function commitInput(mode, explicitEnd = null) {
  const auto = mode === 'auto';
  if (auto && (autoResumeBlocked || !activeExecution?.finished || !activeExecution.waiting)) return Promise.resolve();
  if (appendQueue) {
    if (!auto) { appendQueue.attempts = 0; appendQueue.explicit = true; }
    maybeSendAppend(); return Promise.resolve();
  }
  const value = $('stdin-live')?.value || '';
  if (!value) return Promise.resolve();
  if (auto && (!inputWait || inputMode() === 'manual')) {
    if ($('input-status')) $('input-status').textContent = 'Черновик сохранён локально; он будет передан только в состоянии ожидания ввода.';
    return Promise.resolve();
  }
  const selectedMode = mode === 'line' ? 'line' : inputMode();
  const end = explicitEnd || confirmedEnd(value, selectedMode, !auto);
  if (!end) return Promise.resolve();
  if (!inputWait) return Promise.resolve();
  queueAppend(value.slice(0, end), !auto);
  maybeSendAppend();
  return Promise.resolve();
}
function applyState(state, {allowAuto = true} = {}) {
  phase = state?.phase || null;
  $('state').textContent = pretty(state);
  if (state?.live) { stop = state.live.stop; branchId = state.live.point.branchId; }
  if (phase !== 'waitingForInput') { inputWait = false; inputWaitStop = null; }
  if (phase === 'terminated' || phase === 'failed') {
    stop = null; inputOpen = false; inputWait = false; inputWaitStop = null;
    activeExecution = null; appendQueue = null; appendFlight = null;
  }
  // Get state is deliberately side-effect free, but it still has to restore
  // the input controls after a reload/event gap. `allowAuto` only gates
  // committing a draft or resuming execution.
  if (phase === 'waitingForInput') {
    inputWait = true;
    inputWaitStop = state.live?.stop || inputWaitStop;
  }
  if (allowAuto) maybeCommitAndResume();
}
function applyObservation(observation, {allowAuto = true} = {}) {
  if (!observation) return;
  stop = observation.stop;
  branchId = observation.point.branchId;
  $('observation').textContent = pretty(observation);
  $('stdout').textContent = observation.stdout?.text || '(empty)';
  $('stderr').textContent = observation.stderr?.text || '(empty)';
  $('stdout-check').textContent = `Получено из stdout: ${observation.stdout?.totalBytes ?? 0} байт.`;
  // The wait reason belongs to Observation rather than the transport input
  // object in the native profile. Copy it into the UI view so an idle pipe is
  // not mistaken for a program that is not blocked in cin.
  // Observations are immutable. A Get state reply at the same stop can carry
  // the pre-append input snapshot, even after an append/EOF was acknowledged.
  // Preserve that newer input response until execution creates a new stop.
  if (!sameStop(inputMutationStop, observation.stop))
    applyInput(observation.input ? {...observation.input, reason: observation.reason} : observation.input, {markWait: allowAuto});
  if (observation.reason === 'input-wait' || observation.input?.status === 'waiting') {
    inputWait = true;
    inputWaitStop = observation.stop || inputWaitStop;
  } else if (observation.reason && observation.reason !== 'input-wait') {
    inputWait = false;
    inputWaitStop = null;
  }
  if (allowAuto) maybeCommitAndResume();
  renderBuffer(observation.stdout);
  renderVariables(observation.stack);
}
function finishPending(payload) {
  const kind = pendingRequests.get(payload.requestId);
  pendingRequests.delete(payload.requestId);
  finishedRequests.set(payload.requestId, payload);
  if (finishedRequests.size > 256) finishedRequests.delete(finishedRequests.keys().next().value);
  if (kind && executionKinds.includes(kind) && activeExecution?.requestId === payload.requestId) {
    activeExecution.finished = true;
    activeExecution.outcome = payload.outcome;
    if (payload.outcome === 'waiting' || payload.error?.code === 'INPUT_WAIT') {
      activeExecution.waiting = true;
      inputWait = true;
      inputWaitStop = stop || inputWaitStop;
    } else if (payload.outcome !== 'accepted') {
      activeExecution = null;
    }
    maybeCommitAndResume();
  }
  if (kind === 'stop') {
    activeExecution = null; inputWait = false; inputWaitStop = null;
    appendQueue = null;
    appendFlight = null;
  }
  if (kind === 'pause' && payload.outcome === 'completed') activeExecution = null;
  if (payload.error) $('status').textContent = `${payload.error.code}: ${payload.error.message}`;
  else $('status').textContent = `Команда ${payload.requestId}: ${payload.outcome}.`;
}
function applyEvent(frame) {
  if (!frame.payload) {
    if (frame.kind === 'harnessExit' || frame.kind === 'harnessError') {
      sessionEpoch += 1;
      session = null; stop = null; phase = null; inputOpen = false;
      inputWait = false; inputWaitStop = null; autoResumeBlocked = true;
      appendQueue = null; appendFlight = null; activeExecution = null;
      autoResumeInFlight = false; eofClosing = false;
      artifact = null; builtSource = null; pendingRequests.clear(); sending.clear(); finishedRequests.clear();
      $('status').textContent = frame.message || 'Backend завершился.';
    }
    return;
  }
  if (launchEvents) { launchEvents.push(frame); return; }
  if (!sameSession(frame.session, session) || frame.sequence <= lastSequence) return;
  lastSequence = frame.sequence;
  const payload = frame.payload;
  if (payload.kind === 'observation') applyObservation(payload.observation);
  if (payload.kind === 'state') applyState(payload.state);
  if (payload.kind === 'input') { applyInput(payload.input); maybeCommitAndResume(); }
  if (payload.kind === 'commandFinished') finishPending(payload);
}
function applyResult(frame) {
  const result = frame.result;
  if (result?.kind === 'state') {
    if (result.throughSequence != null && result.throughSequence < lastSequence) return;
    if (result.throughSequence != null) lastSequence = result.throughSequence;
    if (result.observation) applyObservation(result.observation, {allowAuto: false});
    applyState(result.state, {allowAuto: false});
    $('state-status').textContent = `Обновлено Get state в ${new Date().toLocaleTimeString()}. Новая остановка не создаётся.`;
  }
  if (result?.kind === 'history') renderHistory(result);
  if (result?.kind === 'input') {
    inputMutationStop = stop;
    applyInput(result.input);
  }
}
async function pollEvents() {
  const pollEpoch = currentEpoch();
  try {
    const response = await fetch(`/api/events?after=${eventCursor}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const value = await response.json();
    if (pollEpoch !== currentEpoch()) return;
    if (value.gap) {
      addLog('event-gap', {after: eventCursor, nextCursor: value.nextCursor});
      $('status').textContent = 'Часть событий вытеснена. Запросите Get state; исход пропущенных команд неизвестен.';
      autoResumeBlocked = true;
      activeExecution = null;
      pendingRequests.clear();
    }
    eventCursor = value.nextCursor ?? eventCursor;
    // A refreshed tab can attach to the existing session; an active launch is
    // adopted only by its response, with early events buffered until then.
    if (!session && !launchEvents && value.session) session = value.session;
    for (const item of value.events || []) { addLog('event', item); applyEvent(item); }
    $('connection').textContent = value.connected ? 'connected' : 'не подключено';
    $('connection').classList[value.connected ? 'add' : 'remove']('ok');
    if (!value.connected && session && !launchEvents) {
      sessionEpoch += 1;
      session = null; stop = null; phase = null; inputOpen = false;
      inputWait = false; inputWaitStop = null; autoResumeBlocked = true;
      appendQueue = null; appendFlight = null; activeExecution = null;
      autoResumeInFlight = false; eofClosing = false;
      artifact = null; builtSource = null; pendingRequests.clear(); sending.clear(); finishedRequests.clear();
    }
  } catch (error) { $('status').textContent = `event polling: ${error.message}`; }
  finally { refreshControls(); }
}
function refresh() {
  if (!refreshPromise) refreshPromise = pollEvents().finally(() => { refreshPromise = null; });
  return refreshPromise;
}
function enabled(kind) {
  // launchAccepted precedes its entry observation; keep the session busy in
  // that small window so Build/Launch cannot race a running inferior.
  const alive = Boolean(session && (phase === null || phase === 'stopped' || phase === 'waitingForInput' || phase === 'running' || executing()));
  const exclusive = sending.has('build') || sending.has('launch');
  if (sending.has(kind) || exclusive) return false;
  if (kind === 'build') return !alive;
  if (kind === 'launch') return !alive && Boolean(artifact && builtSource === $('source').value);
  if (executionKinds.includes(kind)) return alive && (phase === 'stopped' || phase === 'waitingForInput') && Boolean(stop) && !executing() && pendingRequests.size === 0 && !appendFlight && !appendQueue && !eofClosing;
  if (controlKinds.includes(kind)) return alive && ![...pendingRequests.values()].includes(kind);
  if (inputKinds.includes(kind)) return alive && inputOpen && inputWaiting() && !appendFlight && !inputKinds.some(item => sending.has(item));
  return Boolean(session) && !executing() && pendingRequests.size === 0;
}
function refreshControls() {
  for (const button of document.querySelectorAll('button[data-action]')) button.disabled = !enabled(button.dataset.action);
  // Bytes in appendFlight are immutable until the backend acknowledges them;
  // freezing the small draft textarea makes that boundary visible and avoids
  // a typed edit being mistaken for an additional confirmed value.
  $('stdin-live').readOnly = Boolean(appendFlight || appendQueue || eofClosing);
  if ($('commit-token')) {
    $('commit-token').disabled = !canAppendNow() || Boolean(appendFlight || eofClosing);
    $('commit-token').textContent = appendQueue ? 'Повторить передачу' : 'Подтвердить токен/фрагмент';
  }
  if ($('commit-line')) $('commit-line').disabled = !canAppendNow() || Boolean(appendFlight || appendQueue || eofClosing);
  if ($('close-input')) $('close-input').disabled = !canAppendNow() || Boolean(eofClosing);
  renderBuildStatus();
}
async function action(kind, suppliedText = null, meta = {}) {
  if (!enabled(kind)) {
    if (kind === 'launch') $('status').textContent = 'Для Launch нужна успешная сборка текущего исходника и завершённый предыдущий запуск.';
    return;
  }
  if (kind === 'launch') {
    sessionEpoch += 1;
    inputMutationStop = null;
    inputWait = false; inputWaitStop = null; appendQueue = null; appendFlight = null;
    activeExecution = null; autoResumeInFlight = false; eofRequested = false; eofClosing = false;
  }
  const requestEpoch = currentEpoch();
  // A user control action is an explicit boundary: any automatic stdin
  // continuation which is pending must not restart the inferior afterwards.
  if (kind === 'pause' || kind === 'stop') {
    autoResumeBlocked = true;
    if (kind === 'stop') {
      inputWait = false;
      inputWaitStop = null;
      appendQueue = null;
    }
  }
  if (executionKinds.includes(kind) && !meta.autoResume) autoResumeBlocked = false;
  sending.add(kind);
  refreshControls();
  const sourceText = $('source').value;
  let liveText = '';
  try {
    let command;
    if (requestEpoch !== currentEpoch()) return;
    if (kind === 'build') {
      artifact = null; builtSource = null;
      const hash = await digest(sourceText);
      command = {kind: 'build', source: {id: `source-${hash}`, documents: [{documentId: 'main.cpp', revisionId: `revision-${hash}`, path: 'main.cpp', text: sourceText, sha256: hash}]}, configuration: {revisionId: 'config-revision-1', compiler: 'clang++', flags: ['-std=c++20', '-g', '-O0'], outputDirectory: '.phantom/harness-build'}, architecture: 'x86_64'};
    } else if (kind === 'launch') {
      const initialInput = $('input').value;
      const finiteInput = $('input-eof').checked;
      // With an open stdin the draft stays in Phantom and is released in
      // token/line chunks only after a real input wait. Finite launch input is
      // intentionally submitted as one exact byte sequence for batch tests.
      command = {kind, buildId: artifact.id, input: {id: `${inputIdPrefix}-${++inputCounter}`, text: finiteInput ? initialInput : '', encoding: 'utf-8', closeAfterWrite: finiteInput}, argv: parseLines($('argv').value), environment: environment(), stopAtEntry: true};
      inputLedger = finiteInput ? initialInput : '';
      if ($('input-locked')) $('input-locked').value = inputLedger;
      // A relaunch starts a new local input revision. Never carry an old
      // session's draft into it; open stdin exposes the launch text as the new
      // editable draft, while finite input has no draft left to commit.
      $('stdin-live').value = finiteInput ? '' : initialInput;
      launchEvents = [];
    } else if (kind === 'history') command = {kind: 'listHistory', branchId, afterOrdinal: null, limit: 100};
    else if (kind === 'state') command = {kind: 'getState'};
    else if (kind === 'step') command = {kind, stepKind: 'over'};
    else if (kind === 'appendInput') {
      liveText = suppliedText ?? $('stdin-live').value;
      if (!liveText) throw new Error('Черновик пуст. Введите завершённый токен или строку.');
      command = {kind, id: `${inputIdPrefix}-${++inputCounter}`, text: liveText};
    } else command = {kind};
    // Pause/Stop target the live session even if the last stop token has
    // changed while execution was pending. Source steps require that token.
    if (requestEpoch !== currentEpoch()) return;
    const value = await post('/api/request', {
      command,
      session,
      ...((executionKinds.includes(kind) || inputKinds.includes(kind)) ? {expectedStop: inputKinds.includes(kind) ? (inputWaitStop || stop) : stop} : {}),
    });
    if (requestEpoch !== currentEpoch()) return;
    if (kind === 'build') {
      artifact = value.result.artifact;
      builtSource = artifact ? sourceText : null;
      $('stderr').textContent = value.result.stderr || '(empty)';
      $('status').textContent = value.result.success ? 'Build: успешно.' : 'Build: ошибка компиляции. Launch недоступен.';
    } else if (value.result?.kind === 'launchAccepted') {
      // The backend assigns a monotonically increasing session generation;
      // the local epoch additionally protects us from delayed old fetches.
      session = value.result.session; stop = null; phase = 'running'; lastSequence = 0;
      autoResumeBlocked = false;
      pendingRequests.clear(); finishedRequests.clear();
      activeExecution = null; inputWait = false; inputWaitStop = null; appendQueue = null; appendFlight = null;
      $('history').textContent = 'Новый запуск. Нажмите History для списка остановок.';
      const early = launchEvents; launchEvents = null;
      // Polling can overlap Launch and return the previous session's tail.
      // Buffering is necessary until launchAccepted, but only frames carrying
      // the newly assigned session may be replayed into this run.
      for (const event of early) if (sameSession(event.session, session)) applyEvent(event);
    } else {
      applyResult(value);
      if (value.result?.kind === 'accepted' && !finishedRequests.has(value.requestId)) pendingRequests.set(value.requestId, kind);
      if (executionKinds.includes(kind) && value.result?.kind === 'accepted') {
        const finished = finishedRequests.get(value.requestId);
        activeExecution = {
          kind,
          requestId: value.requestId,
          expectedStop: stop,
          finished: Boolean(finished),
          waiting: finished?.outcome === 'waiting' || finished?.error?.code === 'INPUT_WAIT',
          resumed: false,
          suppliedInput: false,
        };
        if (activeExecution.waiting) inputWait = true;
        maybeCommitAndResume();
      }
    }
    await refresh();
    if (requestEpoch !== currentEpoch()) return;
    if (kind !== 'build' && !finishedRequests.has(value.requestId)) {
      $('status').textContent = kind === 'history' ? `History: получено ${value.result.items?.length ?? 0} остановок.` :
        kind === 'state' ? 'Get state: состояние и последний снимок обновлены.' :
        value.result?.kind === 'accepted' ? `${kind}: выполняется; доступны Pause и Stop.` : `${kind}: готово.`;
    }
  } catch (error) {
    if (requestEpoch !== currentEpoch()) return;
    $('status').textContent = error.message;
    if (meta.autoResume) {
      // A rejected or lost execution response cannot be retried like an
      // idempotent input chunk: the program may already have resumed.
      // Require an explicit user action after inspecting the current state.
      autoResumeBlocked = true;
      autoResumeInFlight = false;
      inputWait = true;
      inputWaitStop = stop || inputWaitStop;
      activeExecution = meta.previous || activeExecution;
      if (activeExecution) activeExecution.resumed = false;
    }
  }
  finally {
    if (requestEpoch === currentEpoch()) {
      if (kind === 'launch') launchEvents = null;
      sending.delete(kind);
      refreshControls();
      maybeSendAppend();
      maybeCommitAndResume();
    }
  }
}
document.querySelectorAll('button[data-action]').forEach(button => button.addEventListener('click', () => action(button.dataset.action)));
$('source').addEventListener('input', refreshControls);
const samples = {
  integer: '#include <iostream>\nint main() {\n  int value = 0;\n  std::cin >> value;\n  std::cout << "value=" << value << "\\n";\n  return 0;\n}\n',
  getline: '#include <iostream>\n#include <string>\nint main() {\n  std::string text;\n  std::getline(std::cin, text);\n  std::cout << "line=[" << text << "]\\n";\n}\n',
  flush: '#include <iostream>\nint main() {\n  std::cout << "before";\n  std::cout << std::flush;\n  std::cout << " after\\n";\n}\n',
};
if ($('sample-program')) $('sample-program').addEventListener('change', () => {
  const sample = samples[$('sample-program').value];
  if (!sample) return;
  $('source').value = sample;
  artifact = null; builtSource = null;
  $('status').textContent = 'Пример загружен. Выполните Build.';
  refreshControls();
});
$('stdin-live').addEventListener('input', () => {
  const value = $('stdin-live').value;
  const mode = $('input-mode')?.value || 'token';
  if (mode === 'manual') { refreshControls(); return; }
  const delimiter = mode === 'line' ? value.search(/[\r\n]/) : value.search(/[ \t\r\n]/);
  if (delimiter >= 0) {
    const end = delimiter + (value[delimiter] === '\r' && value[delimiter + 1] === '\n' ? 2 : 1);
    void commitInput('auto', end);
  }
  refreshControls();
});
$('stdin-live').addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    // Let the textarea insert the real newline. The following input event
    // applies the same waiting-only auto-commit path as a typed delimiter.
    return;
  }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'd') {
    event.preventDefault();
    requestEof();
  }
});
if ($('commit-token')) $('commit-token').addEventListener('click', () => void commitInput('token'));
if ($('commit-line')) $('commit-line').addEventListener('click', () => void commitInput('line'));
if ($('close-input')) $('close-input').addEventListener('click', requestEof);
if ($('input-mode')) $('input-mode').addEventListener('change', () => {
  if ($('input-status')) $('input-status').textContent = `Режим границы: ${$('input-mode').selectedOptions?.[0]?.textContent || $('input-mode').value}.`;
});
$('reset').addEventListener('click', async () => {
  sessionEpoch += 1;
  autoResumeBlocked = true;
  appendQueue = null; appendFlight = null; activeExecution = null;
  sending.clear(); pendingRequests.clear(); finishedRequests.clear();
  try { await post('/api/reset'); location.reload(); }
  catch (error) { $('status').textContent = error.message; }
});
// A read-only seam for dependency-free VM tests. It exposes operations rather
// than mutable internals, so browser users still go through this state
// machine. The seam also lets tests deliver response/event frames in either
// order without a browser automation dependency.
if (typeof window !== 'undefined') {
  window.__phantomHarnessDebug = {
    applyEvent,
    applyResult,
    finishPending,
    state: () => ({
      epoch: sessionEpoch,
      session,
      stop,
      phase,
      inputWait,
      inputWaitStop,
      activeExecution: activeExecution && {...activeExecution},
      appendQueue: appendQueue && {...appendQueue},
      appendFlight: appendFlight && {...appendFlight},
      autoResumeBlocked,
      draft: $('stdin-live')?.value || '',
      ledger: inputLedger,
    }),
    setDraft: value => { $('stdin-live').value = String(value); $('stdin-live').dispatchEvent?.({type: 'input'}); },
    commitToken: () => commitInput('token'),
    commitLine: () => commitInput('line'),
    eof: requestEof,
    action,
    refresh,
  };
}
setInterval(refresh, 500);
refreshControls();
refresh();
