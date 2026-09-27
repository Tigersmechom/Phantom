const $ = id => document.getElementById(id);
const pretty = value => JSON.stringify(value, null, 2);
const executionKinds = ['step', 'continue'];
const controlKinds = ['pause', 'stop'];
const inputKinds = ['appendInput', 'closeInput'];
let artifact = null, builtSource = null, session = null, stop = null, phase = null;
let eventCursor = 0, refreshPromise = null, launchEvents = null, lastSequence = 0;
let inputOpen = false, inputCounter = 0, branchId = 'main';
const log = [], pendingRequests = new Map(), finishedRequests = new Map(), sending = new Set();
const sameSession = (a, b) => a && b && a.id === b.id && a.generation === b.generation;
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
function theoreticalCoutPreview(source) {
  const statements = [...source.matchAll(/\b(?:std::)?cout\b\s*<<([\s\S]*?);/g)];
  if (!statements.length) return 'В исходнике std::cout не найден.';
  let output = '';
  let unknown = false;
  for (const statement of statements) {
    for (const token of statement[1].split('<<').map(item => item.trim()).filter(Boolean)) {
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
function updateTheoreticalCout() {
  const field = $('theoretical-cout');
  if (field) field.value = theoreticalCoutPreview($('source').value);
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
    $('buffer-status').textContent = buffered?.reason || 'На этой остановке буфер не подтверждён.';
    return;
  }
  $('buffered-cout').textContent = buffered.text || '(буфер пуст)';
  const capacity = buffered.capacityBytes;
  const remaining = buffered.remainingCapacityBytes;
  $('buffer-status').textContent = `${buffered.source || 'Runtime'}: в буфере ${buffered.pendingBytes ?? buffered.totalBytes ?? 0} байт` +
    (capacity == null ? '; ёмкость неизвестна' : ` из ${capacity}`) +
    (remaining == null ? '' : `; свободно ${remaining} байт`) +
    (buffered.mode ? `; режим: ${buffered.mode}` : '') +
    (buffered.truncated ? '; текст показан частично.' : '.');
}
function renderVariables(stack) {
  const lines = [];
  for (const frame of stack || []) {
    lines.push(`${frame.functionName} (${frame.id})`);
    for (const variable of frame.variables || []) {
      const value = variable.value;
      const scalar = value?.value;
      const text = value?.availability !== 'available' ? `NaN / недоступно: ${value?.reason || 'not-captured'}` :
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
function applyInput(input) {
  inputOpen = input?.submitted?.closeAfterWrite === false;
  $('input-status').textContent = `${inputOpen ? 'stdin открыт' : 'stdin закрыт / EOF запрошен'}. ` +
    `Доставлено ${input?.deliveredBytes ?? 0} байт. Это не счётчик прочитанного cin.`;
}
function applyState(state) {
  phase = state?.phase || null;
  $('state').textContent = pretty(state);
  if (state?.live) { stop = state.live.stop; branchId = state.live.point.branchId; }
  if (phase === 'terminated' || phase === 'failed') { stop = null; inputOpen = false; }
}
function applyObservation(observation) {
  if (!observation) return;
  stop = observation.stop;
  branchId = observation.point.branchId;
  $('observation').textContent = pretty(observation);
  $('stdout').textContent = observation.stdout?.text || '(empty)';
  $('stderr').textContent = observation.stderr?.text || '(empty)';
  $('stdout-check').textContent = `Получено из stdout: ${observation.stdout?.totalBytes ?? 0} байт.`;
  applyInput(observation.input);
  renderBuffer(observation.stdout);
  renderVariables(observation.stack);
}
function finishPending(payload) {
  pendingRequests.delete(payload.requestId);
  finishedRequests.set(payload.requestId, payload);
  if (finishedRequests.size > 256) finishedRequests.delete(finishedRequests.keys().next().value);
  if (payload.error) $('status').textContent = `${payload.error.code}: ${payload.error.message}`;
  else $('status').textContent = `Команда ${payload.requestId}: ${payload.outcome}.`;
}
function applyEvent(frame) {
  if (!frame.payload) {
    if (frame.kind === 'harnessExit' || frame.kind === 'harnessError') {
      session = null; stop = null; phase = null; inputOpen = false;
      artifact = null; builtSource = null; pendingRequests.clear();
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
  if (payload.kind === 'input') applyInput(payload.input);
  if (payload.kind === 'commandFinished') finishPending(payload);
}
function applyResult(frame) {
  const result = frame.result;
  if (result?.kind === 'state') {
    if (result.observation) applyObservation(result.observation);
    applyState(result.state);
    $('state-status').textContent = `Обновлено Get state в ${new Date().toLocaleTimeString()}. Новая остановка не создаётся.`;
  }
  if (result?.kind === 'history') renderHistory(result);
  if (result?.kind === 'input') applyInput(result.input);
}
async function pollEvents() {
  try {
    const response = await fetch(`/api/events?after=${eventCursor}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const value = await response.json();
    if (value.gap) {
      addLog('event-gap', {after: eventCursor, nextCursor: value.nextCursor});
      $('status').textContent = 'Часть событий вытеснена. Запросите Get state; исход пропущенных команд неизвестен.';
    }
    eventCursor = value.nextCursor ?? eventCursor;
    // A refreshed tab can attach to the existing session; an active launch is
    // adopted only by its response, with early events buffered until then.
    if (!session && !launchEvents && value.session) session = value.session;
    for (const item of value.events || []) { addLog('event', item); applyEvent(item); }
    $('connection').textContent = value.connected ? 'connected' : 'не подключено';
    $('connection').classList[value.connected ? 'add' : 'remove']('ok');
    if (!value.connected && session && !launchEvents) {
      session = null; stop = null; phase = null; inputOpen = false;
      artifact = null; builtSource = null; pendingRequests.clear();
    }
  } catch (error) { $('status').textContent = `event polling: ${error.message}`; }
  finally { refreshControls(); }
}
function refresh() {
  if (!refreshPromise) refreshPromise = pollEvents().finally(() => { refreshPromise = null; });
  return refreshPromise;
}
function enabled(kind) {
  const alive = Boolean(session && (phase === 'stopped' || phase === 'running' || executing()));
  const exclusive = sending.has('build') || sending.has('launch');
  if (sending.has(kind) || exclusive) return false;
  if (kind === 'build') return !alive;
  if (kind === 'launch') return !alive && Boolean(artifact && builtSource === $('source').value);
  if (executionKinds.includes(kind)) return alive && phase === 'stopped' && Boolean(stop) && !executing() && pendingRequests.size === 0;
  if (controlKinds.includes(kind)) return alive && ![...pendingRequests.values()].includes(kind);
  if (inputKinds.includes(kind)) return alive && inputOpen && !inputKinds.some(item => sending.has(item));
  return Boolean(session) && !executing() && pendingRequests.size === 0;
}
function refreshControls() {
  for (const button of document.querySelectorAll('button[data-action]')) button.disabled = !enabled(button.dataset.action);
  renderBuildStatus();
}
async function action(kind) {
  if (!enabled(kind)) {
    if (kind === 'launch') $('status').textContent = 'Для Launch нужна успешная сборка текущего исходника и завершённый предыдущий запуск.';
    return;
  }
  sending.add(kind);
  refreshControls();
  const sourceText = $('source').value;
  let liveText = '';
  try {
    let command;
    if (kind === 'build') {
      artifact = null; builtSource = null;
      const hash = await digest(sourceText);
      command = {kind: 'build', source: {id: `source-${hash}`, documents: [{documentId: 'main.cpp', revisionId: `revision-${hash}`, path: 'main.cpp', text: sourceText, sha256: hash}]}, configuration: {revisionId: 'config-revision-1', compiler: 'clang++', flags: ['-std=c++20', '-g', '-O0'], outputDirectory: '.phantom/harness-build'}, architecture: 'x86_64'};
    } else if (kind === 'launch') {
      command = {kind, buildId: artifact.id, input: {id: `input-${++inputCounter}`, text: $('input').value, encoding: 'utf-8', closeAfterWrite: $('input-eof').checked}, argv: parseLines($('argv').value), environment: environment(), stopAtEntry: true};
      launchEvents = [];
    } else if (kind === 'history') command = {kind: 'listHistory', branchId, afterOrdinal: null, limit: 100};
    else if (kind === 'state') command = {kind: 'getState'};
    else if (kind === 'step') command = {kind, stepKind: 'over'};
    else if (kind === 'appendInput') {
      liveText = $('stdin-live').value;
      const text = liveText + ($('input-newline').checked ? '\n' : '');
      if (!text) throw new Error('Введите текст или включите перевод строки. EOF отправляется отдельной кнопкой.');
      command = {kind, id: `input-${++inputCounter}`, text};
    } else command = {kind};
    // Pause/Stop target the live session even if the last stop token has
    // changed while execution was pending. Source steps require that token.
    const value = await post('/api/request', {
      command,
      session,
      ...((executionKinds.includes(kind) || inputKinds.includes(kind)) ? {expectedStop: stop} : {}),
    });
    if (kind === 'build') {
      artifact = value.result.artifact;
      builtSource = artifact ? sourceText : null;
      $('stderr').textContent = value.result.stderr || '(empty)';
      $('status').textContent = value.result.success ? 'Build: успешно.' : 'Build: ошибка компиляции. Launch недоступен.';
    } else if (value.result?.kind === 'launchAccepted') {
      session = value.result.session; stop = null; phase = null; lastSequence = 0;
      pendingRequests.clear(); finishedRequests.clear();
      $('history').textContent = 'Новый запуск. Нажмите History для списка остановок.';
      const early = launchEvents; launchEvents = null;
      for (const event of early) applyEvent(event);
    } else {
      applyResult(value);
      if (value.result?.kind === 'accepted' && !finishedRequests.has(value.requestId)) pendingRequests.set(value.requestId, kind);
      if (kind === 'appendInput' && $('stdin-live').value === liveText) $('stdin-live').value = '';
    }
    await refresh();
    if (kind !== 'build' && !finishedRequests.has(value.requestId)) {
      $('status').textContent = kind === 'history' ? `History: получено ${value.result.items?.length ?? 0} остановок.` :
        kind === 'state' ? 'Get state: состояние и последний снимок обновлены.' :
        value.result?.kind === 'accepted' ? `${kind}: выполняется; доступны Pause и Stop.` : `${kind}: готово.`;
    }
  } catch (error) { $('status').textContent = error.message; }
  finally { if (kind === 'launch') launchEvents = null; sending.delete(kind); refreshControls(); }
}
document.querySelectorAll('button[data-action]').forEach(button => button.addEventListener('click', () => action(button.dataset.action)));
$('source').addEventListener('input', refreshControls);
$('source').addEventListener('input', updateTheoreticalCout);
$('reset').addEventListener('click', async () => {
  try { await post('/api/reset'); location.reload(); }
  catch (error) { $('status').textContent = error.message; }
});
setInterval(refresh, 500);
refreshControls();
updateTheoreticalCout();
refresh();
