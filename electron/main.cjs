'use strict';
const { app, BrowserWindow, Menu, dialog, ipcMain, shell } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { fileURLToPath } = require('node:url');
const { ProjectService } = require('./project-service.cjs');
const { TerminalService } = require('./terminal-service.cjs');
const { migrateLegacyProfile } = require('./profile-service.cjs');

app.setName('phantom');
const userDataOverride = app.commandLine.getSwitchValue('user-data-dir');
if (userDataOverride) app.setPath('userData', path.resolve(userDataOverride));
else {
  const current = path.join(app.getPath('appData'), 'phantom');
  migrateLegacyProfile(path.join(app.getPath('appData'), 'FRAME'), current);
  app.setPath('userData', current);
}
let window = null, project = null, terminal = null, quitAllowed = false, leaveAction = null;
let documentState = { dirty: false, content: '' };
const productionEntry = path.resolve(__dirname, '..', 'dist', 'index.html');
const devUrl = process.env.FRAME_DEV_URL;
if (devUrl) {
  const url = new URL(devUrl);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.username || url.password) throw new Error('FRAME_DEV_URL должен указывать на локальный HTTP-сервер.');
}
function appUrl(url) {
  try {
    const parsed = new URL(url);
    if (devUrl) return parsed.origin === new URL(devUrl).origin;
    return parsed.protocol === 'file:' && fileURLToPath(parsed) === productionEntry;
  } catch { return false; }
}
function send(channel, value) { if (window && !window.isDestroyed()) window.webContents.send(channel, value); }
async function broadcastWorkspace(state, resetTerminal = false) {
  if (resetTerminal) await terminal.reset();
  documentState = { dirty: false, content: state.document?.content || '' };
  send('frame:workspace', state); return state;
}
async function confirmLeave(action) {
  if (!documentState.dirty || !window || window.isDestroyed()) return true;
  const snapshot = documentState;
  const choice = await dialog.showMessageBox(window, {
    type: 'question', title: 'Несохранённый исходный код',
    message: 'Сохранить изменения перед ' + (action === 'reload' ? 'перезагрузкой окна?' : 'закрытием phantom?'),
    detail: project.activeFile ? path.basename(project.activeFile) : 'main.cpp',
    buttons: ['Сохранить', 'Не сохранять', 'Отмена'], defaultId: 0, cancelId: 2, noLink: true,
  });
  if (choice.response === 2) return false;
  if (choice.response === 0) {
    try { await project.saveDocument({ content: snapshot.content }); }
    catch (error) { dialog.showErrorBox('Не удалось сохранить исходник', error.message); return false; }
  }
  if (documentState.content !== snapshot.content && documentState.dirty) return confirmLeave(action);
  documentState = { dirty: false, content: snapshot.content };
  return true;
}
function requestLeave(action) {
  if (leaveAction) return leaveAction;
  leaveAction = (async () => {
    if (!await confirmLeave(action)) return;
    if (action === 'reload') { window?.webContents.reload(); return; }
    await Promise.all([terminal?.shutdown(), project?.shutdown()]);
    quitAllowed = true; app.quit();
  })().catch(error => { dialog.showErrorBox('phantom', error.message); }).finally(() => { leaveAction = null; });
  return leaveAction;
}
const methods = {
  getWorkspace: () => project.getWorkspace(),
  saveDocument: async request => {
    const saved = await project.saveDocument(request);
    if (documentState.content === saved.content) documentState.dirty = false;
    return saved;
  },
  updateDocumentState: request => {
    if (!request || typeof request.dirty !== 'boolean' || typeof request.content !== 'string' || Buffer.byteLength(request.content) > 8 * 1024 * 1024) throw new Error('Недопустимое состояние документа.');
    documentState = { dirty: request.dirty, content: request.content };
  },
  saveBuildConfig: config => project.saveBuildConfig(config),
  compile: async request => {
    const result = await project.compile(request);
    if (documentState.content === request.content) documentState.dirty = false;
    return result;
  },
  execute: request => project.execute(request),
  stopExecution: () => project.stopExecution(),
  revealBuildConfig: async () => { await project.readBuildConfig(); shell.showItemInFolder(project.configPath); },
  openFile: async () => {
    const result = await dialog.showOpenDialog(window, { title: 'Открыть исходный файл C++', defaultPath: project.root, properties: ['openFile'], filters: [{ name: 'C++', extensions: ['cpp', 'cc', 'cxx'] }] });
    if (result.canceled || !result.filePaths[0]) return null;
    const previous = project.root;
    return broadcastWorkspace(await project.openFile(result.filePaths[0]), previous !== project.root);
  },
  chooseWorkspace: async () => {
    const result = await dialog.showOpenDialog(window, { title: 'Открыть папку проекта', defaultPath: project.root, properties: ['openDirectory', 'createDirectory'] });
    if (result.canceled || !result.filePaths[0]) return null;
    const previous = project.root;
    return broadcastWorkspace(await project.changeWorkspace(result.filePaths[0]), previous !== project.root);
  },
  'terminal.open': dimensions => terminal.open(dimensions),
  'terminal.restart': dimensions => terminal.restart(dimensions),
  'terminal.write': request => terminal.write(request),
  'terminal.resize': request => terminal.resize(request),
};
ipcMain.handle('frame:request', (event, method, argument) => {
  if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || !appUrl(event.senderFrame.url) || !Object.hasOwn(methods, method)) throw new Error('Недоступный запрос приложения.');
  return methods[method](argument);
});

async function start() {
  const statePath = path.join(app.getPath('userData'), 'workspace.json');
  let saved = {};
  try { saved = JSON.parse(await fs.readFile(statePath, 'utf8')); } catch { /* First launch. */ }
  const argument = process.argv.find(value => value.startsWith('--workspace='));
  const marker = process.argv.indexOf('--workspace');
  const explicit = argument ? argument.slice('--workspace='.length) : marker >= 0 ? process.argv[marker + 1] : process.env.FRAME_WORKSPACE;
  let root = explicit || saved.workspace;
  if (!explicit && root) { try { if (!(await fs.stat(root)).isDirectory()) root = null; } catch { root = null; } }
  if (!root) { const defaultRoot = '/Users/123/Desktop/NEW_IDE'; try { await fs.access(defaultRoot); root = defaultRoot; } catch { root = os.homedir(); } }
  project = new ProjectService(path.resolve(root), {
    activeFile: !explicit || path.resolve(explicit) === saved.workspace ? saved.activeFile : null,
    onPersist: async state => { await fs.mkdir(path.dirname(statePath), { recursive: true }); await fs.writeFile(statePath, JSON.stringify(state, null, 2) + '\n', 'utf8'); },
  });
  await project.initialize();
  terminal = new TerminalService({ getCwd: () => project.root, send });
  window = new BrowserWindow({ width: 1440, height: 940, minWidth: 900, minHeight: 620, title: 'phantom', backgroundColor: '#080a0f', titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 14, y: 16 }, webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => { if (!appUrl(url)) event.preventDefault(); });
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  window.webContents.on('render-process-gone', () => { terminal.dispose(); project.dispose(); });
  window.on('close', event => { if (!quitAllowed) { event.preventDefault(); void requestLeave('close'); } });
  window.on('closed', () => { terminal.dispose(); project.dispose(); window = null; });
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'phantom', submenu: [{ role: 'about' }, { type: 'separator' }, { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' }, { type: 'separator' }, { role: 'quit' }] },
    { label: 'Правка', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: 'Вид', submenu: [{ id: 'frame-reload', label: 'Перезагрузить окно', accelerator: 'CmdOrCtrl+R', click: () => { void requestLeave('reload'); } }, { role: 'toggleDevTools' }, { type: 'separator' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }] },
  ]));
  if (devUrl) await window.loadURL(devUrl); else await window.loadFile(productionEntry);
}
app.whenReady().then(start).catch(error => { dialog.showErrorBox('phantom не удалось запустить', error.message); app.quit(); });
app.on('window-all-closed', () => app.quit());
app.on('before-quit', event => {
  if (quitAllowed) return;
  event.preventDefault(); void requestLeave('close');
});
