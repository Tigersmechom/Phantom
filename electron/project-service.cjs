'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');

const DEFAULT_CONFIG = Object.freeze({ version: 1, compiler: 'clang++', flags: ['-std=c++20', '-g', '-O0', '-Wall', '-Wextra'], outputDirectory: '.frame/build' });
const SOURCE_LIMIT = 8 * 1024 * 1024;
const OUTPUT_LIMIT = 4 * 1024 * 1024;

function assertText(value, label, limit = SOURCE_LIMIT) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > limit || value.includes('\0')) throw new Error(`${label}: недопустимое значение.`);
  return value;
}
function validateBuildConfig(value) {
  if (!value || typeof value !== 'object' || value.version !== 1) throw new Error('Версия конфигурации сборки должна быть 1.');
  const compiler = assertText(value.compiler, 'Компилятор', 4096).trim();
  const outputDirectory = assertText(value.outputDirectory, 'Каталог сборки', 4096).trim();
  if (!compiler || !outputDirectory) throw new Error('Укажите компилятор и каталог сборки.');
  if (!Array.isArray(value.flags) || value.flags.length > 256) throw new Error('flags должен быть массивом аргументов компилятора.');
  const flags = value.flags.map(flag => assertText(flag, 'Аргумент компилятора', 16384));
  return { version: 1, compiler, flags, outputDirectory };
}
function within(root, target) { const relative = path.relative(root, target); return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)); }
async function ensureWithin(root, target) {
  if (!within(root, target)) throw new Error('Путь должен находиться внутри открытого проекта.');
  let current = target;
  for (;;) {
    try { if (!within(root, await fs.realpath(current))) throw new Error('Символическая ссылка ведёт за пределы проекта.'); break; }
    catch (error) { if (error.code !== 'ENOENT') throw error; const parent = path.dirname(current); if (parent === current) throw error; current = parent; }
  }
}
function signalProcess(child, signal) {
  try { if (process.platform !== 'win32') process.kill(-child.pid, signal); else child.kill(signal); } catch { /* Process already exited. */ }
}
function terminate(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null || child.__frameTerminating) return;
  child.__frameTerminating = true;
  signalProcess(child, 'SIGTERM');
  const timer = setTimeout(() => signalProcess(child, 'SIGKILL'), 1200);
  child.__frameKillTimer = timer;
  timer.unref();
}

class ProjectService {
  constructor(root, { activeFile = null, onPersist = async () => {} } = {}) {
    this.root = root; this.activeFile = activeFile; this.onPersist = onPersist;
    this.artifact = null; this.buildProcess = null; this.runProcess = null; this.generation = 0; this.building = false;
  }
  get configPath() { return path.join(this.root, '.frame', 'build.json'); }
  async initialize() {
    this.root = await fs.realpath(this.root);
    if (!(await fs.stat(this.root)).isDirectory()) throw new Error('Рабочая папка не является каталогом.');
    if (this.activeFile) {
      this.activeFile = path.resolve(this.activeFile);
      try { await ensureWithin(this.root, this.activeFile); await this.readDocument(this.activeFile); }
      catch { this.activeFile = null; }
    }
    if (!this.activeFile) {
      const names = (await fs.readdir(this.root)).filter(name => /\.(cpp|cc|cxx)$/i.test(name)).sort();
      for (const name of ['examples/prefix_sum.cpp', 'main.cpp', ...names]) {
        const candidate = path.resolve(this.root, name);
        try { await ensureWithin(this.root, candidate); await this.readDocument(candidate); this.activeFile = candidate; break; } catch { /* Try next candidate. */ }
      }
    }
    await this.persist();
    return this.getWorkspace();
  }
  async persist() { await this.onPersist({ workspace: this.root, activeFile: this.activeFile }); }
  async readDocument(file = this.activeFile) {
    if (!file) return null;
    const info = await fs.stat(file);
    if (!info.isFile() || info.size > SOURCE_LIMIT) throw new Error('Исходный файл слишком большой или недоступен.');
    return { path: file, name: path.basename(file), content: await fs.readFile(file, 'utf8') };
  }
  async readBuildConfig() {
    await ensureWithin(this.root, this.configPath);
    try {
      const info = await fs.stat(this.configPath);
      if (info.size > 128 * 1024) throw new Error('Файл конфигурации слишком большой.');
      return validateBuildConfig(JSON.parse(await fs.readFile(this.configPath, 'utf8')));
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error(`Не удалось прочитать ${this.configPath}: ${error.message}`);
      return this.saveBuildConfig(DEFAULT_CONFIG);
    }
  }
  async getWorkspace() {
    let config, configError;
    try { config = await this.readBuildConfig(); } catch (error) { config = { ...DEFAULT_CONFIG, flags: [...DEFAULT_CONFIG.flags] }; configError = error.message; }
    return { root: this.root, name: path.basename(this.root), configPath: this.configPath, config, ...(configError ? { configError } : {}), document: await this.readDocument() };
  }
  async changeWorkspace(root, activeFile = null) {
    const nextRoot = await fs.realpath(root);
    if (!(await fs.stat(nextRoot)).isDirectory()) throw new Error('Рабочая папка не является каталогом.');
    this.dispose(); this.generation++; this.artifact = null;
    this.root = nextRoot; this.activeFile = activeFile;
    return this.initialize();
  }
  async openFile(file) {
    const resolved = await fs.realpath(file);
    if (!/\.(cpp|cc|cxx)$/i.test(resolved)) throw new Error('Выберите исходный файл C++.');
    if (!within(this.root, resolved)) return this.changeWorkspace(path.dirname(resolved), resolved);
    this.artifact = null; this.activeFile = resolved;
    await this.persist(); return this.getWorkspace();
  }
  async saveDocument(request) {
    if (!request || typeof request !== 'object') throw new Error('Ожидался исходный код.');
    const content = assertText(request.content, 'Исходный код');
    const file = request.path ? path.resolve(this.root, assertText(request.path, 'Путь', 4096)) : this.activeFile || path.join(this.root, 'main.cpp');
    if (!/\.(cpp|cc|cxx)$/i.test(file)) throw new Error('Исходник должен иметь расширение .cpp, .cc или .cxx.');
    await ensureWithin(this.root, file);
    await fs.mkdir(path.dirname(file), { recursive: true });
    const previous = await fs.readFile(file, 'utf8').catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (previous !== content) { await fs.writeFile(file, content, 'utf8'); this.artifact = null; }
    this.activeFile = file; await this.persist();
    return { path: file, name: path.basename(file), content };
  }
  async saveBuildConfig(config) {
    const valid = validateBuildConfig(config);
    const output = path.resolve(this.root, valid.outputDirectory);
    await ensureWithin(this.root, output);
    await ensureWithin(this.root, this.configPath);
    await fs.mkdir(path.dirname(this.configPath), { recursive: true });
    await fs.writeFile(this.configPath, JSON.stringify(valid, null, 2) + '\n', 'utf8');
    this.artifact = null; return valid;
  }
  collect(command, args, { stdin, field, timeout = 120000 } = {}) {
    return new Promise(resolve => {
      let child;
      let stdout = '', stderr = '', bytes = 0, truncated = false, timedOut = false, settled = false;
      const append = (stream, chunk) => {
        const buffer = Buffer.from(chunk);
        const remaining = Math.max(0, OUTPUT_LIMIT - bytes);
        const fragment = buffer.subarray(0, remaining).toString('utf8');
        if (stream === 'stdout') stdout += fragment; else stderr += fragment;
        bytes += buffer.length;
        if (bytes > OUTPUT_LIMIT && !truncated) { truncated = true; terminate(child); }
      };
      const finish = (exitCode, signal) => {
        if (settled) return; settled = true; clearTimeout(timer);
        if (child) { child.__frameClosed = true; clearTimeout(child.__frameKillTimer); if (child.__frameTerminating) signalProcess(child, 'SIGKILL'); }
        if (this[field] === child) this[field] = null;
        if (truncated) stderr += '\n[phantom: процесс остановлен после 4 МиБ вывода; вывод обрезан.]\n';
        if (timedOut) stderr += '\n[phantom: процесс остановлен по истечении 120 секунд.]\n';
        resolve({ stdout, stderr, exitCode, truncated, ...(signal ? { signal } : {}), ...(timedOut ? { timedOut } : {}) });
      };
      let timer;
      try {
        const env = { ...process.env, PATH: `${process.env.PATH || '/usr/bin:/bin:/usr/sbin:/sbin'}:/opt/homebrew/bin:/usr/local/bin` };
        child = spawn(command, args, { cwd: this.root, env, shell: false, detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'] });
        this[field] = child;
        child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
        child.stdout.on('data', chunk => append('stdout', chunk));
        child.stderr.on('data', chunk => append('stderr', chunk));
        child.once('error', error => { stderr += error.message; finish(null); });
        child.once('close', (code, signal) => finish(code, signal));
        child.stdin.on('error', () => {});
        child.stdin.end(stdin || '');
        timer = setTimeout(() => { timedOut = true; terminate(child); }, timeout); timer.unref();
      } catch (error) { stderr += error.message; finish(null); }
    });
  }
  async compile(request) {
    if (this.building || this.buildProcess || this.runProcess) throw new Error('Сначала завершите текущую сборку или программу.');
    if (!request || !['arm64', 'x86_64'].includes(request.architecture)) throw new Error('Неизвестная архитектура сборки.');
    this.building = true;
    try {
    this.artifact = null;
    const generation = this.generation;
    const document = await this.saveDocument({ content: request.content });
    const config = await this.readBuildConfig();
    const outputDirectory = path.resolve(this.root, config.outputDirectory);
    await ensureWithin(this.root, outputDirectory); await fs.mkdir(outputDirectory, { recursive: true });
    const stem = path.basename(document.path, path.extname(document.path));
    const outputPath = path.join(outputDirectory, `${stem}-${request.architecture}`);
    await ensureWithin(this.root, outputPath);
    if (generation !== this.generation) throw new Error('Проект изменился во время подготовки сборки.');
    const compiler = config.compiler.includes('/') ? path.resolve(this.root, config.compiler) : config.compiler;
    const args = [...config.flags, '-arch', request.architecture, document.path, '-o', outputPath];
    const result = await this.collect(compiler, args, { field: 'buildProcess' });
    const success = result.exitCode === 0 && !result.truncated && generation === this.generation;
    if (success) this.artifact = { outputPath, generation };
    return { ...result, success, command: [compiler, ...args], outputPath };
    } finally { this.building = false; }
  }
  async execute(request) {
    if (this.building || this.buildProcess || this.runProcess) throw new Error('Уже выполняется сборка или программа.');
    if (!this.artifact || this.artifact.generation !== this.generation) throw new Error('Сначала успешно соберите текущий исходный файл.');
    const stdin = assertText(request?.stdin, 'Входные данные');
    return this.collect(this.artifact.outputPath, [], { field: 'runProcess', stdin });
  }
  stopExecution() { terminate(this.runProcess); }
  dispose() { terminate(this.runProcess); terminate(this.buildProcess); this.artifact = null; }
  async shutdown() {
    const children = [this.runProcess, this.buildProcess].filter(Boolean);
    this.dispose();
    await Promise.all(children.map(child => new Promise(resolve => {
      if (child.__frameClosed) return resolve();
      const timer = setTimeout(() => { signalProcess(child, 'SIGKILL'); resolve(); }, 1500);
      child.once('close', () => { clearTimeout(timer); resolve(); });
    })));
  }
}
module.exports = { ProjectService, DEFAULT_CONFIG, validateBuildConfig, within };
