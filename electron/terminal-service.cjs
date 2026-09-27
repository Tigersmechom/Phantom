'use strict';
const { randomUUID } = require('node:crypto');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const pty = require('node-pty');
const HISTORY_LIMIT = 1024 * 1024;
function size(value, fallback, maximum) { return Number.isInteger(value) ? Math.min(maximum, Math.max(2, value)) : fallback; }
function descendants(pid) {
  if (process.platform === 'win32') return [];
  try {
    const rows = execFileSync('/bin/ps', ['-axo', 'pid=,ppid='], { encoding: 'utf8', timeout: 1500 }).trim().split('\n').map(line => line.trim().split(/\s+/).map(Number));
    const found = new Set([pid]);
    for (let changed = true; changed;) {
      changed = false;
      for (const [child, parent] of rows) if (found.has(parent) && !found.has(child)) { found.add(child); changed = true; }
    }
    found.delete(pid); return [...found].reverse();
  } catch { return []; }
}
function signal(pid, value) { try { process.kill(pid, value); } catch { /* Already exited. */ } }

class TerminalService {
  constructor({ getCwd, send }) { this.getCwd = getCwd; this.send = send; this.session = null; this.operation = Promise.resolve(); }
  enqueue(action) { const result = this.operation.then(action, action); this.operation = result.catch(() => {}); return result; }
  open(dimensions = {}) { return this.enqueue(() => this.createOrReuse(dimensions)); }
  createOrReuse(dimensions = {}) {
    const cols = size(dimensions.cols, 100, 1000), rows = size(dimensions.rows, 24, 500);
    if (!this.session || this.session.exitCode !== undefined) {
      const cwd = this.getCwd();
      const shell = process.env.SHELL || os.userInfo().shell || '/bin/zsh';
      const processPty = pty.spawn(shell, ['-l', '-i'], { name: 'xterm-256color', cols, rows, cwd, env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor', LANG: process.env.LANG || 'en_US.UTF-8' } });
      const session = { id: randomUUID(), cwd, history: '', sequence: 0, process: processPty };
      this.session = session;
      processPty.onData(data => {
        session.history = (session.history + data).slice(-HISTORY_LIMIT);
        this.send('terminal:data', { id: session.id, data, sequence: ++session.sequence });
      });
      processPty.onExit(({ exitCode, signal }) => {
        session.exitCode = exitCode;
        session.finishClosing?.();
        this.send('terminal:exit', { id: session.id, exitCode, signal });
      });
    } else { this.session.process.resize(cols, rows); }
    const { id, cwd, history, sequence, exitCode } = this.session;
    return { id, cwd, history, sequence, ...(exitCode === undefined ? {} : { exitCode }) };
  }
  owned(id) { if (!this.session || typeof id !== 'string' || this.session.id !== id || this.session.exitCode !== undefined) throw new Error('Терминальная сессия уже завершена.'); return this.session; }
  write(request) {
    if (!request || typeof request.data !== 'string' || Buffer.byteLength(request.data) > 1024 * 1024) throw new Error('Недопустимые данные терминала.');
    this.owned(request.id).process.write(request.data);
  }
  resize(request) { const session = this.owned(request?.id); session.process.resize(size(request.cols, 100, 1000), size(request.rows, 24, 500)); }
  async stopCurrent() {
    const previous = this.session; this.session = null;
    if (!previous || previous.exitCode !== undefined) return;
    const children = descendants(previous.process.pid);
    await new Promise(resolve => {
      let finished = false;
      const finish = () => {
        if (finished) return; finished = true;
        clearTimeout(timer);
        // A login shell can exit before jobs that ignore SIGHUP. Clean up the
        // captured child tree too, before exposing the replacement session.
        for (const pid of children) signal(pid, 'SIGKILL');
        if (previous.exitCode === undefined) { try { previous.process.kill('SIGKILL'); } catch { /* Already exited. */ } }
        resolve();
      };
      const timer = setTimeout(finish, 1200);
      previous.finishClosing = finish;
      for (const pid of children) signal(pid, 'SIGHUP');
      try { previous.process.kill('SIGHUP'); } catch { finish(); }
    });
  }
  reset() { return this.enqueue(() => this.stopCurrent()); }
  restart(dimensions = {}) { return this.enqueue(async () => { await this.stopCurrent(); return this.createOrReuse(dimensions); }); }
  dispose() { void this.reset(); }
  shutdown() { return this.reset(); }
}
module.exports = { TerminalService };
