import { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm, type ITheme } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { native, type TerminalData } from './native';
import '@xterm/xterm/css/xterm.css';
import './terminal.css';

type Props = { open: boolean; theme: 'dark' | 'light'; cwd?: string; resetKey?: number; onClose?: () => void };
const themes: Record<Props['theme'], ITheme> = {
  dark: { background: '#0d1016', foreground: '#dce0e7', cursor: '#bde8dd', cursorAccent: '#0d1016', selectionBackground: '#55647e70', black: '#20242d', red: '#fc6a5d', green: '#67b7a4', yellow: '#d0bf69', blue: '#6ca6ec', magenta: '#fc5fa3', cyan: '#5dd8ff', white: '#e6e8ed', brightBlack: '#7a8794', brightRed: '#ff938a', brightGreen: '#9ef1dd', brightYellow: '#eadfa0', brightBlue: '#99c4ff', brightMagenta: '#fba3cb', brightCyan: '#a2eaff', brightWhite: '#ffffff' },
  light: { background: '#f4f3ef', foreground: '#2f3440', cursor: '#326e74', cursorAccent: '#f4f3ef', selectionBackground: '#899cad55', black: '#2e3440', red: '#c41a16', green: '#316d74', yellow: '#826710', blue: '#2865a5', magenta: '#9b2393', cyan: '#006e82', white: '#b8b8b3', brightBlack: '#6c757e', brightRed: '#db4b3f', brightGreen: '#367c58', brightYellow: '#967b0b', brightBlue: '#2672c2', brightMagenta: '#b62da6', brightCyan: '#0c819a', brightWhite: '#ffffff' },
};

export default function TerminalPanel({ open, theme, cwd, resetKey = 0 }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const controller = useRef<{ term: XTerm; fit: FitAddon; connect: () => Promise<void>; restart: () => Promise<void>; resize: () => void } | null>(null);
  const previousResetKey = useRef(resetKey);
  const shown = useRef(open); shown.current = open;
  const requestedCwd = useRef(cwd); requestedCwd.current = cwd;
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    if (!native || !host.current) return;
    const api = native.terminal;
    const term = new XTerm({ theme: themes[theme], fontFamily: '"Monaspace Neon", "SFMono-Regular", Menlo, monospace', fontSize: 13, lineHeight: 1.22, cursorBlink: true, cursorStyle: 'bar', scrollback: 10000, allowTransparency: false, macOptionIsMeta: true });
    const fit = new FitAddon(); term.loadAddon(fit); term.open(host.current);
    let disposed = false, id: string | null = null, sequence = 0, connectedCwd = '', pendingInput = '', exited = false, generation = 0;
    let connecting: Promise<void> | null = null;
    let pending: TerminalData[] = [];
    const display = (event: TerminalData) => {
      if (event.id === id && event.sequence > sequence) { sequence = event.sequence; term.write(event.data); }
    };
    const fail = (reason: unknown) => { if (!disposed) setError(reason instanceof Error ? reason.message : String(reason)); };
    const resize = () => {
      if (disposed || !shown.current || !host.current?.clientWidth || !host.current?.clientHeight) return;
      fit.fit();
      if (id) void api.resize({ id, cols: term.cols, rows: term.rows }).catch(fail);
    };
    const connect = (restart = false) => {
      if (connecting && !restart) return connecting;
      if (!restart && id && (!requestedCwd.current || connectedCwd === requestedCwd.current)) {
        resize(); if (shown.current) term.focus(); return Promise.resolve();
      }
      setError('');
      resize(); pending = []; id = null; exited = false; setConnected(false);
      if (restart) { pendingInput = ''; term.reset(); }
      const requestGeneration = ++generation;
      connecting = (restart ? api.restart : api.open)({ cols: term.cols, rows: term.rows }).then(snapshot => {
        if (disposed || requestGeneration !== generation) return;
        if (id !== snapshot.id) { term.reset(); term.write(snapshot.history); }
        id = snapshot.id; connectedCwd = snapshot.cwd; sequence = snapshot.sequence;
        setConnected(true);
        for (const event of pending) display(event);
        pending = [];
        if (pendingInput) { const data = pendingInput; pendingInput = ''; void api.write({ id, data }).catch(fail); }
        if (shown.current) { resize(); term.focus(); }
      }).catch(reason => { if (requestGeneration === generation) fail(reason); }).finally(() => { if (requestGeneration === generation) connecting = null; });
      return connecting;
    };
    const offData = api.onData(event => {
      if (disposed) return;
      if (connecting) pending.push(event); else display(event);
    });
    const offExit = api.onExit(event => {
      if (event.id !== id || disposed) return;
      id = null; exited = true; setConnected(false);
      term.write(`\r\n\x1b[90m[Оболочка завершена: ${event.exitCode}. Enter — новая сессия.]\x1b[0m\r\n`);
    });
    const input = term.onData(data => {
      if (id) void api.write({ id, data }).catch(fail);
      else if (!exited) { pendingInput = (pendingInput + data).slice(-65536); void connect(); }
      else if (data === '\r') void connect();
    });
    term.attachCustomKeyEventHandler(event => !(event.ctrlKey && (event.code === 'Backquote' || event.key === '`')));
    const observer = new ResizeObserver(resize); observer.observe(host.current);
    controller.current = { term, fit, connect, restart: () => connect(true), resize };
    if (shown.current) void connect();
    void document.fonts.ready.then(() => { if (!disposed) resize(); });
    return () => { disposed = true; offData(); offExit(); input.dispose(); observer.disconnect(); term.dispose(); controller.current = null; };
    // The terminal stays alive across visibility/theme/workspace changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => { if (controller.current) controller.current.term.options.theme = themes[theme]; }, [theme]);
  useEffect(() => {
    if (previousResetKey.current === resetKey) return;
    previousResetKey.current = resetKey;
    void controller.current?.restart();
  }, [resetKey]);
  useEffect(() => {
    if (!open) return;
    const frame = requestAnimationFrame(() => { void controller.current?.connect(); });
    return () => cancelAnimationFrame(frame);
  }, [open, cwd]);
  return <div className={`native-terminal native-terminal-${theme}`} hidden={!open} data-testid="native-terminal" data-connected={connected ? 'true' : 'false'}>
    {native ? <>
      <div className="native-terminal-surface" ref={host} />
      {error && <div className="native-terminal-error" role="alert"><span>{error}</span><button onClick={() => void controller.current?.connect()}>Повторить</button></div>}
    </> : <div className="native-terminal-unavailable">Системная оболочка доступна в настольном приложении phantom.</div>}
  </div>;
}
