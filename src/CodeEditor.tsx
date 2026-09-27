import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react';
import { tokenizeLine } from './tokens';
import './editor.css';

export interface CodeEditorProps {
  source: string;
  onChange: (source: string) => void;
  activeLine: number;
  architecture: 'arm64' | 'x86_64';
  depth: boolean;
  font: 'neon' | 'krypton' | 'xcode';
  fontSize: number;
  /** Duration used when the execution marker travels to a new source line. */
  lineTransitionMs?: number;
  /** Declaration lines of primitive globals used by the current expression. */
  globalLines?: number[];
}

type AssemblyPreview = { line: number; x: number; y: number };
type EditorSelection = { start: number; end: number };
type SelectionRect = { line: number; left: number; top: number; width: number; height: number };
const fonts = {
  neon: '"Monaspace Neon", "SFMono-Regular", Consolas, monospace',
  krypton: '"Monaspace Krypton", "SFMono-Regular", Consolas, monospace',
  xcode: '"SFMono-Regular", Menlo, Consolas, monospace',
};

/** UTF-16 offsets match textarea.selectionStart, including surrogate pairs and tabs. */
function textPosition(element: HTMLElement, offset: number): [Node, number] {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let remaining = offset;
  let node = walker.nextNode();
  let last: Node = element;
  while (node) {
    const length = node.textContent?.length ?? 0;
    if (remaining <= length) return [node, remaining];
    remaining -= length;
    last = node;
    node = walker.nextNode();
  }
  return [last, last === element ? 0 : (last.textContent?.length ?? 0)];
}

function assemblyLines(architecture: CodeEditorProps['architecture'], source: string) {
  if (architecture === 'arm64') {
    if (/\b(for|while)\b/.test(source)) return [['ldr', 'w8, [sp, #12]'], ['cmp', 'w8, w9'], ['b.ge', 'L_loop_end'], ['add', 'w8, w8, #1']];
    if (/\breturn\b/.test(source)) return [['mov', 'w0, #0'], ['ldp', 'x29, x30, [sp], #32'], ['ret', '']];
    if (/cout|printf/.test(source)) return [['adrp', 'x0, L_string@PAGE'], ['add', 'x0, x0, L_string@PAGEOFF'], ['bl', '_print_value']];
    return [['ldr', 'w8, [sp, #8]'], ['ldr', 'w9, [sp, #12]'], ['add', 'w8, w8, w9'], ['str', 'w8, [sp, #8]']];
  }
  if (/\b(for|while)\b/.test(source)) return [['mov', 'eax, DWORD PTR [rbp-8]'], ['cmp', 'eax, DWORD PTR [rbp-12]'], ['jge', '.L_loop_end'], ['inc', 'eax']];
  if (/\breturn\b/.test(source)) return [['xor', 'eax, eax'], ['leave', ''], ['ret', '']];
  if (/cout|printf/.test(source)) return [['lea', 'rdi, [rip + .L_string]'], ['mov', 'esi, DWORD PTR [rbp-8]'], ['call', '_print_value']];
  return [['mov', 'eax, DWORD PTR [rbp-8]'], ['add', 'eax, DWORD PTR [rbp-12]'], ['mov', 'DWORD PTR [rbp-8], eax'], ['nop', '']];
}

export default function CodeEditor({ source, onChange, activeLine, architecture, depth, font, fontSize, lineTransitionMs = 300, globalLines = [] }: CodeEditorProps) {
  const input = useRef<HTMLTextAreaElement>(null);
  const codePlane = useRef<HTMLDivElement>(null);
  const highlight = useRef<HTMLPreElement>(null);
  const pointerSelecting = useRef(false);
  const pendingSelection = useRef<{ start: number; end: number; top: number; left: number } | null>(null);
  const hoverTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hoverPosition = useRef({ x: 0, y: 0 });
  const [scroll, setScroll] = useState({ top: 0, left: 0 });
  const [breakpoints, setBreakpoints] = useState<Set<number>>(() => new Set());
  const [preview, setPreview] = useState<AssemblyPreview | null>(null);
  const [focused, setFocused] = useState(false);
  const [selection, setSelection] = useState<EditorSelection>({ start: 0, end: 0 });
  const [selectionRects, setSelectionRects] = useState<SelectionRect[]>([]);
  const [geometryRevision, setGeometryRevision] = useState(0);
  const lines = useMemo(() => source.split('\n'), [source]);
  const tokens = useMemo(() => lines.map(tokenizeLine), [lines]);
  const lineOffsets = useMemo(() => {
    let offset = 0;
    return lines.map(line => { const start = offset; offset += line.length + 1; return start; });
  }, [lines]);
  const lineHeight = fontSize * 1.85;
  const paddingTop = 22;

  const readSelection = useCallback(() => {
    const element = input.current;
    if (!element) return;
    const start = element.selectionStart;
    const end = element.selectionEnd;
    setSelection(previous => previous.start === start && previous.end === end ? previous : { start, end });
  }, []);

  function cancelPreview() {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
    hoverTimer.current = null;
    setPreview(null);
  }

  useEffect(() => () => {
    if (hoverTimer.current) clearTimeout(hoverTimer.current);
  }, []);

  useLayoutEffect(() => {
    const element = input.current;
    const pending = pendingSelection.current;
    if (!element) return;
    if (pending) {
      element.setSelectionRange(pending.start, pending.end);
      element.scrollTop = pending.top;
      element.scrollLeft = pending.left;
      pendingSelection.current = null;
    }
    readSelection();
    setScroll(previous => previous.top === element.scrollTop && previous.left === element.scrollLeft ? previous : { top: element.scrollTop, left: element.scrollLeft });
  }, [source, readSelection]);

  useEffect(() => {
    const element = input.current;
    const plane = codePlane.current;
    if (!element || !plane) return;
    let frame = 0;
    let alive = true;
    const invalidateGeometry = () => { if (alive) setGeometryRevision(value => value + 1); };
    const pointerMove = () => {
      if (!pointerSelecting.current || frame) return;
      frame = requestAnimationFrame(() => { frame = 0; readSelection(); });
    };
    const pointerUp = () => { pointerSelecting.current = false; readSelection(); };
    // React's onSelect can defer updates until mouseup; native selectionchange keeps drag feedback live.
    element.addEventListener('select', readSelection);
    element.addEventListener('selectionchange', readSelection);
    document.addEventListener('selectionchange', readSelection);
    document.addEventListener('pointermove', pointerMove, { passive: true });
    document.addEventListener('pointerup', pointerUp);
    const observer = new ResizeObserver(invalidateGeometry);
    observer.observe(plane);
    document.fonts.addEventListener('loadingdone', invalidateGeometry);
    document.fonts.ready.then(invalidateGeometry);
    return () => {
      alive = false;
      cancelAnimationFrame(frame);
      observer.disconnect();
      element.removeEventListener('select', readSelection);
      element.removeEventListener('selectionchange', readSelection);
      document.removeEventListener('selectionchange', readSelection);
      document.removeEventListener('pointermove', pointerMove);
      document.removeEventListener('pointerup', pointerUp);
      document.fonts.removeEventListener('loadingdone', invalidateGeometry);
    };
  }, [readSelection]);

  useLayoutEffect(() => {
    const plane = codePlane.current;
    const element = input.current;
    const pre = highlight.current;
    if (!plane || !element || !pre) return;
    const planeBounds = plane.getBoundingClientRect();
    const lineElements = pre.querySelectorAll<HTMLElement>('.editor-source-line');
    const rectangles: SelectionRect[] = [];
    if (selection.end > selection.start) {
      for (let index = 0; index < lines.length; index++) {
        const lineStart = lineOffsets[index];
        const lineEnd = lineStart + lines[index].length;
        const start = Math.max(selection.start, lineStart);
        const end = Math.min(selection.end, lineEnd);
        const includesNewline = index < lines.length - 1 && selection.start <= lineEnd && selection.end > lineEnd;
        if (end <= start && !includesNewline) continue;
        const lineElement = lineElements[index];
        const content = lineElement.querySelector<HTMLElement>('.editor-line-content');
        if (!content) continue;
        const row = lineElement.getBoundingClientRect();
        if (row.bottom < planeBounds.top || row.top > planeBounds.bottom) continue;
        const range = document.createRange();
        const [startNode, startOffset] = textPosition(content, Math.min(lines[index].length, Math.max(0, start - lineStart)));
        const [endNode, endOffset] = textPosition(content, Math.max(0, end - lineStart));
        range.setStart(startNode, startOffset);
        range.setEnd(endNode, endOffset);
        const fragments = Array.from(range.getClientRects());
        // Range coordinates are measured on the actual coloured glyphs, never estimated from character widths.
        const left = (fragments.length ? Math.min(...fragments.map(rect => rect.left)) : content.getBoundingClientRect().left) - planeBounds.left;
        const measuredRight = (fragments.length ? Math.max(...fragments.map(rect => rect.right)) : content.getBoundingClientRect().right) - planeBounds.left;
        const right = includesNewline ? Math.max(measuredRight, element.clientWidth) : measuredRight;
        if (right > left) rectangles.push({ line: index, left, top: row.top - planeBounds.top, width: right - left, height: row.height });
      }
    }
    setSelectionRects(previous => previous.length === rectangles.length && previous.every((rect, index) => {
      const next = rectangles[index];
      return rect.line === next.line && rect.left === next.left && rect.top === next.top && rect.width === next.width && rect.height === next.height;
    }) ? previous : rectangles);
  }, [selection, lines, lineOffsets, font, fontSize, scroll.top, scroll.left, geometryRevision]);

  useLayoutEffect(() => {
    const element = input.current;
    if (!element || activeLine < 1 || activeLine > lines.length) return;
    const top = paddingTop + (activeLine - 1) * lineHeight;
    if (top < element.scrollTop) element.scrollTop = Math.max(0, top - lineHeight);
    else if (top + lineHeight > element.scrollTop + element.clientHeight) element.scrollTop = top + lineHeight * 2 - element.clientHeight;
  }, [activeLine, lineHeight, lines.length]);

  function startPreview(line: number, x: number, y: number) {
    cancelPreview();
    hoverPosition.current = { x, y };
    hoverTimer.current = setTimeout(() => {
      const position = hoverPosition.current;
      setPreview({ line, x: Math.max(12, Math.min(position.x + 22, window.innerWidth - 362)), y: Math.max(12, Math.min(position.y - 14, window.innerHeight - 246)) });
    }, 1000);
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    const element = event.currentTarget;
    const start = element.selectionStart;
    const end = element.selectionEnd;
    let next = source;
    let nextStart = start;
    let nextEnd = end;
    if (start === end && !event.shiftKey) {
      const lineStart = source.lastIndexOf('\n', start - 1) + 1;
      const spaces = ' '.repeat(4 - ((start - lineStart) % 4));
      next = source.slice(0, start) + spaces + source.slice(end);
      nextStart = nextEnd = start + spaces.length;
    } else {
      const blockStart = source.lastIndexOf('\n', start - 1) + 1;
      // A selection ending at column zero should not indent the following line.
      const selectedEnd = end > start && source[end - 1] === '\n' ? end - 1 : end;
      const blockEnd = source.indexOf('\n', selectedEnd);
      const finish = blockEnd === -1 ? source.length : blockEnd;
      const block = source.slice(blockStart, finish).split('\n');
      const deltas = block.map(line => event.shiftKey ? -(line.match(/^(?: {1,4}|\t)/)?.[0].length ?? 0) : 4);
      const replacement = block.map((line, index) => event.shiftKey ? line.slice(-deltas[index]) : '    ' + line).join('\n');
      next = source.slice(0, blockStart) + replacement + source.slice(finish);
      nextStart = Math.max(blockStart, start + deltas[0]);
      nextEnd = Math.max(nextStart, end + deltas.reduce((sum, delta) => sum + delta, 0));
    }
    if (next === source) {
      element.setSelectionRange(nextStart, nextEnd);
      return;
    }
    pendingSelection.current = { start: nextStart, end: nextEnd, top: element.scrollTop, left: element.scrollLeft };
    onChange(next);
  }

  const style = {
    '--editor-font': fonts[font],
    '--editor-font-size': `${fontSize}px`,
    '--editor-line-height': `${lineHeight}px`,
    '--editor-scroll-y': `${-scroll.top}px`,
    '--editor-scroll-x': `${-scroll.left}px`,
    '--editor-line-transition': `${Math.max(0, lineTransitionMs)}ms`,
  } as CSSProperties;

  return <div className={`code-editor${depth ? ' code-editor--depth' : ''}${focused ? ' code-editor--focused' : ''}`} style={style} data-testid="code-editor">
    <div className="editor-gutter" aria-label="Номера строк и точки остановки" onMouseLeave={cancelPreview}>
      <div className="editor-gutter-lines">
        {lines.map((_, index) => <button
          key={index}
          type="button"
          className={`editor-line-number${activeLine === index + 1 ? ' is-active' : ''}${breakpoints.has(index + 1) ? ' has-breakpoint' : ''}`}
          aria-label={`${breakpoints.has(index + 1) ? 'Убрать' : 'Добавить'} точку остановки: строка ${index + 1}`}
          aria-pressed={breakpoints.has(index + 1)}
          data-line={index + 1}
          onClick={() => setBreakpoints(previous => {
            const next = new Set(previous);
            if (next.has(index + 1)) next.delete(index + 1); else next.add(index + 1);
            return next;
          })}
          onMouseEnter={event => startPreview(index + 1, event.clientX, event.clientY)}
          onMouseMove={event => { hoverPosition.current = { x: event.clientX, y: event.clientY }; }}
          onMouseLeave={cancelPreview}
        ><span className="breakpoint-dot" /><span>{index + 1}</span>{activeLine === index + 1 && <span className="execution-arrow">›</span>}</button>)}
      </div>
    </div>

    <div className="editor-code-plane" ref={codePlane}>
      {globalLines.filter(line => line > 0 && line <= lines.length).map(line => <div
        key={`global-${line}`}
        aria-hidden="true"
        className="editor-global-line"
        style={{ top: paddingTop + (line - 1) * lineHeight - scroll.top, height: lineHeight }}
        data-global-line={line}
      />)}
      {activeLine > 0 && activeLine <= lines.length && <div aria-hidden="true" className="editor-active-line" style={{ top: paddingTop + (activeLine - 1) * lineHeight - scroll.top, height: lineHeight }} />}
      <div className="editor-highlight-viewport" aria-hidden="true">
        <div className="editor-selection-layer" data-testid="editor-selection" data-start={selection.start} data-end={selection.end}>{selectionRects.map(rect => <span key={rect.line} className="editor-selection-rect" data-line={rect.line + 1} style={{ left: rect.left, top: rect.top, width: rect.width, height: rect.height }} />)}</div>
        <pre className="editor-highlight" ref={highlight}><code>{tokens.map((line, index) => {
          let offset = lineOffsets[index];
          return <span key={index} className="editor-source-line"><span className="editor-line-content">{line.length ? line.map((token, tokenIndex) => {
            const start = Math.max(0, selection.start - offset);
            const end = Math.min(token.text.length, selection.end - offset);
            offset += token.text.length;
            return <span key={tokenIndex} className={`token token-${token.type}`} style={{ color: `var(--syntax-${token.type})` }}>{end > start ? <>{token.text.slice(0, start)}<span className="editor-selected-glyphs">{token.text.slice(start, end)}</span>{token.text.slice(end)}</> : token.text}</span>;
          }) : '\u200b'}</span>{'\n'}</span>;
        })}</code></pre>
      </div>
      <textarea
        ref={input}
        className="editor-textarea"
        aria-label="Редактор C++"
        data-testid="source-editor"
        value={source}
        onChange={event => onChange(event.target.value)}
        onKeyDown={onKeyDown}
        onSelect={readSelection}
        onKeyUp={readSelection}
        onPointerDown={() => { pointerSelecting.current = true; }}
        onPointerUp={readSelection}
        onFocus={() => { setFocused(true); readSelection(); }}
        onBlur={() => { setFocused(false); readSelection(); }}
        onScroll={event => {
          setScroll({ top: event.currentTarget.scrollTop, left: event.currentTarget.scrollLeft });
          cancelPreview();
        }}
        wrap="off"
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        autoComplete="off"
      />
    </div>

    {preview && <div className="assembly-tooltip" role="tooltip" style={{ left: preview.x, top: preview.y }} data-testid="asm-preview">
      <div className="assembly-tooltip-heading"><span><i />ASM <b>· preview</b></span><span className="assembly-chip">{architecture === 'arm64' ? 'ARM64' : 'x86–64'}</span></div>
      <div className="assembly-source-label">SOURCE LINE <span>{String(preview.line).padStart(2, '0')}</span></div>
      <div className="assembly-instructions">{assemblyLines(architecture, lines[preview.line - 1] ?? '').map(([opcode, operands], index) => <div key={index}><span className="assembly-offset">+{String(index * 4).padStart(2, '0')}</span><span className="assembly-opcode">{opcode}</span><span>{operands}</span></div>)}</div>
      <div className="assembly-tooltip-footer"><span className="assembly-preview-dot" />Макет · не дизассемблирование</div>
    </div>}
  </div>;
}
