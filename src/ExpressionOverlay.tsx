import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties, type RefObject } from 'react';
import type { ExpressionEvent, ExpressionStage, SourceRange } from './execution-types';
import { overlaps, placeExpression, type ExpressionProjector, type ExpressionStyle, type ScreenRect } from './expression-layout';
import { usePresentationMotion } from './presentation-motion';
import './expression.css';

export type { ExpressionStyle } from './expression-layout';
type Props = {
  event: ExpressionEvent | null;
  isPlaying: boolean;
  stepDurationMs?: number;
  style?: ExpressionStyle;
  projectorRef: RefObject<ExpressionProjector | null>;
  /** Whether finite expression transitions should be shown at all. */
  expressionAnimations?: boolean;
  /** `rate` keeps playback compact; `base` exposes the recorded stages while playing. */
  playbackMode?: 'rate' | 'base';
};
type Phase = 'rise' | 'merge' | 'result' | 'pending';
const GROUP_DURATION_MS = 900;
const RAIL_GROUP_DURATION_MS = 3200;
const PRESENCE_MS = 520;
const MAX_GROUPS_PER_EVENT = 12;

function useReducedMotion() {
  const [reduced, setReduced] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(query.matches);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return reduced;
}

type Retained<T> = { key: string; value: T; exiting: boolean; expires: number };
function usePresence<T extends { key: string }>(incoming: T[], identity: string, reduced: boolean) {
  const latest = useRef(incoming);
  latest.current = incoming;
  const [items, setItems] = useState<Retained<T>[]>(() => incoming.map((value) => ({ key: value.key, value, exiting: false, expires: Infinity })));
  useLayoutEffect(() => {
    const now = performance.now();
    setItems((previous) => {
      const keys = new Set(latest.current.map((value) => value.key));
      // Retain the last visible content, never a playback backlog.
      const departing = reduced ? [] : previous.filter((item) => !item.exiting && !keys.has(item.key))
        .map((item) => ({ ...item, exiting: true, expires: now + PRESENCE_MS }));
      const surviving = reduced ? [] : previous.filter((item) => item.exiting && item.expires > now && !keys.has(item.key));
      const active = latest.current.map((value) => ({ key: value.key, value, exiting: false, expires: Infinity }));
      return [...(departing.length ? departing : surviving), ...active];
    });
    const timer = setTimeout(() => setItems((previous) => previous.filter((item) => !item.exiting)), reduced ? 0 : PRESENCE_MS);
    return () => clearTimeout(timer);
  }, [identity, reduced]);
  return items;
}

function valueText(value: number | string | null) { return value === null ? '?' : String(value); }
function resultText(stage: ExpressionStage) {
  if (stage.resultKind === 'boolean') {
    if (stage.result === 1 || stage.result === '1') return 'true';
    if (stage.result === 0 || stage.result === '0') return 'false';
  }
  return valueText(stage.result);
}
function operationSymbol(stage: ExpressionStage, index: number) {
  if (stage.operator === 'call') return ',';
  if (['return', 'input', 'output'].includes(stage.operator)) return null;
  if (stage.operator === '?:') return index === 1 ? '?' : ':';
  return stage.operator;
}
function operandLabel(stage: ExpressionStage, index: number) {
  return stage.operandLabels?.[index] ?? `${stage.operator === 'call' ? 'аргумент' : 'операнд'} ${index + 1}`;
}
function initialPhase(stages: ExpressionStage[], immediate: boolean): Phase {
  if (stages.every((stage) => stage.result === null)) return 'pending';
  return immediate || stages.every((stage) => stage.operands.length === 0) ? 'result' : 'rise';
}
function describe(stage: ExpressionStage) {
  return `${stage.label}: ${stage.operands.map(valueText).join(', ')}. ${stage.result === null ? 'Результат ещё не получен' : `Результат ${resultText(stage)}`}`;
}

type OperandLink = { range?: SourceRange; index: number; path: SVGPathElement | null; dot: SVGCircleElement | null; frame: HTMLDivElement | null };
type AnchorRegistration = {
  key: string;
  element: HTMLDivElement;
  chip: HTMLDivElement;
  path: SVGPathElement;
  dot: SVGCircleElement;
  connector: SVGSVGElement;
  stage: ExpressionStage;
  line: number;
  style: ExpressionStyle;
  exiting: boolean;
  operandLinks: OperandLink[];
  glyphMask: SVGGElement | null;
};
type RegisterAnchor = (registration: AnchorRegistration) => () => void;

function StageValues({ stage, phase, immediate, isPlaying, pendingOperands }: {
  stage: ExpressionStage; phase: Phase; immediate: boolean; isPlaying: boolean; pendingOperands: boolean;
}) {
  const valuesRef = useRef<HTMLDivElement>(null);
  const pending = stage.result === null;
  // A pending call has no observed result to replace its arguments with. Keep
  // those arguments visible when animations are disabled/reduced, including
  // autoplay; `immediate` is intentionally not enough to hide unknown data.
  const showOperands = stage.operands.length > 0 && (!immediate || (pending && pendingOperands));
  const localPhase = pending ? 'pending' : immediate || stage.operands.length === 0 ? 'result' : phase;
  useLayoutEffect(() => {
    const row = valuesRef.current;
    if (!row) return;
    const measure = () => {
      const middle = row.clientWidth / 2;
      for (const element of row.querySelectorAll<HTMLElement>('.expression-operand')) {
        let offset = element.offsetLeft;
        let parent = element.offsetParent as HTMLElement | null;
        while (parent && parent !== row) { offset += parent.offsetLeft; parent = parent.offsetParent as HTMLElement | null; }
        element.style.setProperty('--merge-x', `${middle - offset - element.offsetWidth / 2}px`);
      }
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(row);
    for (const element of row.querySelectorAll('.expression-operand')) observer.observe(element);
    return () => observer.disconnect();
  }, [showOperands]);
  return <div className={`expression-values-area ${pending ? 'expression-values-area--pending' : ''} ${immediate || stage.operands.length === 0 ? 'expression-values-area--immediate' : ''}`}
    data-stage-id={stage.id} data-stage-phase={localPhase} style={{ '--operand-count': stage.operands.length } as CSSProperties}>
    {showOperands && <div className="expression-values" ref={valuesRef}>
      {stage.operands.map((operand, index) => <span className="expression-operand-group" key={index}>
        {index > 0 && operationSymbol(stage, index) && <span className="expression-operator" data-operator={operationSymbol(stage, index)!}>{operationSymbol(stage, index)}</span>}
        <span className="expression-operand" title={valueText(operand)}>{valueText(operand)}</span>
      </span>)}
    </div>}
    {pending ? !showOperands && <span className="expression-pending-note">вызов…</span> : <output className="expression-result" title={resultText(stage)}>{resultText(stage)}</output>}
  </div>;
}

function railMetrics(stage: ExpressionStage, showOperands: boolean) {
  const operands = showOperands ? stage.operands.map((value, index) => Math.max(92, Math.min(216, Math.max(valueText(value).length * 17 + 28, operandLabel(stage, index).length * 7 + 24)))) : [];
  const result = stage.result === null ? 0 : Math.max(102, Math.min(238, Math.max(resultText(stage).length * 17 + 30, (stage.target?.length ?? 9) * 7 + 24)));
  const prefixWidth = operands.length === 1 && ['+', '-', '!', '~', '++', '--'].includes(stage.operator) ? 36 : 0;
  const width = Math.max(116, operands.reduce((sum, item) => sum + item, 0) + Math.max(0, operands.length - 1) * 36 + result + (operands.length && result ? 40 : 0) + prefixWidth);
  return { operands, result, width };
}

function RailValues({ stage, phase, immediate, isPlaying, pendingOperands, links }: {
  stage: ExpressionStage; phase: Phase; immediate: boolean; isPlaying: boolean; pendingOperands: boolean; links: OperandLink[];
}) {
  const pending = stage.result === null;
  const showOperands = stage.operands.length > 0 && (!immediate || (pending && pendingOperands));
  const metrics = railMetrics(stage, showOperands);
  const rowRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const row = rowRef.current;
    if (!row || !showOperands || pending) return;
    const measure = () => {
      const result = row.querySelector<HTMLElement>('.rail-result');
      if (!result) return;
      for (const element of row.querySelectorAll<HTMLElement>('.rail-argument')) {
        element.style.setProperty('--operand-merge-x', `${result.offsetLeft + result.offsetWidth / 2 - element.offsetLeft - element.offsetWidth / 2}px`);
        element.style.setProperty('--operand-merge-y', `${result.offsetTop + result.offsetHeight / 2 - element.offsetTop - element.offsetHeight / 2}px`);
      }
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(row);
    return () => observer.disconnect();
  }, [showOperands, pending]);
  const prefix = stage.operands.length === 1 && ['+', '-', '!', '~', '++', '--'].includes(stage.operator) ? stage.operator : null;
  const isCall = stage.operator === 'call';
  return <div className={`rail-equation ${pending ? 'rail-equation--pending' : ''} ${isCall ? 'rail-equation--call' : ''} ${immediate || stage.operands.length === 0 ? 'rail-equation--immediate' : ''}`}
    data-stage-id={stage.id} data-stage-phase={pending ? 'pending' : immediate ? 'result' : phase} ref={rowRef}>
    {showOperands && stage.operands.map((operand, index) => <div className="rail-term" key={index}>
      {(index > 0 ? operationSymbol(stage, index) : prefix) && <span className="expression-operator" data-operator={(index > 0 ? operationSymbol(stage, index) : prefix)!}>{index > 0 ? operationSymbol(stage, index) : prefix}</span>}
      <div className="rail-argument" data-operand-index={index} ref={(element) => { if (links[index]) links[index].frame = element; }}
        style={{ '--operand-index': index, '--operand-width': `${metrics.operands[index]}px`, '--operand-size': `${Math.min(34, Math.max(13, (metrics.operands[index] - 26) / (Math.max(1, valueText(operand).length) * .64)))}px` } as CSSProperties}>
        <span className="rail-argument-label" title={operandLabel(stage, index)}>{operandLabel(stage, index)}</span>
        <span className="expression-operand" title={valueText(operand)}>{valueText(operand)}</span>
      </div>
    </div>)}
    {stage.result !== null ? <div className="rail-final-term">
      {showOperands && <span className="rail-relation">{['call', 'return', 'input', 'output'].includes(stage.operator) ? '→' : '='}</span>}
      <div className="rail-result" style={{ '--operand-width': `${metrics.result}px`, '--result-size': `${Math.min(34, Math.max(13, (metrics.result - 26) / (Math.max(1, resultText(stage).length) * .64)))}px` } as CSSProperties}>
        <span className="rail-argument-label" title={stage.target || 'результат'}>{stage.target || 'результат'}</span>
        <output className="expression-result" title={resultText(stage)}>{resultText(stage)}</output>
      </div>
    </div> : !showOperands && <span className="expression-pending-note">вызов…</span>}
  </div>;
}

function AnchoredStage({ stage, line, phase, immediate, isPlaying, pendingOperands, style, exiting, registryKey, register, grouped }: {
  stage: ExpressionStage; line: number; phase: Phase; immediate: boolean; isPlaying: boolean; pendingOperands: boolean;
  style: ExpressionStyle; exiting: boolean; registryKey: string; register: RegisterAnchor; grouped: boolean;
}) {
  const elementRef = useRef<HTMLDivElement>(null);
  const chipRef = useRef<HTMLDivElement>(null);
  const connectorRef = useRef<SVGSVGElement>(null);
  const pathRef = useRef<SVGPathElement>(null);
  const dotRef = useRef<SVGCircleElement>(null);
  const maskRef = useRef<SVGGElement>(null);
  const maskId = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const showRailOperands = style === 'rail' && stage.operands.length > 0 && (!immediate || (stage.result === null && pendingOperands));
  const operandLinks = useMemo<OperandLink[]>(() => stage.operands.map((_, index) => ({ range: stage.operandRanges?.[index], index, path: null, dot: null, frame: null })), [stage]);
  useLayoutEffect(() => register({
    key: registryKey, element: elementRef.current!, chip: chipRef.current!, path: pathRef.current!,
    dot: dotRef.current!, connector: connectorRef.current!, stage, line, style, exiting, operandLinks: showRailOperands ? operandLinks : [], glyphMask: maskRef.current,
  }), [registryKey, register, stage, line, style, exiting, operandLinks, showRailOperands]);
  const digits = Math.max(resultText(stage).length + 2, stage.operands.reduce<number>((length, value, index) => length + valueText(value).length + 1.8 + (index > 0 ? (operationSymbol(stage, index)?.length ?? 0) * 1.25 : 0), 0));
  const width = style === 'rail' ? railMetrics(stage, showRailOperands).width
    : Math.max(style === 'inline' ? 50 : 60, Math.min(style === 'inline' ? 280 : 340, digits * (style === 'inline' ? 10 : 11) + 28));
  // Keep ordinary values cinematic and legible, while the width-aware term
  // below still shrinks exact wide integers instead of clipping them.
  const resultSize = Math.min(style === 'inline' ? 17 : style === 'rail' ? 34 : 21, Math.max(11, (width - 34) / (Math.max(1, resultText(stage).length) * .64)));
  return <div className={`expression-stage-presence ${grouped ? 'expression-substage' : ''}`} data-presence={exiting ? 'exiting' : 'present'} aria-hidden="true">
    <svg className={`expression-connector expression-connector--${style} ${showRailOperands ? 'expression-connector--arguments' : ''} ${stage.result === null ? 'expression-connector--pending' : ''}`} ref={connectorRef}>
      {style === 'rail' && <defs><mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="100%" height="100%"><rect x="0" y="0" width="100%" height="100%" fill="white" /><g ref={maskRef} /></mask></defs>}
      <g mask={style === 'rail' ? `url(#${maskId})` : undefined}>
        <path className="expression-stage-link" ref={pathRef} />
        <circle className="expression-stage-dot" ref={dotRef} r={style === 'rail' ? 3 : 1.6} />
        {showRailOperands && operandLinks.map((link) => <g key={link.index} className="rail-link-group">
          <path className="rail-operand-link" data-operand-index={link.index} ref={(element) => { link.path = element; }} />
          <circle className="rail-operand-dot" r="3.5" ref={(element) => { link.dot = element; }} />
        </g>)}
      </g>
    </svg>
    <div className="expression-anchor" ref={elementRef} data-style={style} data-visible="false" data-stage-key={stage.id}>
      <div className="expression-plane">
        <div className="expression-chip-motion">
          <div className={`expression-chip expression-chip--${style} ${stage.operator === 'call' ? 'expression-chip--call' : ''}`} ref={chipRef} style={{ '--chip-width': `${width}px`, '--result-size': `${resultSize}px` } as CSSProperties}>
            <span className="expression-label" title={stage.label}>{stage.label}</span>
            <span className="expression-fallback">строка {line}</span>
            {style === 'rail' ? <RailValues stage={stage} phase={phase} immediate={immediate} isPlaying={isPlaying} pendingOperands={pendingOperands} links={operandLinks} />
              : <StageValues stage={stage} phase={phase} immediate={immediate} isPlaying={isPlaying} pendingOperands={pendingOperands} />}
          </div>
        </div>
      </div>
    </div>
  </div>;
}

function ExpressionCard({ event, isPlaying, reduced, stepDurationMs, style, exiting, register, identity, expressionAnimations, playbackMode }: {
  event: ExpressionEvent; isPlaying: boolean; reduced: boolean; stepDurationMs: number; style: ExpressionStyle;
  exiting: boolean; register: RegisterAnchor; identity: string; expressionAnimations: boolean; playbackMode: 'rate' | 'base';
}) {
  const presentation = usePresentationMotion();
  const animated = expressionAnimations && !reduced;
  // Rate playback intentionally presents only the observed final value. Base
  // playback is an educational mode: it keeps the same finite timeline as a
  // manual step even while execution is running.
  const immediate = !animated || (isPlaying && playbackMode === 'rate');
  // Base is intentionally the fully narrated mode: pending calls keep their
  // observed arguments on screen while the call is being resolved. Rate mode
  // still collapses an in-flight call to the compact “вызов…” marker.
  const pendingOperands = !animated || !isPlaying || playbackMode === 'base';
  const allGroups = event.groups?.filter((group) => group.stages.length > 0) ?? [];
  // A malformed trace must never create an unbounded UI wait. Keep the
  // observed final event visible and make truncation explicit in the DOM/ARIA;
  // a future paginator can expose the remaining recorded groups.
  const groups = allGroups.slice(0, MAX_GROUPS_PER_EVENT);
  const [groupIndex, setGroupIndex] = useState(immediate ? groups.length : 0);
  const group = !immediate && groupIndex < groups.length ? groups[groupIndex] : null;
  const stages = group?.stages ?? [event];
  const [phase, setPhase] = useState<Phase>(() => initialPhase(stages, immediate));
  const groupDuration = style === 'rail' ? RAIL_GROUP_DURATION_MS : GROUP_DURATION_MS;
  // The card re-renders at each recorded group boundary. Hold only the
  // remaining tail, otherwise every boundary would restart a full-event hold
  // and a scheduler could wait quadratically long for one finite event.
  const remainingGroupsMs = Math.max(0, groups.length - groupIndex) * groupDuration;
  const finalStageMs = (!groups.length || groupIndex >= groups.length) && stages.some((stage) => stage.result !== null && stage.operands.length > 0)
    ? (style === 'rail' ? 2300 : 640) : 0;
  // A pending call has no merge/result phase, but its argument frames still
  // need a deliberate reading window. Keep the coordinator aware of that
  // finite reveal so BASE playback cannot advance halfway through it.
  const pendingCallMs = stages.some((stage) => stage.result === null && stage.operator === 'call' && stage.operands.length > 0 && (!isPlaying || playbackMode === 'base'))
    ? (style === 'rail' ? 1750 : 1500) : 0;
  const sequenceMs = remainingGroupsMs + finalStageMs + pendingCallMs;
  useLayoutEffect(() => {
    if (exiting || immediate || !sequenceMs) return;
    // Register before the passive timer effect below, so a presentation
    // coordinator can hold the debugger step across the whole finite chain.
    const release = presentation?.hold(`expression:${event.id}`, sequenceMs + 500);
    const timer = window.setTimeout(() => release?.(), sequenceMs);
    return () => {
      window.clearTimeout(timer);
      release?.();
    };
  }, [event.id, exiting, immediate, presentation, sequenceMs]);
  useEffect(() => {
    if (exiting) return;
    const timers: ReturnType<typeof setTimeout>[] = [];
    if (!immediate && stages.some((stage) => stage.result !== null && stage.operands.length > 0)) {
      timers.push(setTimeout(() => setPhase('merge'), style === 'rail' ? 1400 : 180));
      timers.push(setTimeout(() => setPhase('result'), style === 'rail' ? 2300 : 640));
    }
    if (group) timers.push(setTimeout(() => {
      const nextIndex = groupIndex + 1;
      setPhase(initialPhase(groups[nextIndex]?.stages ?? [event], immediate));
      setGroupIndex(nextIndex);
    }, style === 'rail' ? RAIL_GROUP_DURATION_MS : GROUP_DURATION_MS));
    return () => timers.forEach(clearTimeout);
    // Identity fixes the event snapshot; only a recorded group can advance.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupIndex, immediate, exiting]);
  const stageKey = group?.id ?? 'final';
  const presentStages = usePresence(stages.map((stage) => ({ key: `${stageKey}:${stage.id}`, stage, phase, grouped: Boolean(group) })), `${stageKey}:${phase}`, reduced);
  const overflowNote = allGroups.length > MAX_GROUPS_PER_EVENT ? ` Показаны первые ${MAX_GROUPS_PER_EVENT} из ${allGroups.length} этапов; остальные доступны в трассе.` : '';
  const announcement = `${group ? `Этап ${groupIndex + 1}. ` : ''}${stages.map(describe).join('; ')}. Строка ${event.line}.${overflowNote}`;
  return <div className={`expression-card ${!animated ? 'expression-card--reduced' : ''}`}
    data-event-id={event.id} data-mode={isPlaying ? 'playing' : 'manual'} data-playback-mode={playbackMode}
    data-animations={animated ? 'on' : 'off'} data-expression-animations={animated ? 'true' : 'false'} data-phase={phase} data-style={style}
    data-presence={exiting ? 'exiting' : 'present'} data-group-id={group?.id ?? 'final'} data-group-index={group ? groupIndex : groups.length}
    data-group-count={allGroups.length} data-group-overflow={allGroups.length > MAX_GROUPS_PER_EVENT ? 'true' : 'false'}
    role="status" aria-live={isPlaying || exiting ? 'off' : 'polite'} aria-label={announcement}
    style={{ '--result-fade': `${Math.max(80, Math.min(320, stepDurationMs * .32))}ms` } as CSSProperties}>
    {presentStages.map((item) => <AnchoredStage key={item.key} stage={item.value.stage} line={event.line} phase={item.value.phase}
      grouped={item.value.grouped} immediate={immediate} isPlaying={isPlaying} pendingOperands={pendingOperands} style={style} exiting={exiting || item.exiting}
      registryKey={`${identity}:${item.key}`} register={register} />)}
  </div>;
}

export default function ExpressionOverlay({ event, isPlaying, stepDurationMs = 1250, style = 'float', projectorRef, expressionAnimations = true, playbackMode = 'rate' }: Props) {
  const reduced = useReducedMotion();
  const animated = expressionAnimations && !reduced;
  // Include presentation controls in identity so toggling them cancels a
  // pending group sequence instead of leaving a hidden timer/card behind.
  const identity = event ? JSON.stringify([event, isPlaying, reduced, style, expressionAnimations, playbackMode]) : '';
  const items = usePresence(event ? [{ key: identity, event, isPlaying, stepDurationMs, style, expressionAnimations, playbackMode }] : [], identity, !animated);
  const registry = useRef(new Map<string, AnchorRegistration>());
  const register = useCallback<RegisterAnchor>((entry) => {
    registry.current.set(entry.key, entry);
    return () => { registry.current.delete(entry.key); };
  }, []);
  useEffect(() => {
    let frame = 0;
    let previousTime = performance.now();
    const motion = new Map<string, { x: number; y: number; opacity: number; relocating: boolean; revision: number }>();
    const project = (now: number) => {
      const dt = Math.min(.05, Math.max(0, (now - previousTime) / 1000));
      previousTime = now;
      for (const key of motion.keys()) if (!registry.current.has(key)) motion.delete(key);
      const occupied: ScreenRect[] = [];
      const entries = [...registry.current.values()].sort((a, b) => Number(a.exiting) - Number(b.exiting));
      for (const entry of entries) {
        const projection = projectorRef.current?.(entry.stage.range, entry.line);
        let state = motion.get(entry.key);
        if (!projection?.visible) {
          if (state) state.opacity = Math.max(0, state.opacity - dt / .24);
          entry.element.style.opacity = String(state?.opacity ?? 0);
          entry.connector.style.opacity = String(state?.opacity ?? 0);
          if (!state || state.opacity === 0) {
            entry.element.style.visibility = 'hidden';
            entry.connector.style.visibility = 'hidden';
          }
          entry.element.dataset.visible = 'false';
          continue;
        }
        entry.element.dataset.anchorKind = projection.exact ? 'range' : 'line';
        entry.element.style.setProperty('--scene-width', `${projection.width}px`);
        const anchor = { x: (projection.bounds.left + projection.bounds.right) / 2, y: (projection.bounds.top + projection.bounds.bottom) / 2 };
        const previous = state ? { x: anchor.x + state.x, y: anchor.y + state.y } : undefined;
        const placement = placeExpression(projection, entry.chip.offsetWidth, entry.chip.offsetHeight, entry.style, entry.exiting ? [] : occupied, previous);
        const target = { x: placement.center.x - anchor.x, y: placement.center.y - anchor.y };
        if (!state) {
          state = { ...target, opacity: 1, relocating: false, revision: projection.revision };
          motion.set(entry.key, state);
        }
        const shiftBox = (x: number, y: number) => ({
          left: placement.box.left + x - target.x, right: placement.box.right + x - target.x,
          top: placement.box.top + y - target.y, bottom: placement.box.bottom + y - target.y,
        });
        const obstacles = [...projection.glyphs, ...(entry.exiting ? [] : occupied)];
        const distance = Math.hypot(target.x - state.x, target.y - state.y);
        const unsafePath = distance > 10 && [.2, .4, .6, .8].some((t) => obstacles.some((rect) => overlaps(shiftBox(state!.x + (target.x - state!.x) * t, state!.y + (target.y - state!.y) * t), rect, 1)));
        if (unsafePath) state.relocating = true;
        if (reduced) {
          Object.assign(state, target, { opacity: placement.collision ? 0 : 1, relocating: false });
        } else if (state.relocating) {
          state.opacity = Math.max(0, state.opacity - dt / .18);
          if (state.opacity === 0) Object.assign(state, target, { relocating: false });
        } else {
          const ease = 1 - Math.exp(-dt / .13);
          state.x += (target.x - state.x) * ease;
          state.y += (target.y - state.y) * ease;
          state.opacity = placement.collision ? Math.max(0, state.opacity - dt / .18) : Math.min(1, state.opacity + dt / .36);
        }
        const box = shiftBox(state.x, state.y);
        const collision = obstacles.some((rect) => overlaps(box, rect));
        const visible = !collision && !placement.collision && state.opacity > 0;
        entry.element.dataset.visible = String(visible);
        entry.element.dataset.glyphOverlap = String(collision);
        entry.element.dataset.anchorX = String(anchor.x);
        entry.element.dataset.anchorY = String(anchor.y);
        entry.element.dataset.box = JSON.stringify(box);
        entry.element.dataset.layoutMotion = state.relocating ? 'relocating' : distance > .5 ? 'moving' : 'still';
        entry.element.style.visibility = visible ? 'visible' : 'hidden';
        entry.connector.style.visibility = visible ? 'visible' : 'hidden';
        entry.element.style.opacity = String(state.opacity);
        entry.connector.style.opacity = String(state.opacity);
        entry.element.style.transform = `translate3d(${anchor.x + state.x}px, ${anchor.y + state.y}px, 0)`;
        entry.element.style.setProperty('--plane-matrix', `matrix(${placement.matrix.join(',')},0,0)`);
        entry.element.title = projection.exact ? `${entry.stage.label} · строка ${entry.stage.range!.start.line}` : `${entry.stage.label} · вся строка ${entry.line}, точный диапазон не задан`;
        const { start } = placement;
        let targetBox = box;
        const resultFrame = entry.style === 'rail' ? entry.chip.querySelector<HTMLElement>('.rail-result') : null;
        if (resultFrame) {
          const frameBounds = resultFrame.getBoundingClientRect();
          const overlayBounds = entry.connector.getBoundingClientRect();
          targetBox = { left: frameBounds.left - overlayBounds.left, right: frameBounds.right - overlayBounds.left, top: frameBounds.top - overlayBounds.top, bottom: frameBounds.bottom - overlayBounds.top };
        }
        const end = { x: Math.max(targetBox.left, Math.min(targetBox.right, start.x)), y: Math.max(targetBox.top, Math.min(targetBox.bottom, start.y)) };
        const path = entry.style === 'rail'
          ? `M${start.x},${start.y} C${start.x + (end.x - start.x) * .55},${start.y} ${end.x - 10},${end.y} ${end.x},${end.y}`
          : `M${start.x},${start.y} Q${start.x},${(start.y + end.y) / 2} ${end.x},${end.y}`;
        entry.path.setAttribute('d', path);
        entry.dot.setAttribute('cx', String(start.x));
        entry.dot.setAttribute('cy', String(start.y));
        if (entry.style === 'rail') {
          // Thick links stay legible without painting over projected code glyphs.
          if (entry.glyphMask && entry.glyphMask.dataset.revision !== String(projection.revision)) {
            entry.glyphMask.replaceChildren(...projection.glyphs.map((rect) => {
              const element = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
              element.setAttribute('x', String(rect.left - 2));
              element.setAttribute('y', String(rect.top - 2));
              element.setAttribute('width', String(rect.right - rect.left + 4));
              element.setAttribute('height', String(rect.bottom - rect.top + 4));
              element.setAttribute('fill', 'black');
              return element;
            }));
            entry.glyphMask.dataset.revision = String(projection.revision);
          }
          const overlayBounds = entry.connector.getBoundingClientRect();
          for (const link of entry.operandLinks) {
            if (!link.path || !link.dot || !link.frame) continue;
            const operandProjection = link.range ? projectorRef.current?.(link.range, entry.line) : null;
            const exact = Boolean(operandProjection?.visible && operandProjection.exact);
            link.path.style.visibility = exact && visible ? 'visible' : 'hidden';
            link.dot.style.visibility = exact && visible ? 'visible' : 'hidden';
            link.path.dataset.exact = String(exact);
            if (!exact || !operandProjection) continue;
            const frameBox = link.frame.getBoundingClientRect();
            const targetBox = { left: frameBox.left - overlayBounds.left, right: frameBox.right - overlayBounds.left, top: frameBox.top - overlayBounds.top, bottom: frameBox.bottom - overlayBounds.top };
            const sourceX = (operandProjection.bounds.left + operandProjection.bounds.right) / 2;
            const targetY = (targetBox.top + targetBox.bottom) / 2;
            const above = targetY < (operandProjection.lineBounds.top + operandProjection.lineBounds.bottom) / 2;
            const sourceY = above ? Math.min(operandProjection.bounds.top, operandProjection.lineBounds.top) - 5 : Math.max(operandProjection.bounds.bottom, operandProjection.lineBounds.bottom) + 5;
            const laneY = above ? operandProjection.lineBounds.top - 12 - link.index * 10 : operandProjection.lineBounds.bottom + 12 + link.index * 10;
            let path: string;
            if (sourceX < targetBox.left || sourceX > targetBox.right) {
              const side = sourceX < targetBox.left ? 1 : -1;
              const targetX = side > 0 ? targetBox.left : targetBox.right;
              const targetEdgeY = Math.max(targetBox.top + 9, Math.min(targetBox.bottom - 9, sourceY));
              const turnX = targetX - side * 14;
              path = `M${sourceX},${sourceY} Q${sourceX},${laneY} ${sourceX + side * 10},${laneY} L${turnX},${laneY} Q${turnX},${targetEdgeY} ${targetX},${targetEdgeY}`;
            } else {
              const targetEdgeY = sourceY < targetBox.top ? targetBox.top : targetBox.bottom;
              path = `M${sourceX},${sourceY} C${sourceX},${laneY} ${sourceX},${laneY} ${sourceX},${targetEdgeY}`;
            }
            link.path.setAttribute('d', path);
            link.dot.setAttribute('cx', String(sourceX));
            link.dot.setAttribute('cy', String(sourceY));
            Object.assign(link.path.dataset, { sourceLine: String(link.range!.start.line), sourceColumn: String(link.range!.start.column), sourceX: String(sourceX), sourceY: String(sourceY) });
          }
        }
        if (!entry.exiting && visible) occupied.push(box);
      }
      frame = requestAnimationFrame(project);
    };
    frame = requestAnimationFrame(project);
    return () => cancelAnimationFrame(frame);
  }, [projectorRef, reduced]);
  return <div className="expression-overlay" data-style={style}>
    {items.map((item) => <ExpressionCard key={item.key} identity={item.key} event={item.value.event} isPlaying={item.value.isPlaying}
      stepDurationMs={item.value.stepDurationMs} style={item.value.style} reduced={reduced} exiting={item.exiting}
      expressionAnimations={item.value.expressionAnimations} playbackMode={item.value.playbackMode} register={register} />)}
  </div>;
}
