import { useLayoutEffect, useRef, useState, type CSSProperties } from "react";
import { ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import AnimatedValue, { useChangeMotion } from "./AnimatedValue";
import {
  becameKnown,
  INSPECTOR_PAGE_SIZE,
  pageForIndex,
  pageSlice,
  retireDelay,
  type InspectorTransition,
} from "./inspector-lifecycle";
export type { InspectorTransition } from "./inspector-lifecycle";

export type DisplayValue = number | string | null;
export type InspectorMotionCoordinator = {
  hold: (label: string, maxMs: number) => () => void;
  track?: (
    animation: Animation | PromiseLike<unknown>,
    maxMs?: number,
  ) => () => void;
};
export type InspectorLifetime = {
  state: "alive" | "invalidated";
  invalidatedAt?: string;
  reason?: string;
};
export interface InspectorScalar {
  id: string;
  name: string;
  type: string;
  value: DisplayValue;
  kind: "local" | "argument";
  caption: string;
  unit?: string;
  lifetime?: InspectorLifetime;
}
export interface InspectorArray {
  id: string;
  name: string;
  type: string;
  values: DisplayValue[];
  collapsible?: boolean;
  readingIndex?: number;
  changedIndex?: number;
  unvisitedFrom?: number;
  presentation?: "prefix";
  note?: { text: string; total: DisplayValue };
  lifetime?: InspectorLifetime;
  cellLifetimes?: Record<number, InspectorLifetime>;
}
/** A projection of one active frame only. Caller data never enters this component. */
export interface InspectorFrame {
  id: string;
  functionName: string;
  scalars: InspectorScalar[];
  arrays: InspectorArray[];
}

export interface InspectorScopeProps {
  frame: InspectorFrame;
  fileName: string;
  line: number;
  transition?: InspectorTransition;
  motion?: InspectorMotionCoordinator | null;
}

type RetiredFrame = {
  key: string;
  frame: InspectorFrame;
  scalarIds?: Set<string>;
  arrayIndexes?: Record<string, Set<number>>;
  allScalars: boolean;
  allArrays: boolean;
};
let retirementSequence = 0;

function arraySignature(array: InspectorArray) {
  const focus = array.readingIndex ?? array.changedIndex;
  const indexes = new Set([
    0,
    Math.max(0, array.values.length - 1),
    focus ?? -1,
  ]);
  return [
    array.id,
    array.values.length,
    array.lifetime?.state,
    ...[...indexes]
      .filter((index) => index >= 0 && index < array.values.length)
      .map((index) => [index, array.values[index]]),
  ];
}

/* Keep render-time identity bounded for a million-element vector. Only the
   active/focus page can produce a visible birth animation. */
const frameSignature = (frame: InspectorFrame) =>
  JSON.stringify([
    frame.id,
    frame.functionName,
    frame.scalars.map((value) => [
      value.id,
      value.name,
      value.value,
      value.lifetime?.state,
    ]),
    frame.arrays.map(arraySignature),
  ]);

function retiredProjection(
  frame: InspectorFrame,
  transition: InspectorTransition,
): RetiredFrame {
  const scalarIds = transition.departedVariables
    ? new Set(transition.departedVariables)
    : undefined;
  const arrayIndexes = transition.retiredArrays
    ? Object.fromEntries(
        Object.entries(transition.retiredArrays).map(([id, indexes]) => [
          id,
          new Set(indexes),
        ]),
      )
    : undefined;
  const hasScalarSelection = transition.departedVariables !== undefined;
  const hasArraySelection = transition.retiredArrays !== undefined;
  return {
    key: `${frame.id}:retired:${++retirementSequence}`,
    frame,
    scalarIds,
    arrayIndexes,
    allScalars:
      Boolean(transition.departedFrame) ||
      (!hasScalarSelection && !hasArraySelection),
    allArrays:
      Boolean(transition.departedFrame) ||
      (!hasScalarSelection && !hasArraySelection),
  };
}

function RetiredFrameView({
  retired,
  fileName,
  line,
  motion,
}: {
  retired: RetiredFrame;
  fileName: string;
  line: number;
  motion?: InspectorMotionCoordinator | null;
}) {
  const frameElement = useRef<HTMLDivElement>(null);
  const releaseHold = useRef<(() => void) | null>(null);
  const releaseAnimation = useRef<(() => void) | null>(null);
  useLayoutEffect(() => {
    releaseHold.current = motion?.hold("inspector-lifecycle", 1700) ?? null;
    const animation = frameElement.current?.getAnimations()[0];
    releaseAnimation.current =
      animation && motion?.track ? motion.track(animation, 1700) : null;
    return () => {
      releaseHold.current?.();
      releaseHold.current = null;
      releaseAnimation.current?.();
      releaseAnimation.current = null;
    };
  }, [motion, retired.key]);
  const scalars = retired.frame.scalars.filter(
    (variable) =>
      retired.allScalars || Boolean(retired.scalarIds?.has(variable.id)),
  );
  const arrays = retired.frame.arrays.filter((array) => {
    const indexes = retired.arrayIndexes?.[array.id];
    return retired.allArrays || Boolean(indexes?.size);
  });
  return (
    <div
      ref={frameElement}
      className="inspector-retired-frame"
      data-retired-frame={retired.frame.functionName}
      aria-hidden="true"
      inert={true}
    >
      <div className="inspector-retired-frame__inner">
        <div className="scope-label">
          <ChevronDown size={12} />
          <span>Завершено · {retired.frame.functionName}</span>
          <span className="scope-line" />
        </div>
        <div className="inspector-retired-values">
          {scalars.map((variable, scalarIndex) => (
            <div
              className={`scalar-card inspector-retired-variable ${variable.lifetime?.state === "invalidated" ? "inspector-lifecycle-invalidated" : ""}`}
              key={variable.id}
              data-retired-variable={variable.id}
              data-lifetime={variable.lifetime?.state}
              data-value-cell
              style={
                {
                  "--lifecycle-delay": `${Math.min((scalars.length - 1 - scalarIndex) * 50, 300)}ms`,
                } as CSSProperties
              }
            >
              <div>
                <span className="variable-name" title={variable.name}>
                  {variable.name}
                </span>
                <span className="type-label">{variable.type}</span>
              </div>
              <strong>
                <AnimatedValue value={variable.value} />
              </strong>
              <small>{variable.lifetime?.reason || variable.caption}</small>
            </div>
          ))}
        </div>
        {arrays.map((array) => {
          const indexes = retired.arrayIndexes?.[array.id];
          const values = indexes
            ? array.values.flatMap((value, index) =>
                indexes.has(index) ? [{ value, index }] : [],
              )
            : array.values.map((value, index) => ({ value, index }));
          return (
            <div
              className={`array-section inspector-retired-variable ${array.lifetime?.state === "invalidated" ? "inspector-lifecycle-invalidated" : ""}`}
              key={array.id}
              data-retired-array={array.id}
              data-lifetime={array.lifetime?.state}
            >
              <div className="array-heading">
                <ChevronDown size={12} />
                <span className="variable-name" title={array.name}>
                  {array.name}
                </span>
                <span className="type-label">{array.type}</span>
                <span className="array-count">{values.length}</span>
              </div>
              <div className="array-cells">
                {values
                  .slice(0, INSPECTOR_PAGE_SIZE)
                  .map(({ value, index }, arrayIndex) => (
                    <div
                      className={`array-cell inspector-retired-variable ${array.cellLifetimes?.[index]?.state === "invalidated" ? "inspector-lifecycle-invalidated" : ""}`}
                      key={index}
                      data-retired-variable={`${array.id}[${index}]`}
                      data-lifetime={array.cellLifetimes?.[index]?.state}
                      data-value-cell
                      style={
                        {
                          "--lifecycle-delay": `${Math.min(arrayIndex * 50, 300)}ms`,
                        } as CSSProperties
                      }
                    >
                      <span>{index}</span>
                      <strong>
                        <AnimatedValue value={value} />
                      </strong>
                    </div>
                  ))}
              </div>
            </div>
          );
        })}
        <div className="stack-row inspector-retired-stack">
          <span className="stack-symbol">↳</span>
          <span>{retired.frame.functionName}</span>
          <span>
            {fileName}:{line}
          </span>
        </div>
      </div>
    </div>
  );
}

function ScalarCard({
  variable,
  birth,
}: {
  variable: InspectorScalar;
  birth: boolean;
}) {
  return (
    <div
      className={`scalar-card ${birth ? "inspector-lifecycle-birth" : ""} ${variable.lifetime?.state === "invalidated" ? "inspector-lifecycle-invalidated" : ""}`}
      data-value-cell
      data-variable={variable.name}
      data-variable-kind={variable.kind}
      data-lifetime={variable.lifetime?.state}
      data-lifecycle={birth ? "birth" : undefined}
      title={variable.name}
    >
      <div>
        <span className="variable-name">{variable.name}</span>
        <span className="type-label">{variable.type}</span>
      </div>
      <strong>
        <AnimatedValue value={variable.value} />
        {variable.unit && <span className="value-unit">{variable.unit}</span>}
      </strong>
      <small>
        {variable.lifetime?.state === "invalidated"
          ? variable.lifetime.reason || "недоступно"
          : variable.caption}
      </small>
    </div>
  );
}

function ArrayView({
  array,
  collapsed,
  onToggle,
  birthIndexes,
}: {
  array: InspectorArray;
  collapsed: boolean;
  onToggle: () => void;
  birthIndexes: Set<number>;
}) {
  const expanded = !collapsed;
  const focus = array.readingIndex ?? array.changedIndex;
  const automaticPage = pageForIndex(array.values.length, focus);
  const [manualPage, setManualPage] = useState<number | null>(null);
  const page =
    focus === undefined ? (manualPage ?? automaticPage) : automaticPage;
  const slice = pageSlice(array.values.length, page);
  const values = array.values.slice(slice.start, slice.end);
  const heading = (
    <>
      <ChevronDown size={12} className={expanded ? "" : "collapsed"} />
      <span className="variable-name" title={array.name}>
        {array.name}
      </span>
      <span className="type-label" title={array.type}>
        {array.type}
      </span>
      <span className="array-count">{array.values.length}</span>
    </>
  );
  return (
    <div
      className={`array-section ${array.presentation === "prefix" ? "prefix-section" : ""}`}
      data-variable={array.name}
      data-lifetime={array.lifetime?.state}
      title={array.name}
    >
      {array.collapsible ? (
        <button
          className="array-heading"
          aria-expanded={expanded}
          onClick={onToggle}
        >
          {heading}
        </button>
      ) : (
        <div className="array-heading">{heading}</div>
      )}
      {expanded && (
        <>
          {values.length > 0 ? (
            <div
              className={`array-cells ${array.presentation === "prefix" ? "prefix-cells" : ""}`}
              data-array-page={page}
            >
              {values.map((value, offset) => {
                const index = slice.start + offset;
                const birth = birthIndexes.has(index);
                const lifetime = array.cellLifetimes?.[index];
                return (
                  <div
                    className={`array-cell ${index === array.readingIndex ? "reading" : ""} ${index === array.changedIndex ? "changed" : ""} ${array.unvisitedFrom !== undefined && index >= array.unvisitedFrom ? "unvisited" : ""} ${birth ? "inspector-lifecycle-birth" : ""} ${lifetime?.state === "invalidated" ? "inspector-lifecycle-invalidated" : ""}`}
                    key={index}
                    data-value-cell
                    data-lifecycle={birth ? "birth" : undefined}
                    data-lifetime={lifetime?.state}
                  >
                    <span>{index}</span>
                    <strong>
                      <AnimatedValue value={value} />
                    </strong>
                    {index === array.readingIndex && <i />}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="inspector-array-empty">пусто</div>
          )}
          {slice.pages > 1 && (
            <div
              className="inspector-array-pagination"
              aria-label={`Страница массива ${array.name}`}
            >
              <button
                type="button"
                aria-label="Предыдущая страница"
                disabled={page <= 0}
                onClick={() => setManualPage(Math.max(0, page - 1))}
              >
                <ChevronLeft size={11} />
              </button>
              <span>
                {page + 1} / {slice.pages}
              </span>
              <button
                type="button"
                aria-label="Следующая страница"
                disabled={page >= slice.pages - 1}
                onClick={() =>
                  setManualPage(Math.min(slice.pages - 1, page + 1))
                }
              >
                <ChevronRight size={11} />
              </button>
            </div>
          )}
        </>
      )}
      {array.note && (
        <div className="array-note">
          <span className="legend-dot" /> {array.note.text}
          <span>
            Σ <AnimatedValue value={array.note.total} />
          </span>
        </div>
      )}
    </div>
  );
}

export default function InspectorScope({
  frame,
  fileName,
  line,
  transition,
  motion,
}: InspectorScopeProps) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [retired, setRetired] = useState<RetiredFrame[]>([]);
  const frameRef = useRef<InspectorFrame | null>(null);
  const frameIdRef = useRef<string | null>(null);
  const signatureRef = useRef<string | null>(null);
  const motionSignatureRef = useRef<string | null>(null);
  const retireTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const transitionKey = JSON.stringify(transition || null);
  const hasRetiredArrayIndexes = Object.values(
    transition?.retiredArrays || {},
  ).some((indexes) => indexes.length > 0);
  const signature = frameSignature(frame);
  const motionSignature = `${signature}|${transitionKey}`;
  const previous = signature !== signatureRef.current ? frameRef.current : null;
  const frameChanged = frame.id !== frameIdRef.current;
  const previousScalars = new Map(
    (previous?.scalars || []).map((value) => [value.id, value]),
  );
  const previousArrays = new Map(
    (previous?.arrays || []).map((value) => [value.id, value]),
  );
  const birthAllowed = transition?.kind !== "seek";
  const birthScalars = new Set(
    birthAllowed
      ? frame.scalars
          .filter((value) =>
            becameKnown(previousScalars.get(value.id)?.value, value.value),
          )
          .map((value) => value.id)
      : [],
  );
  const birthArrays = new Map(
    frame.arrays.map((array) => {
      const previousArray = previousArrays.get(array.id);
      const page = pageSlice(
        array.values.length,
        pageForIndex(
          array.values.length,
          array.readingIndex ?? array.changedIndex,
        ),
      );
      const indexes = new Set<number>();
      if (birthAllowed) {
        for (let index = page.start; index < page.end; index += 1) {
          if (becameKnown(previousArray?.values[index], array.values[index]))
            indexes.add(index);
        }
      }
      return [array.id, indexes] as const;
    }),
  );

  useLayoutEffect(() => {
    if (
      !frameChanged &&
      transition?.kind !== "seek" &&
      !(transition?.departedVariables?.length || hasRetiredArrayIndexes)
    ) {
      frameRef.current = frame;
      signatureRef.current = signature;
      return;
    }
    if (retireTimer.current) clearTimeout(retireTimer.current);
    const explicitForward = transition?.kind === "forward";
    const shouldRetire =
      explicitForward &&
      frameRef.current &&
      ((frameChanged && Boolean(transition?.departedFrame)) ||
        Boolean(transition?.departedVariables?.length) ||
        hasRetiredArrayIndexes);
    if (shouldRetire) {
      const record = retiredProjection(frameRef.current!, transition!);
      setRetired([record]);
      retireTimer.current = setTimeout(
        () =>
          setRetired((items) =>
            items.filter((item) => item.key !== record.key),
          ),
        retireDelay(
          window.matchMedia("(prefers-reduced-motion: reduce)").matches,
        ),
      );
    } else if (frameChanged || transition?.kind === "seek") {
      setRetired([]);
    }
    frameRef.current = frame;
    frameIdRef.current = frame.id;
    signatureRef.current = signature;
    return () => {
      if (retireTimer.current) clearTimeout(retireTimer.current);
    };
    // transitionKey is intentional: explicit lifetime metadata is an event, not an inferred diff.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [frame.id, signature, transitionKey]);

  // AnimatedValue uses a bounded Web Animation for every confirmed value
  // change. Register one frame-level hold so BASE mode also waits for births,
  // updates and focus flashes, not only for retired scopes/3D expressions.
  useLayoutEffect(() => {
    const changed = motionSignatureRef.current !== motionSignature;
    motionSignatureRef.current = motionSignature;
    if (!changed || transition?.kind !== "forward") return;
    return motion?.hold("inspector-values", 820);
  }, [motion, motionSignature, transition?.kind]);

  const scopeMotion = useChangeMotion<HTMLDivElement>(frame.id, "scope");
  return (
    <>
      {retired.map((item) => (
        <RetiredFrameView
          key={item.key}
          retired={item}
          fileName={fileName}
          line={line}
          motion={motion}
        />
      ))}
      <div
        data-testid="inspector-scope"
        data-frame-id={frame.id}
        data-function={frame.functionName}
      >
        <div>
          <div className="scope-label">
            <ChevronDown size={12} />
            <span>
              {frame.scalars.length > 0 &&
              frame.scalars.every((variable) => variable.kind === "argument") &&
              frame.arrays.length === 0
                ? "Аргументы"
                : "Локальная область"}
            </span>
            <span className="scope-line" />
            <span>
              {String(frame.scalars.length + frame.arrays.length).padStart(
                2,
                "0",
              )}
            </span>
          </div>
          {frame.scalars.length > 0 && (
            <div className="scalar-grid">
              {frame.scalars.map((variable) => (
                <ScalarCard
                  key={variable.id}
                  variable={variable}
                  birth={birthScalars.has(variable.id)}
                />
              ))}
            </div>
          )}
          {frame.arrays.map((array) => (
            <ArrayView
              key={array.id}
              array={array}
              collapsed={Boolean(collapsed[array.id])}
              onToggle={() =>
                setCollapsed((items) => ({
                  ...items,
                  [array.id]: !items[array.id],
                }))
              }
              birthIndexes={birthArrays.get(array.id) || new Set()}
            />
          ))}
        </div>
        <div className="stack-row" ref={scopeMotion}>
          <span className="stack-symbol">↳</span>
          <span>{frame.functionName}</span>
          <span>
            {fileName}:{line}
          </span>
          <span className="stack-badge">#0</span>
        </div>
      </div>
    </>
  );
}
