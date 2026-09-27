import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import type { InputTrace } from "./backend-contract";
import "./input-panel.css";

export type InputPanelProps = {
  value: string;
  onChange: (value: string) => void;
  trace: InputTrace | null;
  font?: "neon" | "krypton" | "xcode";
};
type InputRect = {
  key: string;
  state: "active" | "consumed";
  left: number;
  top: number;
  width: number;
  height: number;
};
const fontFamilies = {
  neon: '"Monaspace Neon", "SFMono-Regular", Menlo, monospace',
  krypton: '"Monaspace Krypton", "SFMono-Regular", Menlo, monospace',
  xcode: '"SFMono-Regular", Menlo, monospace',
};

/** InputTrace is supplied by the backend/demo adapter; this view never parses or infers cin reads. */
export default function InputPanel({
  value,
  onChange,
  trace,
  font,
}: InputPanelProps) {
  const host = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);
  const mirror = useRef<HTMLDivElement>(null);
  const text = useRef<HTMLSpanElement>(null);
  const latest = useRef({ value, trace });
  latest.current = { value, trace };
  const [rectangles, setRectangles] = useState<InputRect[]>([]);
  const matchingTrace = trace?.revision === value ? trace : null;

  const measure = useCallback(() => {
    const textarea = input.current,
      plane = host.current,
      pre = mirror.current,
      textNode = text.current?.firstChild;
    if (!textarea || !plane || !pre || !textNode) return;
    pre.style.width = `${textarea.clientWidth}px`;
    pre.style.transform = `translate(${-textarea.scrollLeft}px, ${-textarea.scrollTop}px)`;
    const current = latest.current;
    const validTrace =
      current.trace?.revision === current.value ? current.trace : null;
    const bounds = plane.getBoundingClientRect();
    const next: InputRect[] = [];
    const ranges = validTrace
      ? [
          ...validTrace.consumedRanges.map((range, index) => ({
            ...range,
            state: "consumed" as const,
            key: `consumed-${index}`,
          })),
          ...(validTrace.activeRange
            ? [
                {
                  ...validTrace.activeRange,
                  state: "active" as const,
                  key: "active",
                },
              ]
            : []),
        ]
      : [];
    for (const range of ranges) {
      if (
        !Number.isInteger(range.start) ||
        !Number.isInteger(range.end) ||
        range.start < 0 ||
        range.end < range.start ||
        range.end > current.value.length
      )
        continue;
      if (range.start === range.end && range.state !== "active") continue;
      const selection = document.createRange();
      selection.setStart(textNode, range.start);
      selection.setEnd(textNode, range.end);
      // A single text node preserves original tabs/spaces/newlines and naturally yields wrapped-line rectangles.
      Array.from(selection.getClientRects()).forEach((rect, index) => {
        if (
          !rect.height ||
          rect.bottom < bounds.top ||
          rect.top > bounds.bottom
        )
          return;
        next.push({
          key: `${range.key}-${index}`,
          state: range.state,
          left: rect.left - bounds.left - 1,
          top: rect.top - bounds.top - 1,
          width: Math.max(range.state === "active" ? 3 : 0, rect.width + 2),
          height: rect.height + 2,
        });
      });
    }
    setRectangles((previous) =>
      previous.length === next.length &&
      previous.every((rect, index) => {
        const candidate = next[index];
        return (
          rect.key === candidate.key &&
          rect.state === candidate.state &&
          rect.left === candidate.left &&
          rect.top === candidate.top &&
          rect.width === candidate.width &&
          rect.height === candidate.height
        );
      })
        ? previous
        : next,
    );
  }, []);

  // Parent renders also cover inherited font-size changes without guessing glyph advances.
  useLayoutEffect(() => {
    measure();
  });
  useEffect(() => {
    const node = host.current;
    if (!node) return;
    let active = true;
    const update = () => {
      if (active) measure();
    };
    const observer = new ResizeObserver(update);
    observer.observe(node);
    document.fonts.addEventListener("loadingdone", update);
    void document.fonts.ready.then(update);
    return () => {
      active = false;
      observer.disconnect();
      document.fonts.removeEventListener("loadingdone", update);
    };
  }, [measure]);

  const style = font
    ? ({ "--stdin-font": fontFamilies[font] } as CSSProperties)
    : undefined;
  return (
    <div
      className="input-trace-editor"
      ref={host}
      style={style}
      data-testid="input-panel"
      data-trace-status={matchingTrace?.status ?? "idle"}
    >
      <div
        className="input-trace-overlay"
        aria-hidden="true"
        data-testid="input-trace-overlay"
      >
        {rectangles.map((rect) => (
          <span
            key={rect.key}
            className={`input-trace-rect input-trace-${rect.state}`}
            data-input-state={rect.state}
            style={{
              left: rect.left,
              top: rect.top,
              width: rect.width,
              height: rect.height,
            }}
          />
        ))}
      </div>
      <div ref={mirror} className="input-trace-mirror" aria-hidden="true">
        <span ref={text}>
          {value}
          {"\u200b"}
        </span>
      </div>
      <textarea
        ref={input}
        className="input-trace-textarea"
        aria-label="Входные данные"
        data-testid="stdin-editor"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={measure}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        wrap="soft"
      />
    </div>
  );
}
