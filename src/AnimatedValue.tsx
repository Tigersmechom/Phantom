import { useEffect, useLayoutEffect, useRef } from "react";

type Bounds = { left: number; right: number; top: number; bottom: number };
const keepInside = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), Math.max(min, max));
let metricsCanvas: HTMLCanvasElement | null = null;

function motionBounds(node: HTMLElement): Bounds {
  const strong = node.closest<HTMLElement>("strong");
  const cell = node.closest<HTMLElement>("[data-value-cell]");
  const container = strong || node.parentElement || node;
  const rect = container.getBoundingClientRect();
  const style = getComputedStyle(container);
  const inset = strong ? 3 : 0;
  const bounds = {
    left: rect.left + parseFloat(style.borderLeftWidth || "0") + inset,
    right: rect.right - parseFloat(style.borderRightWidth || "0") - inset,
    top: rect.top + parseFloat(style.borderTopWidth || "0") + inset,
    bottom: rect.bottom - parseFloat(style.borderBottomWidth || "0") - inset,
  };
  if (cell?.classList.contains("scalar-card")) {
    const header = cell.querySelector<HTMLElement>(":scope > div");
    const caption = cell.querySelector<HTMLElement>(":scope > small");
    if (header) bounds.top = header.getBoundingClientRect().bottom + 3;
    if (caption) bounds.bottom = caption.getBoundingClientRect().top - 3;
    const unit = strong?.querySelector<HTMLElement>(".value-unit");
    if (unit)
      bounds.right = Math.min(
        bounds.right,
        unit.getBoundingClientRect().left - 4,
      );
  } else if (!strong) {
    // Inline totals sit next to labels such as Σ; keep their motion inside their own text slot.
    const own = node.getBoundingClientRect();
    bounds.left = own.left;
  }
  return bounds;
}

function fitRestingValue(node: HTMLElement) {
  if (!node.classList.contains("motion-value")) return;
  node.style.fontSize = "";
  const strong = node.closest<HTMLElement>("strong");
  if (!strong) return;
  const bounds = motionBounds(node);
  const available = Math.max(1, bounds.right - bounds.left);
  const width = node.offsetWidth;
  if (width > available) {
    const size = parseFloat(getComputedStyle(node).fontSize);
    node.style.fontSize = `${(size * available) / width}px`;
  }
}

function measureValuePop(node: HTMLElement) {
  const own = node.getBoundingClientRect();
  const style = getComputedStyle(node);
  const bounds = motionBounds(node);
  let ink: Bounds = {
    left: own.left,
    right: own.right,
    top: own.top,
    bottom: own.bottom,
  };
  metricsCanvas ||= document.createElement("canvas");
  const context = metricsCanvas.getContext("2d");
  const baseline = node.querySelector<HTMLElement>(".motion-value-baseline");
  if (context && baseline) {
    context.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    context.letterSpacing =
      style.letterSpacing === "normal" ? "0px" : style.letterSpacing;
    const metrics = context.measureText(
      node.dataset.value || node.textContent || "",
    );
    const y = baseline.getBoundingClientRect().top;
    if (
      metrics.actualBoundingBoxAscent + metrics.actualBoundingBoxDescent >
      0
    ) {
      ink = {
        left: Math.min(own.left, own.left - metrics.actualBoundingBoxLeft),
        right: Math.max(own.right, own.left + metrics.actualBoundingBoxRight),
        top: y - metrics.actualBoundingBoxAscent,
        bottom: y + metrics.actualBoundingBoxDescent,
      };
    }
  }
  const width = Math.max(1, ink.right - ink.left),
    height = Math.max(1, ink.bottom - ink.top);
  const availableWidth = Math.max(1, bounds.right - bounds.left),
    availableHeight = Math.max(1, bounds.bottom - bounds.top);
  const scale = Math.min(4, availableWidth / width, availableHeight / height);
  const originX = own.left + own.width / 2,
    originY = own.top + own.height / 2;
  const left = originX + (ink.left - originX) * scale,
    right = originX + (ink.right - originX) * scale;
  const top = originY + (ink.top - originY) * scale,
    bottom = originY + (ink.bottom - originY) * scale;
  const x = keepInside(0, bounds.left - left, bounds.right - right);
  const y = keepInside(
    -Math.min(8, availableHeight * 0.14),
    bounds.top - top,
    bounds.bottom - bottom,
  );
  return { scale, x, y, width: availableWidth, height: availableHeight };
}

export function formatDebugValue(value: number | string | null | undefined) {
  // Missing/unavailable slots are NaN in the presentation layer. A known zero
  // (including vector<int>(n, 0)) stays zero. Never invent memory contents.
  return value == null || (typeof value === "number" && Number.isNaN(value))
    ? "NaN"
    : String(value);
}

export function useChangeMotion<T extends HTMLElement = HTMLElement>(
  value: unknown,
  kind: "value" | "scope" | "output",
) {
  const element = useRef<T>(null);
  const previous = useRef(value);
  const running = useRef<Animation[]>([]);
  const lastSize = useRef({ width: 0, height: 0 });
  useLayoutEffect(() => {
    const node = element.current;
    if (!node || kind !== "value") return;
    const container =
      node.closest<HTMLElement>("strong") || node.parentElement || node;
    const update = () => {
      const rect = container.getBoundingClientRect();
      if (
        rect.width !== lastSize.current.width ||
        rect.height !== lastSize.current.height
      ) {
        running.current.forEach((animation) => animation.cancel());
        fitRestingValue(node);
        lastSize.current = { width: rect.width, height: rect.height };
      }
    };
    fitRestingValue(node);
    const initial = container.getBoundingClientRect();
    lastSize.current = { width: initial.width, height: initial.height };
    const observer = new ResizeObserver(update);
    observer.observe(container);
    document.fonts.addEventListener("loadingdone", update);
    return () => {
      observer.disconnect();
      document.fonts.removeEventListener("loadingdone", update);
    };
  }, [kind]);
  useEffect(() => {
    const query = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      if (query.matches)
        running.current.forEach((animation) => animation.cancel());
    };
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  useLayoutEffect(() => {
    const changed = !Object.is(previous.current, value);
    previous.current = value;
    const node = element.current;
    if (!node || !changed) return;
    if (kind === "value") {
      fitRestingValue(node);
      const container =
        node.closest<HTMLElement>("strong") || node.parentElement || node;
      const rect = container.getBoundingClientRect();
      lastSize.current = { width: rect.width, height: rect.height };
    }
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const animations: Animation[] = [];
    node.dataset.changeCount = String(
      Number(node.dataset.changeCount || 0) + 1,
    );
    if (!reduced) {
      const pop = kind === "value" ? measureValuePop(node) : null;
      if (pop) {
        node.dataset.motionScale = pop.scale.toFixed(4);
        node.dataset.motionLift = pop.y.toFixed(3);
        node.dataset.motionBoundWidth = pop.width.toFixed(3);
        node.dataset.motionBoundHeight = pop.height.toFixed(3);
      }
      animations.push(
        node.animate(
          kind === "value"
            ? [
                { transform: "translateY(0) scale(1)", offset: 0 },
                {
                  transform: `translate(${pop?.x ?? 0}px, ${pop?.y ?? 0}px) scale(${pop?.scale ?? 1})`,
                  offset: 0.2,
                  easing: "cubic-bezier(.18,.8,.3,1)",
                },
                {
                  transform: "translate(0, 0) scale(.985)",
                  offset: 0.7,
                  easing: "ease-out",
                },
                { transform: "translateY(0) scale(1)", offset: 1 },
              ]
            : [
                {
                  opacity: 0.5,
                  transform:
                    kind === "scope" ? "translateX(-5px)" : "translateY(4px)",
                },
                { opacity: 1, transform: "translate(0)", offset: 0.7 },
                { opacity: 1, transform: "translate(0)" },
              ],
          {
            duration: kind === "value" ? 680 : 450,
            easing: "cubic-bezier(.2,.7,.25,1)",
          },
        ),
      );
    }
    const cell = node.closest<HTMLElement>("[data-value-cell]");
    const target = cell?.classList.contains("array-cell")
      ? cell.querySelector<HTMLElement>("strong") || cell
      : cell || node;
    const accent =
      getComputedStyle(node).getPropertyValue("--accent").trim() || "#bde8dd";
    animations.push(
      target.animate(
        [
          { boxShadow: `inset 0 0 0 1px transparent, 0 0 0 transparent` },
          {
            boxShadow: `inset 0 0 0 1px ${accent}, 0 0 18px color-mix(in srgb, ${accent} 20%, transparent)`,
            offset: 0.15,
          },
          { boxShadow: `inset 0 0 0 1px transparent, 0 0 0 transparent` },
        ],
        { duration: reduced ? 160 : 750, easing: "ease-out" },
      ),
    );
    running.current = animations;
    return () => animations.forEach((animation) => animation.cancel());
  }, [value, kind]);
  return element;
}

export default function AnimatedValue({
  value,
}: {
  value: number | string | null | undefined;
}) {
  const text = formatDebugValue(value);
  const motion = useChangeMotion(text, "value");
  return (
    <span
      className={`motion-value ${text === "NaN" ? "is-unavailable" : ""}`}
      ref={motion}
      data-value={text}
    >
      {text}
      <span className="motion-value-baseline" aria-hidden="true" />
    </span>
  );
}
