import {
  useRef,
  useEffect,
  type PointerEvent as ReactPointerEvent,
} from "react";
export default function Separator({
  label,
  direction = "vertical",
  value,
  onChange,
  min,
  max,
  container,
  invert = false,
}: {
  label: string;
  direction?: "vertical" | "horizontal";
  value: number;
  onChange: (n: number) => void;
  min: number;
  max: number;
  container: React.RefObject<HTMLElement | null>;
  invert?: boolean;
}) {
  const cleanup = useRef<(() => void) | null>(null);
  useEffect(() => () => cleanup.current?.(), []);
  function begin(e: ReactPointerEvent<HTMLDivElement>) {
    e.preventDefault();
    cleanup.current?.();
    const box = container.current?.getBoundingClientRect();
    if (!box) return;
    const start = direction === "vertical" ? e.clientX : e.clientY;
    const size = direction === "vertical" ? box.width : box.height;
    const move = (ev: PointerEvent) => {
      const n = direction === "vertical" ? ev.clientX : ev.clientY;
      onChange(
        Math.max(
          min,
          Math.min(max, value + ((n - start) / size) * 100 * (invert ? -1 : 1)),
        ),
      );
    };
    const stop = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", stop);
      document.body.classList.remove("resizing");
    };
    cleanup.current = stop;
    document.body.classList.add("resizing");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop, { once: true });
  }
  return (
    <div
      className={`separator ${direction}`}
      role="separator"
      aria-label={label}
      aria-orientation={direction}
      aria-valuenow={Math.round(value)}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onPointerDown={begin}
      onKeyDown={(e) => {
        if (
          ["ArrowLeft", "ArrowUp", "ArrowRight", "ArrowDown"].includes(e.key)
        ) {
          e.preventDefault();
          const d = ["ArrowLeft", "ArrowUp"].includes(e.key) ? -2 : 2;
          onChange(Math.max(min, Math.min(max, value + d * (invert ? -1 : 1))));
        }
      }}
    >
      <span />
    </div>
  );
}
