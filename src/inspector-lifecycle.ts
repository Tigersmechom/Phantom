/** Pure presentation lifecycle helpers. They never infer a death from a missing value. */
export type LifecycleDirection = "forward" | "seek";

export interface InspectorTransition {
  kind: LifecycleDirection;
  /** A caller frame left because execution returned from it. */
  departedFrame?: boolean;
  /** Explicitly retired variable IDs. Missing IDs are never treated as deaths. */
  departedVariables?: string[];
  /** Explicitly retired array indexes, by array ID. */
  retiredArrays?: Record<string, number[]>;
}

export const INSPECTOR_PAGE_SIZE = 128;
// The longest ordinary cascade is 300ms of stagger plus the 980ms card
// choreography. Keep the retired lane mounted until both have finished.
export const INSPECTOR_RETIRE_MS = 1_500;

export const isKnownValue = (value: unknown): boolean =>
  value !== null && value !== undefined;

export function becameKnown(previous: unknown, current: unknown): boolean {
  return !isKnownValue(previous) && isKnownValue(current);
}

export function pageForIndex(
  length: number,
  focusIndex: number | undefined,
  pageSize = INSPECTOR_PAGE_SIZE,
): number {
  if (length <= 0 || !Number.isFinite(focusIndex ?? 0)) return 0;
  const bounded = Math.max(
    0,
    Math.min(length - 1, Math.floor(focusIndex ?? 0)),
  );
  return Math.floor(bounded / Math.max(1, pageSize));
}

export function pageSlice(
  length: number,
  page: number,
  pageSize = INSPECTOR_PAGE_SIZE,
): { start: number; end: number; pages: number } {
  const size = Math.max(1, Math.floor(pageSize));
  const pages = Math.max(1, Math.ceil(Math.max(0, length) / size));
  const requested = Number.isFinite(page) ? Math.floor(page) : 0;
  const safePage = Math.max(0, Math.min(pages - 1, requested));
  return {
    start: safePage * size,
    end: Math.min(length, (safePage + 1) * size),
    pages,
  };
}

export function retireDelay(reducedMotion: boolean): number {
  return reducedMotion ? 0 : INSPECTOR_RETIRE_MS;
}
