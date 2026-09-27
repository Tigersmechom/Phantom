import { useSyncExternalStore } from "react";

/**
 * Coordinates finite presentation effects without making them authoritative
 * execution state.  The debugger can continue recording while the UI waits.
 * Every hold has a hard deadline so a broken CSS/Web Animation can never stop
 * playback forever.
 */
export type PresentationMotion = {
  hold: (label: string, maxMs: number) => () => void;
  track: (animation: Animation | PromiseLike<unknown>, maxMs?: number) => () => void;
  waitForSettled: (maxMs?: number) => Promise<void>;
  reset: () => void;
  generation: () => number;
};
/** Stable name for backend/frontend adapters that treat presentation as a coordinator. */
export type PresentationCoordinator = PresentationMotion;

type Hold = { generation: number; expires: number; release: () => void };

const listeners = new Set<() => void>();
const holds = new Set<Hold>();
let currentGeneration = 0;
let version = 0;

function notify() {
  version += 1;
  listeners.forEach((listener) => listener());
}

function releaseHold(hold: Hold) {
  if (!holds.delete(hold)) return;
  notify();
}

function hold(label: string, maxMs: number) {
  void label;
  const generation = currentGeneration;
  // A base-mode expression can contain several recorded groups. Keep the
  // deadline finite, but do not truncate a legitimate long educational
  // sequence (12 rail groups are ~40 seconds at the deliberate pace).
  const duration = Math.max(0, Math.min(120_000, Number.isFinite(maxMs) ? maxMs : 0));
  const holdRecord = {} as Hold;
  holdRecord.generation = generation;
  holdRecord.expires = performance.now() + duration;
  let released = false;
  let release = () => {};
  const timer = window.setTimeout(() => release(), duration);
  release = () => {
    if (released) return;
    released = true;
    window.clearTimeout(timer);
    releaseHold(holdRecord);
  };
  holdRecord.release = release;
  holds.add(holdRecord);
  notify();
  return release;
}

function track(animation: Animation | PromiseLike<unknown>, maxMs = 12_000) {
  const release = hold("web-animation", maxMs);
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    release();
  };
  const finished = "finished" in animation ? animation.finished : animation;
  Promise.resolve(finished).then(finish, finish);
  return finish;
}

function reset() {
  currentGeneration += 1;
  [...holds].forEach((item) => item.release());
  notify();
}

function waitForSettled(maxMs = 120_000) {
  const deadline = performance.now() + Math.max(0, Math.min(120_000, maxMs));
  const generation = currentGeneration;
  return new Promise<void>((resolve) => {
    let frames = 0;
    let timer = 0;
    const check = () => {
      const now = performance.now();
      for (const item of [...holds]) {
        if (item.expires <= now) item.release();
      }
      const active = [...holds].some((item) => item.generation === generation);
      // Let child layout/passive effects register the current transition first.
      if ((!active && frames >= 2) || now >= deadline || generation !== currentGeneration) {
        window.cancelAnimationFrame(timer);
        resolve();
        return;
      }
      frames += 1;
      timer = window.requestAnimationFrame(check);
    };
    timer = window.requestAnimationFrame(check);
  });
}

export const presentationMotion: PresentationMotion = {
  hold,
  track,
  waitForSettled,
  reset,
  generation: () => currentGeneration,
};

/** Hook-shaped API keeps animation components independent of App and Electron. */
export function usePresentationMotion(): PresentationMotion {
  useSyncExternalStore(
    (onStoreChange) => {
      listeners.add(onStoreChange);
      return () => listeners.delete(onStoreChange);
    },
    () => version,
    () => 0,
  );
  return presentationMotion;
}
