export type Theme = "noir" | "porcelain" | "spectral";
export type Preferences = {
  theme: Theme;
  font: "neon" | "krypton" | "xcode";
  fontSize: number;
  depth: boolean;
  sideWidth: number;
  variablesHeight: number;
  inputWidth: number;
  consoleHeight: number;
  spatialDepth: number;
  spatialLight: number;
  spatialHighlightBrightness: number;
  spatialWireframe: boolean;
  cameraFollow: boolean;
  inputFontSize: number;
  outputFontSize: number;
  debuggerNumberScale: number;
  debuggerNameScale: number;
  operationsPerSecond: number;
  playbackMode: "rate" | "base";
  spatialExpressionAnimations: boolean;
  expressionStyle: "float" | "rail" | "inline";
};
export const defaults: Preferences = {
  theme: "noir",
  font: "neon",
  fontSize: 18,
  depth: true,
  sideWidth: 33,
  variablesHeight: 72,
  inputWidth: 50,
  consoleHeight: 240,
  spatialDepth: 0.56,
  spatialLight: 3.4,
  spatialHighlightBrightness: 1,
  spatialWireframe: false,
  cameraFollow: true,
  inputFontSize: 14,
  outputFontSize: 14,
  debuggerNumberScale: 1.15,
  debuggerNameScale: 1.05,
  operationsPerSecond: 1,
  playbackMode: "rate",
  spatialExpressionAnimations: true,
  expressionStyle: "rail",
};
const clamp = (value: unknown, fallback: number, min: number, max: number) =>
  typeof value === "number" && Number.isFinite(value)
    ? Math.max(min, Math.min(max, value))
    : fallback;
export function readPrefs(): Preferences {
  try {
    let p: Record<string, unknown> = {};
    for (const key of ["phantom.preferences", "frame.preferences"]) {
      try {
        const stored = localStorage.getItem(key);
        if (!stored) continue;
        const candidate = JSON.parse(stored);
        if (
          candidate &&
          typeof candidate === "object" &&
          !Array.isArray(candidate)
        ) {
          p = candidate;
          break;
        }
      } catch {
        /* Fall back to the previous preference key if the new value is invalid. */
      }
    }
    return {
      theme:
        typeof p.theme === "string" &&
        ["noir", "porcelain", "spectral"].includes(p.theme)
          ? (p.theme as Theme)
          : defaults.theme,
      font:
        typeof p.font === "string" &&
        ["neon", "krypton", "xcode"].includes(p.font)
          ? (p.font as Preferences["font"])
          : defaults.font,
      fontSize: clamp(p.fontSize, 18, 13, 28),
      depth: typeof p.depth === "boolean" ? p.depth : true,
      sideWidth: clamp(p.sideWidth, 33, 24, 48),
      variablesHeight: clamp(p.variablesHeight, 72, 35, 80),
      inputWidth: clamp(p.inputWidth, 50, 28, 72),
      consoleHeight: clamp(p.consoleHeight, 240, 110, 600),
      spatialDepth: clamp(p.spatialDepth, 0.56, 0.03, 1.3),
      spatialLight: clamp(p.spatialLight, 3.4, 0.3, 7),
      spatialHighlightBrightness: clamp(p.spatialHighlightBrightness, 1, 0, 2),
      spatialWireframe: p.spatialWireframe === true,
      cameraFollow: p.cameraFollow !== false,
      inputFontSize: clamp(p.inputFontSize, 14, 10, 28),
      outputFontSize: clamp(p.outputFontSize, 14, 10, 28),
      debuggerNumberScale: clamp(p.debuggerNumberScale, defaults.debuggerNumberScale, 0.7, 1.8),
      debuggerNameScale: clamp(p.debuggerNameScale, defaults.debuggerNameScale, 0.7, 1.8),
      operationsPerSecond: clamp(p.operationsPerSecond, 1, 0.25, 12),
      playbackMode: p.playbackMode === "base" ? "base" : defaults.playbackMode,
      spatialExpressionAnimations: p.spatialExpressionAnimations !== false,
      expressionStyle: p.expressionStyle === "rail" || p.expressionStyle === "inline" || p.expressionStyle === "float" ? p.expressionStyle : defaults.expressionStyle,
    };
  } catch {
    return defaults;
  }
}
export const themes = [
  { id: "noir" as Theme, name: "Obsidian", desc: "Тёмное стекло", num: "01" },
  {
    id: "porcelain" as Theme,
    name: "Porcelain",
    desc: "Свет и керамика",
    num: "02",
  },
  {
    id: "spectral" as Theme,
    name: "Spectral",
    desc: "Код в пространстве",
    num: "03",
  },
];
