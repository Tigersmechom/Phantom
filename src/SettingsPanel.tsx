import { useCallback, useEffect, useRef, useState } from "react";
import {
  X,
  Minus,
  Plus,
  RotateCcw,
  Palette,
  Box,
  Hammer,
  Check,
} from "lucide-react";
import { themes, type Preferences } from "./preferences";
import type { BuildConfig } from "./native";
import "./settings.css";

export const defaultBuildConfig: BuildConfig = {
  version: 1,
  compiler: "/usr/bin/clang++",
  flags: ["-std=c++20", "-g", "-O0", "-Wall", "-Wextra"],
  outputDirectory: ".frame/build",
};

export type SettingsPanelProps = {
  prefs: Preferences;
  update: (p: Partial<Preferences>) => void;
  close: () => void;
  config: BuildConfig;
  configError?: string;
  native: boolean;
  saveConfig: (c: BuildConfig) => Promise<void>;
  resetCamera: () => void;
  showSpatial: () => void;
  busy: boolean;
};
type SettingsTab = "appearance" | "spatial" | "build";
const parseFlags = (text: string) =>
  text
    .split("\n")
    .map((flag) => flag.trim())
    .filter(Boolean);
const serializeFlags = (text: string) => JSON.stringify(parseFlags(text));

export default function SettingsPanel({
  prefs,
  update,
  close,
  config,
  configError,
  native,
  saveConfig,
  resetCamera,
  showSpatial,
  busy,
}: SettingsPanelProps) {
  const [tab, setTab] = useState<SettingsTab>("appearance");
  const [flags, setFlags] = useState(config.flags.join("\n"));
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const mounted = useRef(true);
  const draft = useRef(flags);
  const lastSaved = useRef(JSON.stringify(config.flags));
  const pending = useRef<Promise<boolean> | null>(null);
  const latest = useRef({ config, native, saveConfig, busy });
  latest.current = { config, native, saveConfig, busy };

  useEffect(() => {
    const previous = lastSaved.current;
    const incoming = JSON.stringify(config.flags);
    lastSaved.current = incoming;
    // A save response must not overwrite a newer draft. External updates replace only a clean draft.
    if (!pending.current && serializeFlags(draft.current) === previous) {
      draft.current = config.flags.join("\n");
      setFlags(draft.current);
    }
  }, [config]);

  const flushFlags = useCallback((): Promise<boolean> => {
    if (pending.current) return pending.current;
    const flagValues = parseFlags(draft.current);
    const serialized = JSON.stringify(flagValues);
    if (serialized === lastSaved.current) return Promise.resolve(true);
    const current = latest.current;
    if (!current.native || current.busy) return Promise.resolve(false);
    if (mounted.current) {
      setSaving(true);
      setSaved(false);
      setError("");
    }
    // Call synchronously from blur so the app can await its config-save promise before compiling.
    let request: Promise<void>;
    try {
      request = current.saveConfig({ ...current.config, flags: flagValues });
    } catch (reason) {
      request = Promise.reject(reason);
    }
    const operation = request
      .then(() => {
        lastSaved.current = serialized;
        if (mounted.current) setSaved(true);
        return true;
      })
      .catch((reason) => {
        if (mounted.current)
          setError(reason instanceof Error ? reason.message : String(reason));
        return false;
      })
      .finally(() => {
        pending.current = null;
        if (mounted.current) setSaving(false);
      });
    pending.current = operation;
    return operation;
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      // Escape and the toolbar can unmount the panel without clicking its own close button.
      void flushFlags();
    };
  }, [flushFlags]);

  async function closePanel() {
    if (await flushFlags()) close();
    else if (mounted.current) setTab("build");
  }
  async function changeTab(next: SettingsTab) {
    if (tab !== "build" || (await flushFlags())) setTab(next);
  }

  return (
    <>
      <button
        className="popover-backdrop"
        aria-label="Закрыть настройки"
        onClick={() => void closePanel()}
      />
      <section
        className="settings-popover"
        role="dialog"
        aria-label="Настройки phantom"
      >
        <div className="popover-title">
          <span>phantom</span>
          <button
            className="icon-button"
            onClick={() => void closePanel()}
            aria-label="Закрыть настройки типографики"
          >
            <X size={14} />
          </button>
        </div>
        <div
          className="settings-tabs"
          role="tablist"
          aria-label="Раздел настроек"
        >
          <button
            role="tab"
            aria-selected={tab === "appearance"}
            onClick={() => void changeTab("appearance")}
          >
            <Palette size={12} />
            Вид
          </button>
          <button
            role="tab"
            aria-selected={tab === "spatial"}
            onClick={() => void changeTab("spatial")}
          >
            <Box size={12} />
            3D и камера
          </button>
          <button
            role="tab"
            aria-selected={tab === "build"}
            onClick={() => void changeTab("build")}
          >
            <Hammer size={12} />
            Сборка
          </button>
        </div>
        <div className="settings-content">
          {tab === "appearance" && (
            <div role="tabpanel" aria-label="Внешний вид">
              <div className="setting-section-title">ОФОРМЛЕНИЕ</div>
              <div className="theme-options">
                {themes.map((theme) => (
                  <button
                    key={theme.id}
                    className={`theme-option ${prefs.theme === theme.id ? "chosen" : ""}`}
                    onClick={() => update({ theme: theme.id })}
                    aria-pressed={prefs.theme === theme.id}
                  >
                    <span className={`theme-swatch swatch-${theme.id}`}>
                      <i />
                      <i />
                      <i />
                    </span>
                    <span>
                      <b>{theme.name}</b>
                    </span>
                    {prefs.theme === theme.id && <Check size={12} />}
                  </button>
                ))}
              </div>
              <label>
                Гарнитура
                <select
                  aria-label="Гарнитура"
                  value={prefs.font}
                  onChange={(event) =>
                    update({ font: event.target.value as Preferences["font"] })
                  }
                >
                  <option value="neon">Monaspace Neon</option>
                  <option value="krypton">Monaspace Krypton</option>
                  <option value="xcode">SF Mono / системный</option>
                </select>
              </label>
              <label>
                Размер кода
                <span className="size-stepper">
                  <button
                    disabled={prefs.fontSize <= 13}
                    onClick={() =>
                      update({ fontSize: Math.max(13, prefs.fontSize - 1) })
                    }
                    aria-label="Уменьшить шрифт"
                  >
                    <Minus size={13} />
                  </button>
                  <output>{prefs.fontSize}</output>
                  <button
                    disabled={prefs.fontSize >= 28}
                    onClick={() =>
                      update({ fontSize: Math.min(28, prefs.fontSize + 1) })
                    }
                    aria-label="Увеличить шрифт"
                  >
                    <Plus size={13} />
                  </button>
                </span>
              </label>
              <label>
                Рельеф в редакторе
                <button
                  role="switch"
                  aria-label="Рельеф в редакторе"
                  aria-checked={prefs.depth}
                  className={`switch ${prefs.depth ? "on" : ""}`}
                  onClick={() => update({ depth: !prefs.depth })}
                >
                  <i />
                </button>
              </label>
              <div className="setting-section-title">ВВОД И ВЫВОД</div>
              <label>
                Размер ввода
                <span className="size-stepper">
                  <button
                    disabled={prefs.inputFontSize <= 10}
                    onClick={() =>
                      update({
                        inputFontSize: Math.max(10, prefs.inputFontSize - 1),
                      })
                    }
                    aria-label="Уменьшить размер ввода"
                  >
                    <Minus size={13} />
                  </button>
                  <output>{prefs.inputFontSize}</output>
                  <button
                    disabled={prefs.inputFontSize >= 28}
                    onClick={() =>
                      update({
                        inputFontSize: Math.min(28, prefs.inputFontSize + 1),
                      })
                    }
                    aria-label="Увеличить размер ввода"
                  >
                    <Plus size={13} />
                  </button>
                </span>
              </label>
              <label>
                Размер вывода
                <span className="size-stepper">
                  <button
                    disabled={prefs.outputFontSize <= 10}
                    onClick={() =>
                      update({
                        outputFontSize: Math.max(10, prefs.outputFontSize - 1),
                      })
                    }
                    aria-label="Уменьшить размер вывода"
                  >
                    <Minus size={13} />
                  </button>
                  <output>{prefs.outputFontSize}</output>
                  <button
                    disabled={prefs.outputFontSize >= 28}
                    onClick={() =>
                      update({
                        outputFontSize: Math.min(28, prefs.outputFontSize + 1),
                      })
                    }
                    aria-label="Увеличить размер вывода"
                  >
                    <Plus size={13} />
                  </button>
                </span>
              </label>
              <div className="setting-section-title">ДЕБАГГЕР</div>
              <label className="range-setting">
                <span>
                  Числа<output>{prefs.debuggerNumberScale.toFixed(2)}×</output>
                </span>
                <input
                  aria-label="Масштаб чисел в дебаггере"
                  type="range"
                  min=".7"
                  max="1.8"
                  step=".05"
                  value={prefs.debuggerNumberScale}
                  onChange={(event) =>
                    update({ debuggerNumberScale: Number(event.target.value) })
                  }
                />
              </label>
              <label className="range-setting">
                <span>
                  Названия<output>{prefs.debuggerNameScale.toFixed(2)}×</output>
                </span>
                <input
                  aria-label="Масштаб названий в дебаггере"
                  type="range"
                  min=".7"
                  max="1.8"
                  step=".05"
                  value={prefs.debuggerNameScale}
                  onChange={(event) =>
                    update({ debuggerNameScale: Number(event.target.value) })
                  }
                />
              </label>
            </div>
          )}
          {tab === "spatial" && (
            <div role="tabpanel" aria-label="3D и камера">
              <div className="setting-section-title">РЕЗУЛЬТАТЫ ВЫЧИСЛЕНИЙ</div>
              <div className="expression-style-options" role="group" aria-label="Расположение результатов в 3D">
                {([
                  { id: "float", name: "Над выражением", hint: "Небольшие значения над кодом" },
                  { id: "rail", name: "На полях", hint: "Рядом со строкой, с тонкой связью" },
                  { id: "inline", name: "В плоскости", hint: "Подсказка следует наклону кода" },
                ] as const).map((variant) => <button
                  key={variant.id}
                  className={`expression-style-option preview-${variant.id}`}
                  aria-label={`Результаты: ${variant.name}`}
                  aria-pressed={prefs.expressionStyle === variant.id}
                  title={variant.hint}
                  onClick={() => { update({ expressionStyle: variant.id }); showSpatial(); }}
                >
                  <span className="expression-style-preview" aria-hidden="true"><i /><i /><i /><b>3</b><em /></span>
                  <span>{variant.name}</span>
                </button>)}
              </div>
              <div className="setting-section-title">БУКВЫ И СВЕТ</div>
              <label>
                Анимации вычислений
                <button
                  role="switch"
                  aria-label="Анимации вычислений"
                  aria-checked={prefs.spatialExpressionAnimations}
                  className={`switch ${prefs.spatialExpressionAnimations ? "on" : ""}`}
                  onClick={() =>
                    update({ spatialExpressionAnimations: !prefs.spatialExpressionAnimations })
                  }
                >
                  <i />
                </button>
              </label>
              <label className="range-setting">
                <span>
                  Глубина<output>{prefs.spatialDepth.toFixed(2)}</output>
                </span>
                <input
                  aria-label="Глубина 3D"
                  type="range"
                  min=".03"
                  max="1.3"
                  step=".01"
                  value={prefs.spatialDepth}
                  onChange={(event) =>
                    update({ spatialDepth: Number(event.target.value) })
                  }
                />
              </label>
              <label className="range-setting">
                <span>
                  Свет<output>{prefs.spatialLight.toFixed(1)}</output>
                </span>
                <input
                  aria-label="Свет 3D"
                  type="range"
                  min=".3"
                  max="7"
                  step=".1"
                  value={prefs.spatialLight}
                  onChange={(event) =>
                    update({ spatialLight: Number(event.target.value) })
                  }
                />
              </label>
              <label
                className="range-setting"
                htmlFor="spatial-highlight-brightness"
              >
                <span>
                  Яркость полоски
                  <output>
                    {Math.round(prefs.spatialHighlightBrightness * 100)}%
                  </output>
                </span>
                <input
                  id="spatial-highlight-brightness"
                  aria-label="Яркость полоски"
                  type="range"
                  min="0"
                  max="2"
                  step=".05"
                  value={prefs.spatialHighlightBrightness}
                  onChange={(event) =>
                    update({
                      spatialHighlightBrightness: Number(event.target.value),
                    })
                  }
                />
              </label>
              <label>
                Каркас букв
                <button
                  role="switch"
                  aria-label="Каркас букв"
                  aria-checked={prefs.spatialWireframe}
                  className={`switch ${prefs.spatialWireframe ? "on" : ""}`}
                  onClick={() =>
                    update({ spatialWireframe: !prefs.spatialWireframe })
                  }
                >
                  <i />
                </button>
              </label>
              <div className="setting-section-title">КАМЕРА</div>
              <label>
                Следовать за строкой
                <button
                  role="switch"
                  aria-label="Камера следует за строкой"
                  aria-checked={prefs.cameraFollow}
                  className={`switch ${prefs.cameraFollow ? "on" : ""}`}
                  onClick={() => update({ cameraFollow: !prefs.cameraFollow })}
                >
                  <i />
                </button>
              </label>
              <div className="settings-actions">
                <button
                  className="subtle-button"
                  onClick={resetCamera}
                  aria-label="Сбросить камеру"
                >
                  <RotateCcw size={12} />
                  Сбросить камеру
                </button>
                <button
                  className="subtle-button"
                  onClick={async () => {
                    if (await flushFlags()) {
                      showSpatial();
                      close();
                    }
                  }}
                >
                  <Box size={12} />
                  Открыть 3D
                </button>
              </div>
            </div>
          )}
          {tab === "build" && (
            <div role="tabpanel" aria-label="Параметры сборки">
              <label className="stacked-setting">
                Флаги компиляции<small>Один аргумент на строку</small>
                <textarea
                  aria-label="Флаги компиляции"
                  aria-describedby="build-flags-status"
                  data-build-flags
                  value={flags}
                  disabled={!native || busy || saving}
                  onChange={(event) => {
                    draft.current = event.target.value;
                    setFlags(event.target.value);
                    setSaved(false);
                    setError("");
                  }}
                  onBlur={() => void flushFlags()}
                  rows={9}
                  spellCheck={false}
                />
              </label>
              <div
                className="settings-save-status"
                id="build-flags-status"
                role="status"
                aria-live="polite"
              >
                {!native
                  ? "Доступно в приложении phantom"
                  : saving
                    ? "Сохраняется…"
                    : error
                      ? "Не удалось сохранить"
                      : saved
                        ? "Сохранено"
                        : serializeFlags(flags) !== lastSaved.current
                          ? "Изменено"
                          : "Сохраняется после ввода"}
              </div>
              {(error || configError) && (
                <div className="settings-error" role="alert">
                  {error || configError}
                </div>
              )}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
