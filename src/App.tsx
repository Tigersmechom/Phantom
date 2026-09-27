import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import {
  Play,
  Pause,
  Square,
  SkipBack,
  SkipForward,
  RotateCcw,
  Terminal,
  Trash2,
  Hammer,
  FolderOpen,
  Save,
  Code2,
  SlidersHorizontal,
  ChevronDown,
  ChevronRight,
  ArrowUpRight,
  X,
  Maximize2,
  CircleHelp,
  Check,
  ArrowRight,
  Layers3,
  CornerDownLeft,
  Command,
  PanelRightClose,
  PanelRightOpen,
  Folder,
} from "lucide-react";
import CodeEditor from "./CodeEditor";
import InputPanel from "./InputPanel";
import { useChangeMotion } from "./AnimatedValue";
import InspectorScope, { type InspectorFrame } from "./InspectorScope";
import "./inspector-motion.css";
import Separator from "./Separator";
import SettingsPanel, { defaultBuildConfig } from "./SettingsPanel";
import TerminalPanel from "./TerminalPanel";
import { readPrefs, type Preferences } from "./preferences";
import {
  native,
  type WorkspaceState,
  type NativeDocument,
  type ExecutionResult,
  type BuildConfig,
} from "./native";
import palettes from "./xcode-palette.json";
import {
  DEMO_SOURCE,
  DEFAULT_INPUT,
  DEMO_FRAME_COUNT,
  parseInput,
  snapshot,
  demoInputTrace,
  type DemoSnapshot,
} from "./demo";
const SpatialCode = lazy(() => import("./SpatialCode"));

/** Adapt the prepared trace to the same one-current-frame boundary a backend will supply. */
function demoInspectorFrame(current: DemoSnapshot): InspectorFrame {
  if (current.functionName !== "main()") {
    return {
      id: `demo:add:${current.i}`,
      functionName: current.functionName,
      scalars: [
        {
          id: "a",
          name: "a",
          type: "int",
          value: current.a,
          kind: "argument",
          caption: "аргумент функции",
        },
        {
          id: "b",
          name: "b",
          type: "int",
          value: current.b,
          kind: "argument",
          caption: "аргумент функции",
        },
      ],
      arrays: [],
    };
  }
  const scalars: InspectorFrame["scalars"] = [];
  if (current.inLoop) {
    scalars.push({
      id: "i",
      name: "i",
      type: "int",
      value: current.i,
      kind: "local",
      caption: "текущий индекс",
      unit: "/ 6",
    });
  }
  scalars.push({
    id: "n",
    name: "n",
    type: "const int",
    value: current.n,
    kind: "local",
    caption: "длина массива",
  });
  if (current.inputIndex !== null) {
    scalars.push({
      id: "value",
      name: "value",
      type: "int &",
      value: current.arrayValues[current.inputIndex],
      kind: "local",
      caption: `ссылка на values[${current.inputIndex}]`,
    });
  }
  return {
    id: "demo:main",
    functionName: current.functionName,
    scalars,
    arrays: [
      {
        id: "values",
        name: "values",
        type: "vector<int>",
        values: current.arrayValues,
        collapsible: true,
        readingIndex:
          current.inputIndex ??
          (current.inLoop ? (current.i ?? undefined) : undefined),
      },
      {
        id: "prefix",
        name: "prefix",
        type: "vector<int>",
        values: current.prefix,
        presentation: "prefix",
        changedIndex: current.initialized.prefix ? current.filled : undefined,
        unvisitedFrom: current.initialized.prefix ? current.filled + 1 : 0,
        note: {
          text:
            current.filled === 0
              ? "Начальное состояние"
              : `Обновлён prefix[${current.filled}]`,
          total: current.sum,
        },
      },
    ],
  };
}

export default function App() {
  const [prefs, setPrefs] = useState(readPrefs);
  const [mode, setMode] = useState<"debug" | "basic">("debug");
  const [arch, setArch] = useState<"arm64" | "x86_64">("arm64");
  const [source, setSource] = useState(DEMO_SOURCE);
  const [savedSource, setSavedSource] = useState(DEMO_SOURCE);
  const [document, setDocument] = useState<NativeDocument | null>(null);
  const [project, setProject] = useState<WorkspaceState | null>(null);
  const [buildConfig, setBuildConfig] =
    useState<BuildConfig>(defaultBuildConfig);
  const [input, setInput] = useState(DEFAULT_INPUT);
  const [traceInput, setTraceInput] = useState(DEFAULT_INPUT);
  const [values, setValues] = useState([3, 1, 4, 1, 5, 9]);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [bottomTab, setBottomTab] = useState<"terminal" | "build">("terminal");
  const [settings, setSettings] = useState(false);
  const [help, setHelp] = useState(false);
  const [spatial, setSpatial] = useState(false);
  const [cameraReset, setCameraReset] = useState(0);
  const [terminalResetKey, setTerminalResetKey] = useState(0);
  const [sideOpen, setSideOpen] = useState(true);
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState<"build" | "run" | "save" | null>(null);
  const [buildLog, setBuildLog] = useState(
    "Cmd+B — собрать текущий файл. Флаги находятся в .frame/build.json.",
  );
  const [runResult, setRunResult] = useState<ExecutionResult | null>(null);
  const workspace = useRef<HTMLElement>(null),
    right = useRef<HTMLElement>(null),
    io = useRef<HTMLDivElement>(null),
    left = useRef<HTMLDivElement>(null);
  const consoleDragCleanup = useRef<(() => void) | null>(null);
  const operationRef = useRef(false);
  const configSaveRef = useRef<Promise<void> | null>(null);
  const sourceRef = useRef(source);
  sourceRef.current = source;
  const isDemo = source.trimEnd() === DEMO_SOURCE.trimEnd();
  const dirty = source !== savedSource;
  const showDemoState = mode === "debug" && isDemo;
  const palette =
    palettes[prefs.theme === "porcelain" ? "light" : "dark"].colors;
  const current = snapshot(step, values);
  const inspectorFrame = showDemoState ? demoInspectorFrame(current) : null;
  const fileName = document?.name || "prefix_sum.cpp";
  const activeLine = showDemoState ? current.line : 0;
  const hasDemoOutput = showDemoState && current.output !== null;
  const update = useCallback(
    (patch: Partial<Preferences>) => setPrefs((p) => ({ ...p, ...patch })),
    [],
  );
  const explainError = (error: unknown) =>
    setToast(error instanceof Error ? error.message : String(error));
  useEffect(() => {
    try {
      localStorage.setItem("phantom.preferences", JSON.stringify(prefs));
    } catch {}
  }, [prefs]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 4200);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => () => consoleDragCleanup.current?.(), []);
  useEffect(() => {
    if (!native || !project) return;
    void native
      .updateDocumentState({ dirty, content: source })
      .catch(explainError);
  }, [dirty, source, project?.root, document?.path]);
  const acceptWorkspace = useCallback((state: WorkspaceState) => {
    configSaveRef.current = null;
    setSettings(false);
    setProject(state);
    if (state.configError) setToast(state.configError);
    setBuildConfig(state.config);
    setDocument(state.document);
    const content = state.document?.content ?? DEMO_SOURCE;
    setSource(content);
    setSavedSource(content);
    setPlaying(false);
    setRunResult(null);
    setStep(0);
  }, []);
  useEffect(() => {
    if (!native) return;
    let active = true;
    native
      .getWorkspace()
      .then((state) => {
        if (active) acceptWorkspace(state);
      })
      .catch((error) => {
        if (active) explainError(error);
      });
    const dispose = native.onWorkspace(acceptWorkspace);
    return () => {
      active = false;
      dispose();
    };
  }, [acceptWorkspace]);
  useEffect(() => {
    if (!playing) return;
    if (step >= DEMO_FRAME_COUNT - 1) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(
      () => setStep((s) => Math.min(DEMO_FRAME_COUNT - 1, s + 1)),
      1000 / prefs.operationsPerSecond,
    );
    return () => clearTimeout(timer);
  }, [playing, step, prefs.operationsPerSecond]);
  const next = useCallback(() => {
    setPlaying(false);
    setStep((s) => Math.min(DEMO_FRAME_COUNT - 1, s + 1));
  }, []);
  const back = useCallback(() => {
    setPlaying(false);
    setStep((s) => Math.max(0, s - 1));
  }, []);
  function editSource(value: string) {
    setSource(value);
    setPlaying(false);
    setRunResult(null);
  }
  async function save() {
    if (operationRef.current || (native && !project)) return false;
    if (!native) {
      setToast(
        "Сохранение C++-файлов доступно в приложении phantom для macOS.",
      );
      return false;
    }
    const content = sourceRef.current;
    operationRef.current = true;
    setBusy("save");
    try {
      const saved = await native.saveDocument({
        content,
        path: document?.path,
      });
      setDocument(saved);
      setSavedSource(content);
      setToast("Файл сохранён");
      return true;
    } catch (error) {
      explainError(error);
      return false;
    } finally {
      operationRef.current = false;
      setBusy(null);
    }
  }
  async function openProject(folder = false) {
    if (operationRef.current || busy || (native && !project)) return;
    if (!native) {
      setToast(
        "Открытие папки и файлов доступно в приложении phantom для macOS.",
      );
      return;
    }
    const pendingConfig = flushBuildFlags();
    operationRef.current = true;
    setBusy("save");
    try {
      await pendingConfig;
      if (
        sourceRef.current !== savedSource &&
        !window.confirm(
          "Открыть другой файл? Несохранённые изменения текущего файла будут потеряны.",
        )
      )
        return;
      setSettings(false);
      const result = folder
        ? await native.chooseWorkspace()
        : await native.openFile();
      if (result) acceptWorkspace(result);
    } catch (error) {
      explainError(error);
    } finally {
      operationRef.current = false;
      setBusy(null);
    }
  }
  function flushBuildFlags() {
    const focused = window.document.activeElement;
    if (
      focused instanceof HTMLTextAreaElement &&
      focused.hasAttribute("data-build-flags")
    )
      focused.blur();
    return configSaveRef.current;
  }
  async function compileCurrent() {
    flushBuildFlags();
    if (operationRef.current || (native && !project)) return null;
    if (!native) {
      setToast("Сборка доступна в приложении phantom для macOS.");
      return null;
    }
    const content = sourceRef.current;
    operationRef.current = true;
    setPlaying(false);
    setBusy("build");
    setConsoleOpen(true);
    setBottomTab("build");
    setBuildLog("Сборка " + fileName + "…");
    setRunResult(null);
    try {
      await configSaveRef.current;
      const result = await native.compile({ content, architecture: arch });
      setSavedSource(content);
      const quote = (s: string) =>
        /^[\w./=:+-]+$/.test(s) ? s : JSON.stringify(s);
      setBuildLog(
        result.command.map(quote).join(" ") +
          "\n\n" +
          result.stdout +
          result.stderr +
          "\n" +
          (result.success
            ? "✓ Сборка завершена: " + result.outputPath
            : "Сборка не удалась · код " + result.exitCode) +
          (result.truncated ? "\nВывод сокращён." : ""),
      );
      if (!result.success)
        setToast("Ошибка сборки. Диагностика открыта под кодом.");
      return result;
    } catch (error) {
      setBuildLog(String(error));
      explainError(error);
      return null;
    } finally {
      operationRef.current = false;
      setBusy(null);
    }
  }
  async function run() {
    if (busy === "run") {
      await native?.stopExecution();
      return;
    }
    if (busy || operationRef.current || (native && !project)) return;
    if (mode === "basic") {
      if (!native) {
        setToast("Настоящий запуск доступен в приложении phantom для macOS.");
        return;
      }
      const runningSource = sourceRef.current;
      const result = await compileCurrent();
      if (!result?.success) return;
      operationRef.current = true;
      setBusy("run");
      try {
        const execution = await native.execute({ stdin: input });
        if (sourceRef.current === runningSource) setRunResult(execution);
        else
          setToast(
            "Завершён запуск предыдущей версии исходника. Текущий код изменён.",
          );
        if (execution.stderr)
          setBuildLog((log) => log + "\n\n" + execution.stderr);
        if (execution.truncated)
          setToast("Вывод программы сокращён из-за размера.");
      } catch (error) {
        explainError(error);
      } finally {
        operationRef.current = false;
        setBusy(null);
      }
      return;
    }
    if (playing) {
      setPlaying(false);
      return;
    }
    if (!isDemo) {
      setToast(
        "Пошаговая отладка пока доступна для примера. Для вашего C++ выберите Basic.",
      );
      return;
    }
    const parsed = parseInput(input);
    if (!parsed) {
      setToast(
        "Для примера введите ровно 6 целых чисел от −1 000 000 до 1 000 000.",
      );
      return;
    }
    setValues(parsed);
    setTraceInput(input);
    setStep(0);
    setPlaying(true);
    setRunResult(null);
  }
  function reset() {
    if (
      dirty &&
      !window.confirm("Восстановить пример и заменить несохранённые изменения?")
    )
      return;
    setPlaying(false);
    setSource(DEMO_SOURCE);
    setInput(DEFAULT_INPUT);
    setTraceInput(DEFAULT_INPUT);
    setValues([3, 1, 4, 1, 5, 9]);
    setStep(0);
    setRunResult(null);
    setMode("debug");
    setToast("Пример восстановлен в редакторе");
  }
  function saveConfig(config: BuildConfig): Promise<void> {
    if (!native) return Promise.reject(Error("Откройте приложение phantom"));
    const api = native;
    const pending = (configSaveRef.current || Promise.resolve())
      .catch(() => {})
      .then(async () => {
        const updated = await api.saveBuildConfig(config);
        setBuildConfig(updated);
        setProject((p) =>
          p ? { ...p, config: updated, configError: undefined } : p,
        );
      });
    configSaveRef.current = pending;
    void pending.catch(explainError);
    return pending;
  }
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.ctrlKey && (event.code === "Backquote" || event.key === "`")) {
        event.preventDefault();
        setConsoleOpen((v) => !v);
        setBottomTab("terminal");
        return;
      }
      if (event.key === "Escape") {
        setSettings(false);
        setHelp(false);
      }
      if (event.key === "F10" && showDemoState && !busy) {
        event.preventDefault();
        event.shiftKey ? back() : next();
      }
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        window.document.getElementById("run-button")?.click();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        window.document.getElementById("save-button")?.click();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "b") {
        event.preventDefault();
        window.document.getElementById("build-button")?.click();
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "o") {
        event.preventDefault();
        window.document.getElementById("open-button")?.click();
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [showDemoState, busy, next, back]);
  const style = {
    ...Object.fromEntries(
      Object.entries(palette).map(([k, v]) => ["--syntax-" + k, v]),
    ),
    "--side-width": `${sideOpen ? prefs.sideWidth : 0}%`,
    "--variables-height": `${prefs.variablesHeight}%`,
    "--input-width": `${prefs.inputWidth}%`,
    "--console-height": `${prefs.consoleHeight}px`,
    "--input-font-size": `${prefs.inputFontSize}px`,
    "--output-font-size": `${prefs.outputFontSize}px`,
    "--debug-number-scale": prefs.debuggerNumberScale,
    "--debug-name-scale": prefs.debuggerNameScale,
  } as CSSProperties;
  const runtimeOutput = runResult?.stdout || runResult?.stderr || "";
  const outputMotion = useChangeMotion<HTMLPreElement>(
    mode === "basic" ? runResult : showDemoState ? current.output : null,
    "output",
  );
  return (
    <div
      className={`app theme-${prefs.theme} ${native ? "native" : ""} ${mode === "basic" ? "mode-basic" : ""}`}
      style={style}
    >
      <header className="toolbar">
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setHelp(true);
          }}
          aria-label="О phantom"
        >
          <svg width="22" height="24" viewBox="0 0 22 24" fill="none">
            <path
              d="M4 22V3h9a6 6 0 0 1 0 12H9M9 22V8h4"
              stroke="currentColor"
              strokeWidth="2.4"
            />
          </svg>
          <span>phantom</span>
        </a>
        <span className="toolbar-divider" />
        <div className="run-controls">
          <button
            className={`run-button ${playing || busy === "run" ? "running" : ""}`}
            id="run-button"
            disabled={
              busy === "build" || busy === "save" || (!!native && !project)
            }
            onClick={() => void run()}
            title={
              mode === "basic"
                ? "Собрать и запустить · ⌘ Enter"
                : "Запуск · ⌘ Enter"
            }
          >
            {busy === "run" ? (
              <Square size={12} fill="currentColor" />
            ) : playing ? (
              <Pause size={13} />
            ) : (
              <Play size={13} fill="currentColor" />
            )}
            <span>
              {busy === "run" ? "Стоп" : playing ? "Пауза" : "Запуск"}
            </span>
          </button>
          <button
            className="icon-button"
            onClick={back}
            disabled={step === 0 || !showDemoState || !!busy}
            aria-label="Предыдущая итерация"
            title="Назад · Shift F10"
          >
            <SkipBack size={15} />
          </button>
          <button
            className="icon-button"
            onClick={next}
            disabled={step === DEMO_FRAME_COUNT - 1 || !showDemoState || !!busy}
            aria-label="Следующая итерация"
            title="Шаг · F10"
          >
            <SkipForward size={15} />
          </button>
          <button
            className="icon-button"
            onClick={reset}
            disabled={!!busy}
            aria-label="Восстановить пример"
            title="Восстановить пример"
          >
            <RotateCcw size={14} />
          </button>
          <button
            className={`icon-button build-button ${busy === "build" ? "busy" : ""}`}
            id="build-button"
            disabled={!!busy}
            onClick={() => void compileCurrent()}
            aria-label="Собрать текущий файл"
            title="Собрать · ⌘ B"
          >
            <Hammer size={14} />
          </button>
        </div>
        <span className="toolbar-divider" />
        <div className="segmented modes">
          <button
            className={mode === "debug" ? "selected" : ""}
            disabled={!!busy}
            onClick={() => {
              setMode("debug");
              setPlaying(false);
            }}
          >
            Debug
          </button>
          <button
            className={mode === "basic" ? "selected" : ""}
            disabled={!!busy}
            onClick={() => {
              setMode("basic");
              setPlaying(false);
            }}
          >
            Basic
          </button>
        </div>
        <span className="toolbar-divider" />
        <label className="operation-speed" title="Скорость выполнения шагов">
          <select
            aria-label="Операций в секунду"
            disabled={mode !== "debug"}
            value={prefs.operationsPerSecond}
            onChange={(event) =>
              update({ operationsPerSecond: Number(event.target.value) })
            }
          >
            {[0.25, 0.5, 1, 2, 4, 8, 12].map((speed) => (
              <option key={speed} value={speed}>
                {speed}
              </option>
            ))}
          </select>
          <span>оп/с</span>
        </label>
        <span className="toolbar-divider" />
        <div className="architecture">
          <span className="chip-icon">
            <Layers3 size={13} />
          </span>
          <select
            aria-label="Архитектура"
            disabled={!!busy}
            value={arch}
            onChange={(e) => {
              setArch(e.target.value as typeof arch);
              setPlaying(false);
            }}
          >
            <option value="arm64">ARM64</option>
            <option value="x86_64">x86_64</option>
          </select>
          <ChevronDown size={10} />
        </div>
        <div className="toolbar-space" />
        <button
          className={`icon-button ${consoleOpen ? "active" : ""}`}
          onClick={() => {
            setConsoleOpen((v) => !v);
            setBottomTab("terminal");
          }}
          aria-label="Консоль"
          title="Терминал · Ctrl `"
        >
          <Terminal size={15} />
        </button>
        <button
          className={`icon-button ${settings ? "active" : ""}`}
          onClick={() => setSettings((v) => !v)}
          aria-label="Настройки типографики"
          title="Настройки: оформление, 3D и сборка"
        >
          <SlidersHorizontal size={15} />
        </button>
        <button
          className="icon-button help-button"
          onClick={() => setHelp(true)}
          aria-label="Помощь"
        >
          <CircleHelp size={15} />
        </button>
      </header>
      <main
        className={`workspace ${sideOpen ? "" : "side-hidden"}`}
        ref={workspace}
      >
        <div className="left-workspace" ref={left}>
          <section className="editor-pane" aria-label="Редактор кода">
            <div className="file-bar">
              <div className="file-tab">
                <span className="cpp-symbol">
                  C<span>++</span>
                </span>
                <span className="native-file-name" title={document?.path}>
                  {fileName}
                </span>
                <span
                  className={`file-dot ${dirty ? "unsaved-indicator" : ""}`}
                />
              </div>
              <div className="file-bar-rest">
                <span className="file-path">
                  <button
                    onClick={() => void openProject(true)}
                    title={project?.root || "Открыть папку"}
                    aria-label="Открыть папку проекта"
                    disabled={!!busy || (!!native && !project)}
                  >
                    <Folder size={12} />
                  </button>
                  {project?.name || "workspace"}
                  <ChevronRight size={11} />
                  {fileName.replace(/\.[^.]+$/, "")}
                </span>
                <div className="file-actions">
                  <button
                    className="icon-button"
                    id="open-button"
                    disabled={!!busy}
                    onClick={() => void openProject()}
                    aria-label="Открыть C++ файл"
                    title="Открыть · ⌘ O"
                  >
                    <FolderOpen size={13} />
                  </button>
                  <button
                    className="icon-button"
                    id="save-button"
                    disabled={!!busy}
                    onClick={() => void save()}
                    aria-label="Сохранить файл"
                    title="Сохранить · ⌘ S"
                  >
                    <Save size={13} />
                  </button>
                </div>
                <div className="editor-view-switch">
                  <button
                    className={!spatial ? "selected" : ""}
                    onClick={() => setSpatial(false)}
                    title="Редактор"
                  >
                    <Code2 size={13} />
                    <span>Код</span>
                  </button>
                  <button
                    className={spatial ? "selected" : ""}
                    onClick={() => setSpatial(true)}
                    title="3D"
                  >
                    <Layers3 size={13} />
                    <span>3D</span>
                  </button>
                </div>
                <button
                  className="icon-button"
                  onClick={() => setSideOpen((v) => !v)}
                  aria-label={
                    sideOpen ? "Скрыть переменные" : "Показать переменные"
                  }
                >
                  {sideOpen ? (
                    <PanelRightClose size={14} />
                  ) : (
                    <PanelRightOpen size={14} />
                  )}
                </button>
              </div>
            </div>
            <div className="editor-breadcrumb">
              <span>{showDemoState ? current.functionName : fileName}</span>
              <span className="editor-breadcrumb-end">
                {dirty ? "НЕ СОХРАНЕНО" : "C++"}
              </span>
            </div>
            <div className={`code-surface ${spatial ? "is-spatial" : ""}`}>
              {spatial ? (
                <Suspense
                  fallback={
                    <div className="loading-scene">
                      Создаём геометрию букв
                      <span />
                    </div>
                  }
                >
                  <SpatialCode
                    source={source}
                    palette={palette}
                    theme={prefs.theme === "porcelain" ? "light" : "dark"}
                    activeLine={activeLine}
                    expression={showDemoState ? current.expression : null}
                    expressionStyle={prefs.expressionStyle}
                    stepDurationMs={1000 / prefs.operationsPerSecond}
                    isPlaying={playing}
                    executionKey={step}
                    followExecution={prefs.cameraFollow}
                    depth={prefs.spatialDepth}
                    light={prefs.spatialLight}
                    highlightBrightness={prefs.spatialHighlightBrightness}
                    wireframe={prefs.spatialWireframe}
                    resetKey={cameraReset}
                  />
                </Suspense>
              ) : (
                <CodeEditor
                  source={source}
                  onChange={editSource}
                  activeLine={activeLine}
                  architecture={arch}
                  depth={prefs.depth}
                  font={prefs.font}
                  fontSize={prefs.fontSize}
                />
              )}
            </div>
          </section>
          {consoleOpen && (
            <div
              className="console-resizer"
              role="separator"
              aria-label="Высота консоли"
              aria-orientation="horizontal"
              tabIndex={0}
              aria-valuenow={prefs.consoleHeight}
              aria-valuemin={110}
              aria-valuemax={Math.round(
                (left.current?.clientHeight || 600) * 0.6,
              )}
              onKeyDown={(e) => {
                if (e.key === "ArrowUp" || e.key === "ArrowDown") {
                  e.preventDefault();
                  update({
                    consoleHeight: Math.max(
                      110,
                      Math.min(
                        (left.current?.clientHeight || 600) * 0.6,
                        prefs.consoleHeight + (e.key === "ArrowUp" ? 12 : -12),
                      ),
                    ),
                  });
                }
              }}
              onPointerDown={(e) => {
                e.preventDefault();
                consoleDragCleanup.current?.();
                const y = e.clientY,
                  h = prefs.consoleHeight;
                const move = (ev: PointerEvent) =>
                  update({
                    consoleHeight: Math.max(
                      110,
                      Math.min(
                        (left.current?.clientHeight || 600) * 0.6,
                        h + y - ev.clientY,
                      ),
                    ),
                  });
                const stop = () => {
                  window.removeEventListener("pointermove", move);
                  window.removeEventListener("pointerup", stop);
                };
                consoleDragCleanup.current = stop;
                window.addEventListener("pointermove", move);
                window.addEventListener("pointerup", stop, { once: true });
              }}
            />
          )}
          <section
            className="console"
            hidden={!consoleOpen}
            style={!consoleOpen ? { display: "none" } : undefined}
          >
            <div className="panel-heading">
              <div className="bottom-tabs">
                <button
                  className={bottomTab === "terminal" ? "selected" : ""}
                  onClick={() => setBottomTab("terminal")}
                >
                  <Terminal size={12} />
                  Терминал
                </button>
                <button
                  className={bottomTab === "build" ? "selected" : ""}
                  onClick={() => setBottomTab("build")}
                >
                  <Hammer size={12} />
                  Сборка
                </button>
              </div>
              <span className="console-cwd" title={project?.root}>
                {project?.root || ""}
              </span>
              {bottomTab === "terminal" && (
                <button
                  className="icon-button terminal-trash"
                  disabled={!native}
                  onClick={() => setTerminalResetKey((key) => key + 1)}
                  aria-label="Пересоздать терминал"
                  title="Завершить оболочку и открыть новую"
                >
                  <Trash2 size={13} />
                </button>
              )}
              <button
                className="icon-button"
                onClick={() => setConsoleOpen(false)}
                aria-label="Закрыть консоль"
              >
                <X size={13} />
              </button>
            </div>
            <div className="console-content">
              <TerminalPanel
                open={consoleOpen && bottomTab === "terminal"}
                theme={prefs.theme === "porcelain" ? "light" : "dark"}
                cwd={project?.root}
                resetKey={terminalResetKey}
              />
              {bottomTab === "build" && (
                <pre
                  className="build-output"
                  role="log"
                  aria-label="Результат сборки"
                >
                  {buildLog}
                </pre>
              )}
            </div>
          </section>
        </div>
        {sideOpen && (
          <>
            <Separator
              label="Ширина переменных"
              value={prefs.sideWidth}
              min={24}
              max={48}
              onChange={(sideWidth) => update({ sideWidth })}
              container={workspace}
              invert
            />
            <aside
              className={`inspector ${playing ? "is-playing" : ""}`}
              ref={right}
            >
              <section className="variables-panel">
                <div className="panel-heading">
                  <span>
                    <span className="four-dots">⠿</span> Переменные{" "}
                    <small>LOCAL</small>
                  </span>
                  <span className="scope-indicator">
                    {inspectorFrame?.functionName.split("(")[0] || "—"}
                  </span>
                </div>
                <div className="variables-scroll">
                  <div className="state-heading">
                    <div>
                      <h1>
                        {showDemoState
                          ? current.functionName
                          : "Состояние программы"}
                      </h1>
                    </div>
                    <span className="state-orb" aria-hidden="true" />
                  </div>
                  {inspectorFrame ? (
                    <InspectorScope
                      frame={inspectorFrame}
                      fileName={fileName}
                      line={current.line}
                    />
                  ) : (
                    <div className="program-state-empty">
                      <strong>
                        {busy === "run"
                          ? "Программа выполняется"
                          : "Нет активной сессии"}
                      </strong>
                      <span>
                        {mode === "basic"
                          ? "Переменные доступны в режиме Debug"
                          : "Нет данных отладчика"}
                      </span>
                    </div>
                  )}
                </div>
                {showDemoState && (
                  <div className="timeline">
                    <div>
                      <span>История</span>
                      <span>
                        <b>{String(step + 1).padStart(2, "0")}</b> /{" "}
                        {DEMO_FRAME_COUNT}
                      </span>
                    </div>
                    <div className="timeline-track">
                      {Array.from({ length: DEMO_FRAME_COUNT }, (_, i) => (
                        <button
                          key={i}
                          aria-label={`Кадр ${i + 1}`}
                          aria-current={step === i ? "step" : undefined}
                          className={`${i <= step ? "visited" : ""} ${i === step ? "current" : ""}`}
                          onClick={() => {
                            setPlaying(false);
                            setStep(i);
                          }}
                        >
                          <i />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </section>
              <Separator
                label="Высота переменных"
                direction="horizontal"
                value={prefs.variablesHeight}
                min={35}
                max={80}
                onChange={(variablesHeight) => update({ variablesHeight })}
                container={right}
              />
              <div className="io-panels" ref={io}>
                <section className="input-panel">
                  <div className="panel-heading">
                    <span>
                      Ввод <small>STDIN</small>
                    </span>
                    <CornerDownLeft size={11} />
                  </div>
                  <div className="io-content">
                    <div className="io-caption">
                      {showDemoState ? "6 целых чисел" : "Данные для программы"}
                    </div>
                    <InputPanel
                      value={input}
                      onChange={setInput}
                      trace={
                        showDemoState ? demoInputTrace(step, traceInput) : null
                      }
                    />
                    <div className="io-hint">Применяется при запуске</div>
                  </div>
                </section>
                <Separator
                  label="Ширина ввода и вывода"
                  value={prefs.inputWidth}
                  min={28}
                  max={72}
                  onChange={(inputWidth) => update({ inputWidth })}
                  container={io}
                />
                <section className="output-panel">
                  <div className="panel-heading">
                    <span>
                      Вывод <small>STDOUT</small>
                    </span>
                    <ArrowUpRight size={12} />
                  </div>
                  <div className="io-content">
                    <div className="io-caption">
                      {mode === "basic"
                        ? busy === "run"
                          ? "Программа выполняется"
                          : runResult
                            ? "Программа завершена"
                            : "Ожидание запуска"
                        : showDemoState && current.done
                          ? "Завершено"
                          : "Ожидание вывода"}
                    </div>
                    <pre
                      ref={outputMotion}
                      className={
                        (mode === "basic" ? runResult : hasDemoOutput)
                          ? "has-output"
                          : ""
                      }
                    >
                      {mode === "basic" ? (
                        runtimeOutput || <span className="output-caret" />
                      ) : hasDemoOutput ? (
                        current.output
                      ) : (
                        <span className="output-caret" />
                      )}
                    </pre>
                    <div className="io-hint">
                      {mode === "basic" ? (
                        runResult ? (
                          `exit code ${runResult.exitCode ?? runResult.signal ?? "—"}`
                        ) : (
                          "stdin закрывается после ввода"
                        )
                      ) : showDemoState && current.done ? (
                        <>
                          <Check size={10} /> exit code 0
                        </>
                      ) : showDemoState ? (
                        "Появится после цикла"
                      ) : (
                        "Запустите файл в Basic"
                      )}
                    </div>
                  </div>
                </section>
              </div>
            </aside>
          </>
        )}
      </main>
      <div className="statusbar">
        <span>
          <span className="status-dot" />
          {busy === "build"
            ? "Компиляция"
            : busy === "run"
              ? "Выполняется"
              : dirty
                ? "Есть изменения"
                : playing
                  ? "Воспроизведение"
                  : showDemoState
                    ? current.done
                      ? "Завершено"
                      : "Пауза"
                    : "Готово"}
        </span>
        <span className="status-divider" />
        <span>{mode === "debug" ? "Debug" : "Basic"}</span>
        <div className="toolbar-space" />
        <span>UTF-8</span>
        <span>{arch === "arm64" ? "Apple Silicon" : "Intel 64-bit"}</span>
        <button
          onClick={() => {
            if (window.document.fullscreenElement)
              void window.document.exitFullscreen().catch(() => {});
            else
              void window.document.documentElement
                .requestFullscreen()
                .catch(() => setToast("Полноэкранный режим недоступен"));
          }}
          title="На весь экран"
          aria-label="На весь экран"
        >
          <Maximize2 size={11} />
        </button>
      </div>
      {settings && (
        <SettingsPanel
          prefs={prefs}
          update={update}
          close={() => setSettings(false)}
          config={buildConfig}
          configError={project?.configError}
          native={!!native}
          saveConfig={saveConfig}
          resetCamera={() => setCameraReset((v) => v + 1)}
          showSpatial={() => setSpatial(true)}
          busy={!!busy}
        />
      )}
      {help && (
        <div className="modal-backdrop" onClick={() => setHelp(false)}>
          <section
            className="help-modal"
            role="dialog"
            aria-modal="true"
            aria-label="О phantom"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close icon-button"
              aria-label="Закрыть помощь"
              onClick={() => setHelp(false)}
            >
              <X size={18} />
            </button>

            <h2>phantom</h2>
            <p>
              Оформление, объём букв, свет и движение камеры находятся в
              настройках сверху. В 3D нажмите на сцену, чтобы управлять
              стрелками.
            </p>
            <div className="shortcut-row">
              <span>Терминал</span>
              <kbd>Ctrl `</kbd>
            </div>
            <div className="shortcut-row">
              <span>Сохранить / собрать</span>
              <kbd>⌘ S / ⌘ B</kbd>
            </div>
            <div className="shortcut-row">
              <span>Запустить</span>
              <kbd>
                <Command size={10} /> Enter
              </kbd>
            </div>
            <div className="shortcut-row">
              <span>Шаг вперёд / назад</span>
              <kbd>F10 / ⇧ F10</kbd>
            </div>
            <div className="shortcut-row">
              <span>Камера 3D</span>
              <kbd>↑ ↓ ← →</kbd>
            </div>
            <p className="prototype-note">
              В приложении macOS доступны файлы, настоящий терминал и
              компиляция. Basic собирает и исполняет текущий C++. Debug пока
              показывает подготовленный пример с вызовом функции; подключение
              LLDB и настоящего ASM — следующий этап.
            </p>
            <button className="primary-button" onClick={() => setHelp(false)}>
              Перейти к коду <ArrowRight size={14} />
            </button>
          </section>
        </div>
      )}
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}
