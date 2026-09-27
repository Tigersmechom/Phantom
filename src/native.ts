export interface BuildConfig { version: 1; compiler: string; flags: string[]; outputDirectory: string }
export interface NativeDocument { path: string; name: string; content: string }
export interface WorkspaceState { root: string; name: string; configPath: string; config: BuildConfig; configError?: string; document: NativeDocument | null }
export interface BuildResult { success: boolean; command: string[]; stdout: string; stderr: string; exitCode: number | null; outputPath: string; truncated: boolean; signal?: string; timedOut?: boolean }
export interface ExecutionResult { stdout: string; stderr: string; exitCode: number | null; truncated: boolean; signal?: string; timedOut?: boolean }
export interface TerminalSnapshot { id: string; cwd: string; history: string; sequence: number; exitCode?: number }
export interface TerminalData { id: string; data: string; sequence: number }
export interface TerminalExit { id: string; exitCode: number; signal?: number }
export interface FrameNative {
  getWorkspace(): Promise<WorkspaceState>;
  openFile(): Promise<WorkspaceState | null>;
  chooseWorkspace(): Promise<WorkspaceState | null>;
  saveDocument(request: { content: string; path?: string }): Promise<NativeDocument>;
  updateDocumentState(request: { dirty: boolean; content: string }): Promise<void>;
  saveBuildConfig(config: BuildConfig): Promise<BuildConfig>;
  revealBuildConfig(): Promise<void>;
  compile(request: { content: string; architecture: 'arm64' | 'x86_64' }): Promise<BuildResult>;
  execute(request: { stdin: string }): Promise<ExecutionResult>;
  stopExecution(): Promise<void>;
  onWorkspace(listener: (state: WorkspaceState) => void): () => void;
  terminal: {
    open(size: { cols: number; rows: number }): Promise<TerminalSnapshot>;
    restart(size: { cols: number; rows: number }): Promise<TerminalSnapshot>;
    write(request: { id: string; data: string }): Promise<void>;
    resize(request: { id: string; cols: number; rows: number }): Promise<void>;
    onData(listener: (event: TerminalData) => void): () => void;
    onExit(listener: (event: TerminalExit) => void): () => void;
  };
}
declare global { interface Window { frameNative?: FrameNative } }
export const native = typeof window === 'undefined' ? undefined : window.frameNative;
