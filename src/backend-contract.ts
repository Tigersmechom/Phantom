/** Proposed debugger adapter protocol. This file does not implement or expose an IPC bridge. */
export const BACKEND_PROTOCOL_VERSION = 1 as const;
export type BackendProtocolVersion = typeof BACKEND_PROTOCOL_VERSION;
export type ArchitectureDTO = 'arm64' | 'x86_64';

/** Zero-based UTF-16 code-unit offsets, [start, end), in the exact referenced text. */
export interface Utf16Range { start: number; end: number }
/** Immutable input draft revision. The text is never normalized. */
export interface InputRevisionDTO {
  id: string;
  parentId: string | null;
  text: string;
}
/**
 * Compatibility view used by the original InputPanel. New clients should use
 * InputStateDTO.revision and its top-level ranges; the legacy string revision
 * remains accepted so old fixtures do not silently lose their highlights.
 */
export interface InputTrace {
  revision: string | InputRevisionDTO;
  consumedRanges: Utf16Range[];
  exposedRanges?: Utf16Range[];
  activeRange?: Utf16Range;
  status: 'idle' | 'waiting' | 'reading' | 'complete' | 'error';
}
export interface SourceDocumentDTO {
  documentId: string;
  revisionId: string;
  path: string;
  text: string;
  /** SHA-256 of the exact UTF-8 encoding, without newline/Unicode normalization. */
  sha256: string;
}
export interface SourceBundleDTO { id: string; documents: SourceDocumentDTO[] }
export interface SourceSpanDTO {
  documentId: string;
  revisionId: string;
  range: Utf16Range;
  /** One-based line and UTF-16 column, end exclusive; must agree with range. */
  start: { line: number; column: number };
  end: { line: number; column: number };
}
export interface WorkspaceRefDTO { id: string; revisionId: string }
export interface SessionRefDTO { id: string; generation: number }
export interface HistoryPointDTO { branchId: string; eventOrdinal: number }
export interface StopRefDTO { stopId: string; stateRevision: number }

export interface BuildConfigurationDTO {
  revisionId: string;
  compiler: string;
  flags: string[];
  outputDirectory: string;
}
export interface BuildArtifactDTO {
  id: string;
  sourceBundleId: string;
  configurationRevisionId: string;
  architecture: ArchitectureDTO;
  targetTriple: string;
  compiler: { path: string; version: string };
  command: string[];
  binaryPath: string;
  binarySha256: string;
  debugSymbolsAvailable: boolean;
}
export interface SubmittedInputDTO {
  id: string;
  text: string;
  encoding: 'utf-8';
  /** true closes stdin after these bytes; false keeps it open for appendInput/closeInput. */
  closeAfterWrite: boolean;
}
export type UnavailableReasonDTO = 'not-declared' | 'uninitialized' | 'not-captured' | 'out-of-scope' | 'optimized-out' | 'read-error' | 'truncated' | 'unsupported';
export type ScalarValueDTO =
  | { kind: 'integer'; decimal: string; bits: number; signed: boolean }
  | { kind: 'float'; text: string; bits: number; classification: 'finite' | 'nan' | 'positive-infinity' | 'negative-infinity' | 'negative-zero'; rawBitsHex?: string }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'pointer'; addressHex: string; pointeeType: string }
  | { kind: 'string'; text: string; encoding: string; byteLength: number; truncated: boolean }
  | { kind: 'aggregate'; summary: string; elementCount?: string; childrenReference?: string };
export type RuntimeValueDTO =
  | { availability: 'available'; value: ScalarValueDTO }
  | { availability: 'unavailable'; reason: UnavailableReasonDTO; detail?: string };
export type VariableStorageUnknownReasonDTO =
  | 'location-unavailable'
  | 'unsupported-name'
  | 'no-own-storage'
  | 'size-unavailable'
  | 'too-large'
  | 'read-error';
/**
 * Physical bytes for the variable's own storage slot. This is intentionally
 * separate from RuntimeValueDTO: a readable stack slot does not prove that
 * the C++ object's lifetime has begun or that its bytes form an initialized
 * value. `addressHex` is the storage address, never a pointer's pointee.
 */
export interface VariableStorageDTO {
  state: 'observed' | 'unknown';
  lifetime: 'unknown';
  addressHex: string | null;
  byteLength: number | null;
  /** Bounded raw bytes from the current stop; padding and stale bytes remain possible. */
  rawBytesHex?: string;
  reason?: VariableStorageUnknownReasonDTO;
}
export interface VariableDTO {
  id: string;
  name: string;
  type: string;
  scopeId: string;
  activationId: string;
  /** Opaque logical locator resolved again after restore; never a raw DAP handle. */
  locator: string;
  value: RuntimeValueDTO;
  writable: boolean;
  /** Current-frame storage address, if GDB supplied a safe location. */
  addressHex?: string | null;
  storage?: VariableStorageDTO;
  children?: VariableDTO[];
}
export interface StackFrameDTO {
  id: string;
  activationId: string;
  functionName: string;
  location: SourceSpanDTO | null;
  variables: VariableDTO[];
}

export interface ExpressionStageDTO {
  id: string;
  kind: 'operator' | 'call' | 'return' | 'store';
  operator: string;
  label: string;
  range: SourceSpanDTO | null;
  operands: { name?: string; value: RuntimeValueDTO; range?: SourceSpanDTO }[];
  result: RuntimeValueDTO;
  targetLocator?: string;
  /** Observed data dependencies by stage ID; source order is not execution evidence. */
  dependsOn: string[];
}
export interface EvaluationGroupDTO {
  id: string;
  relationToPrevious: 'observed-after' | 'not-established';
  /** No execution order is implied between stages within this group. */
  stages: ExpressionStageDTO[];
}
export interface ExpressionTraceDTO {
  id: string;
  range: SourceSpanDTO | null;
  evidence: 'debugger' | 'instrumentation';
  groups: EvaluationGroupDTO[];
  activeStageIds: string[];
  complete: boolean;
}
export interface InputStateDTO {
  submitted: SubmittedInputDTO;
  /** `observed-extractions` is the pre-revision spelling kept for old fixtures. */
  tracking: 'none' | 'transport-only' | 'semantic' | 'observed-extractions';
  /** Bytes written to the pipe are NOT proof that the C++ extraction consumed them. */
  deliveredBytes: number;
  /** Current editable draft revision; absent in the legacy transport-only shape. */
  revision?: InputRevisionDTO;
  /** Ranges already exposed to the inferior, tied to revision.text. */
  exposedRanges?: Utf16Range[];
  /** Ranges confirmed as consumed by a semantic input profile. */
  consumedRanges?: Utf16Range[];
  activeRange?: Utf16Range;
  status?: 'idle' | 'waiting' | 'reading' | 'complete' | 'error';
  eof?: 'open' | 'requested' | 'observed';
  trace: InputTrace | null;
  consumedThroughUtf16?: number;
  /** null means stream flags were not observed. EOF is distinct from complete UI trace. */
  stream: { eof: boolean; fail: boolean; bad: boolean } | null;
  lastRead?: {
    id: string;
    kind: 'formatted' | 'getline' | 'raw';
    status: 'completed' | 'waiting' | 'parse-error' | 'eof';
    range?: SourceSpanDTO;
    targetLocator?: string;
    consumedRanges: Utf16Range[];
    value?: RuntimeValueDTO;
  };
}
export interface OutputSnapshotDTO {
  text: string;
  totalBytes: number;
  retainedFromByte: number;
  truncated: boolean;
  /** Optional bytes still held by a runtime buffer at this stop. */
  buffered?: {
    available: true;
    /** This is the glibc C stdout stream; cout uses it only while synchronized. */
    source: 'glibc-_IO_FILE';
    stream: 'stdout';
    association: 'cout-if-synchronized';
    mode: 'full' | 'line' | 'unbuffered' | 'unknown';
    flushPolicy: 'buffer-full-or-explicit' | 'newline-or-explicit' | 'every-write' | 'unknown';
    pendingBytes: number;
    writeWindowCapacityBytes: number | null;
    writeWindowRemainingBytes: number | null;
    /** Null when line buffering/ABI metadata cannot define a byte threshold. */
    capacityBytes: number | null;
    remainingCapacityBytes: number | null;
    storageCapacityBytes: number | null;
    metadataAvailable: boolean;
    metadataReason?: string;
    text: string;
    totalBytes: number;
    retainedFromByte: number;
    truncated: boolean;
    textStatus?: 'unavailable';
    textReason?: string;
  } | {
    available: false;
    reason: string;
  };
}
export interface StopObservationDTO {
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  buildId: string;
  sourceBundleId: string;
  reason: 'entry' | 'step' | 'breakpoint' | 'pause' | 'signal' | 'input-wait' | 'step-timeout' | 'mutation' | 'exit';
  /** Actual PC location before the next instruction, not proof this statement has completed. */
  location: SourceSpanDTO | null;
  threadId: string | null;
  stack: StackFrameDTO[];
  input: InputStateDTO;
  stdout: OutputSnapshotDTO;
  stderr: OutputSnapshotDTO;
  expressions: ExpressionTraceDTO[];
  coverage: { variables: 'complete' | 'partial'; expressions: 'none' | 'partial' | 'observed'; memory: 'none' | 'partial' };
}
export interface DebugSessionStateDTO {
  session: SessionRefDTO;
  phase: 'idle' | 'building' | 'launching' | 'stopped' | 'waitingForInput' | 'running' | 'pausing' | 'restoring' | 'terminated' | 'failed';
  processInstanceId: string | null;
  buildId: string | null;
  /** Authoritative live process position; a history read must never change this. */
  live: { point: HistoryPointDTO; stop: StopRefDTO } | null;
  exit: { code: number | null; signal: string | null } | null;
}
/** Owned by the frontend, independent of the state of the live process. */
export type ExecutionViewDTO = { kind: 'live' } | { kind: 'history'; session: SessionRefDTO; point: HistoryPointDTO };
export interface ResourceLimitsDTO {
  maxOutputBytes: number;
  maxHistoryBytes: number;
  maxResidentSnapshots: number;
  maxVariablesPerPage: number;
  maxStringBytes: number;
  maxMemoryReadBytes: number;
  maxInstructionsPerRequest: number;
  commandTimeoutMs: number;
  replayTimeoutMs: number;
}
export interface BackendCapabilitiesDTO {
  protocolVersion: BackendProtocolVersion;
  backendName: string;
  backendVersion: string;
  architectures: ArchitectureDTO[];
  stepKinds: ('over' | 'into' | 'out' | 'instruction')[];
  sourceBreakpoints: boolean;
  conditionalBreakpoints: boolean;
  hitCountBreakpoints: boolean;
  variableWrite: boolean;
  inputTracking: InputStateDTO['tracking'];
  interactiveInput: boolean;
  expressionGroups: boolean;
  history: boolean;
  restore: 'none' | 'verified-replay';
  asm: { currentPc: boolean; sourceRange: boolean };
  memoryRead: boolean;
  eventReplay: boolean;
  limits: ResourceLimitsDTO;
}
export interface BreakpointRequestDTO { id: string; range: SourceSpanDTO; enabled: boolean; condition?: string; hitCount?: number }
export interface BreakpointDTO extends BreakpointRequestDTO { verified: boolean; resolvedRange?: SourceSpanDTO; message?: string }
export interface InstructionDTO { addressHex: string; bytesHex: string; text: string; current: boolean; source?: SourceSpanDTO }
export interface BackendErrorDTO {
  code: 'UNSUPPORTED' | 'INVALID_REQUEST' | 'STALE_CONTEXT' | 'STALE_STOP' | 'BUSY' | 'BUILD_FAILED' | 'LAUNCH_FAILED' | 'READ_FAILED' | 'WRITE_FAILED' | 'TIMEOUT' | 'STEP_TIMEOUT' | 'CANCELLED' | 'REPLAY_DIVERGED' | 'EVENT_GAP' | 'HISTORY_EVICTED' | 'LIMIT_EXCEEDED' | 'INTERNAL';
  message: string;
  retryable: boolean;
  detail?: string;
}
export type BackendCommandDTO =
  | { kind: 'capabilities' }
  | { kind: 'build'; source: SourceBundleDTO; configuration: BuildConfigurationDTO; architecture: ArchitectureDTO }
  | { kind: 'launch'; buildId: string; input: SubmittedInputDTO; argv: string[]; environment: Record<string, string>; stopAtEntry: boolean }
  | { kind: 'appendInput'; id: string; text: string }
  | { kind: 'closeInput' }
  | { kind: 'step'; stepKind: 'over' | 'into' | 'out' | 'instruction' }
  | { kind: 'continue' }
  | { kind: 'pause' }
  | { kind: 'stop' }
  | { kind: 'getState' }
  | { kind: 'listHistory'; branchId: string; afterOrdinal: number | null; limit: number }
  | { kind: 'readHistory'; point: HistoryPointDTO }
  | { kind: 'restoreExecution'; point: HistoryPointDTO; strategy: 'verified-replay' }
  | { kind: 'setBreakpoints'; documentId: string; revisionId: string; breakpoints: BreakpointRequestDTO[] }
  | { kind: 'readVariables'; reference: string; start: number; count: number }
  | { kind: 'writeVariable'; locator: string; expected: RuntimeValueDTO; value: ScalarValueDTO }
  | { kind: 'disassemble'; buildId: string; target: { kind: 'pc'; addressHex: string } | { kind: 'source'; range: SourceSpanDTO }; maxInstructions: number }
  | { kind: 'readMemory'; addressHex: string; byteCount: number }
  | { kind: 'cancel'; targetRequestId: string }
  | { kind: 'replayEvents'; afterSequence: number };
export interface BackendRequestDTO {
  protocolVersion: BackendProtocolVersion;
  requestId: string;
  workspace: WorkspaceRefDTO;
  session: SessionRefDTO | null;
  /** Required for mutations, stepping and live handles; checked atomically by backend. */
  expectedStop?: StopRefDTO;
  command: BackendCommandDTO;
}
export type BackendResultDTO =
  | { kind: 'capabilities'; capabilities: BackendCapabilitiesDTO }
  | { kind: 'accepted' }
  | { kind: 'input'; input: InputStateDTO }
  /** Assigned before inferior events; buffer early events by causedByRequestId until this arrives. */
  | { kind: 'launchAccepted'; session: SessionRefDTO; throughSequence: 0 }
  | { kind: 'build'; artifact: BuildArtifactDTO | null; success: boolean; command: string[]; stdout: string; stderr: string; exitCode: number | null; truncated: boolean }
  | { kind: 'state'; state: DebugSessionStateDTO; observation: StopObservationDTO | null; throughSequence: number }
  | { kind: 'history'; items: { point: HistoryPointDTO; stop: StopRefDTO; label: string; retained: boolean }[]; hasMore: boolean }
  | { kind: 'observation'; observation: StopObservationDTO }
  | { kind: 'variables'; variables: VariableDTO[]; hasMore: boolean }
  | { kind: 'breakpoints'; breakpoints: BreakpointDTO[] }
  | { kind: 'asm'; architecture: ArchitectureDTO; instructions: InstructionDTO[]; truncated: boolean }
  | { kind: 'memory'; addressHex: string; bytesBase64: string; unreadableBytes: number }
  | { kind: 'events'; events: BackendEventDTO[] };
export type BackendResponseDTO = {
  protocolVersion: BackendProtocolVersion;
  requestId: string;
  workspace: WorkspaceRefDTO;
  session: SessionRefDTO | null;
} & ({ ok: true; result: BackendResultDTO } | { ok: false; error: BackendErrorDTO });
export type BackendEventPayloadDTO =
  | { kind: 'state'; state: DebugSessionStateDTO }
  | { kind: 'observation'; observation: StopObservationDTO }
  | { kind: 'output'; stream: 'stdout' | 'stderr'; text: string; fromByte: number; throughByte: number; truncated: boolean }
  | { kind: 'input'; input: InputStateDTO }
  | { kind: 'breakpoints'; breakpoints: BreakpointDTO[] }
  | { kind: 'restoreProgress'; completedCommands: number; totalCommands: number; phase: 'replaying' | 'verifying'; candidateProcessInstanceId: string }
  | { kind: 'branchCreated'; branchId: string; parent: HistoryPointDTO }
  | { kind: 'historyEvicted'; branchId: string; throughOrdinal: number }
  | { kind: 'commandFinished'; requestId: string; outcome: 'completed' | 'cancelled' | 'failed'; error?: BackendErrorDTO }
  | { kind: 'error'; error: BackendErrorDTO };
export interface BackendEventDTO {
  protocolVersion: BackendProtocolVersion;
  workspace: WorkspaceRefDTO;
  session: SessionRefDTO | null;
  /** Required provenance for inferior events; null only when no process produced this event. */
  processInstanceId: string | null;
  /** Monotonic safe integer within workspace revision + session generation, starting at 1. */
  sequence: number;
  causedByRequestId?: string;
  payload: BackendEventPayloadDTO;
}
/** New adapter seam; a future implementation must validate all incoming JSON at runtime. */
export interface DebugBackendAdapter {
  readonly protocolVersion: BackendProtocolVersion;
  connect(request: { supportedProtocolVersions: number[] }): Promise<
    | { ok: true; protocolVersion: BackendProtocolVersion; workspace: WorkspaceRefDTO; state: DebugSessionStateDTO | null; observation: StopObservationDTO | null; capabilities: BackendCapabilitiesDTO; throughSequence: number }
    | { ok: false; error: BackendErrorDTO }
  >;
  request(request: BackendRequestDTO): Promise<BackendResponseDTO>;
  subscribe(listener: (event: BackendEventDTO) => void): () => void;
  dispose(): Promise<void>;
}
