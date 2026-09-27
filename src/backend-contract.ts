/** Proposed debugger adapter protocol. This file does not implement or expose an IPC bridge. */
export const BACKEND_PROTOCOL_VERSION = 1 as const;
export type BackendProtocolVersion = typeof BACKEND_PROTOCOL_VERSION;
export type ArchitectureDTO = 'arm64' | 'x86_64';

/** Zero-based UTF-16 code-unit offsets, [start, end), in the exact referenced text. */
export interface Utf16Range { start: number; end: number }
/** Frontend compatibility view: revision is the EXACT submitted stdin TEXT, not an ID/hash. */
export interface InputTrace {
  revision: string;
  consumedRanges: Utf16Range[];
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
  /** Protocol v1 has fixed stdin only; append/interactive input is not part of this contract. */
  closeAfterWrite: true;
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
  children?: VariableDTO[];
}
export interface StackFrameDTO {
  id: string;
  activationId: string;
  functionName: string;
  location: SourceSpanDTO | null;
  variables: VariableDTO[];
}

/**
 * A source operation is an observed execution boundary. A source line can
 * produce several operations and an operation can stop before completion
 * (for example when an expression throws), so consumers must not collapse
 * these records to one event per line.
 */
export type OperationKindDTO =
  | 'statement' | 'expression' | 'instruction' | 'call' | 'return' | 'branch'
  | 'switch' | 'case' | 'loop' | 'break' | 'continue' | 'goto' | 'throw' | 'catch'
  | 'rethrow' | 'cleanup' | 'input' | 'output' | 'allocation' | 'lifetime';
export type OperationBoundaryDTO = 'before' | 'after' | 'throw' | 'unwind' | 'catch' | 'terminate';
export interface OperationTraceDTO {
  id: string;
  /** Stable occurrence identity across replay; do not derive it from line number. */
  occurrence: string;
  kind: OperationKindDTO;
  granularity: 'statement' | 'expression' | 'instruction';
  boundary: OperationBoundaryDTO;
  range: SourceSpanDTO | null;
  activationId: string | null;
  threadId: string | null;
  observed: boolean;
  /** Optional destination for control transfer operations. */
  targetRange?: SourceSpanDTO;
  targetActivationId?: string;
  condition?: RuntimeValueDTO;
  branch?: 'true' | 'false' | 'case' | 'default' | 'unknown';
  exceptionId?: string;
  exceptionType?: string;
}

/** A primitive global/static read, with enough provenance to highlight its declaration. */
export interface GlobalReferenceDTO {
  id: string;
  name: string;
  qualifiedName?: string;
  type: string;
  scope: 'global' | 'static' | 'thread-local';
  value: RuntimeValueDTO;
  locator: string;
  useRange?: SourceSpanDTO;
  declarationRange?: SourceSpanDTO;
}

export interface ControlFlowEventDTO {
  id: string;
  operationId?: string;
  kind: 'if' | 'else' | 'loop' | 'switch' | 'case' | 'default' | 'break' | 'continue' | 'goto' | 'throw' | 'catch' | 'rethrow' | 'return' | 'fallthrough' | 'cleanup';
  phase: 'before' | 'condition' | 'taken' | 'enter' | 'leave' | 'unwind' | 'caught' | 'terminate' | 'fallthrough';
  range: SourceSpanDTO | null;
  targetRange?: SourceSpanDTO;
  condition?: RuntimeValueDTO;
  branch?: 'true' | 'false' | 'case' | 'default' | 'unknown';
  activationId?: string;
  fromActivationId?: string;
  toActivationId?: string;
  exceptionId?: string;
  exceptionType?: string;
  /** False means the adapter knows the record is incomplete or inferred. */
  observed: boolean;
}

export type RuntimeOutcomeDTO =
  | 'normal' | 'throwing' | 'caught' | 'uncaught' | 'rethrowing'
  | 'terminate' | 'assert' | 'signal' | 'segfault' | 'undefined-behavior' | 'timeout';

export interface TraceGapDTO {
  id: string;
  range: SourceSpanDTO | null;
  reason: 'not-instrumented' | 'optimized-out' | 'unsupported' | 'limit' | 'event-loss' | 'unobserved';
  detail?: string;
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
  /** Global/static primitive reads observed by this stage. */
  globalReferences?: GlobalReferenceDTO[];
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
  globalReferences?: GlobalReferenceDTO[];
}
export interface InputStateDTO {
  submitted: SubmittedInputDTO;
  tracking: 'none' | 'transport-only' | 'observed-extractions';
  /** Bytes written to the pipe are NOT proof that the C++ extraction consumed them. */
  deliveredBytes: number;
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
}
export interface StopObservationDTO {
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  buildId: string;
  sourceBundleId: string;
  reason: 'entry' | 'step' | 'breakpoint' | 'pause' | 'signal' | 'mutation' | 'exit';
  /** Actual PC location before the next instruction, not proof this statement has completed. */
  location: SourceSpanDTO | null;
  threadId: string | null;
  stack: StackFrameDTO[];
  input: InputStateDTO;
  stdout: OutputSnapshotDTO;
  stderr: OutputSnapshotDTO;
  expressions: ExpressionTraceDTO[];
  /** Optional semantic trace. Missing means this capability was not captured. */
  operations?: OperationTraceDTO[];
  controlFlow?: ControlFlowEventDTO[];
  outcome?: RuntimeOutcomeDTO;
  gaps?: TraceGapDTO[];
  coverage: { variables: 'complete' | 'partial'; expressions: 'none' | 'partial' | 'observed'; memory: 'none' | 'partial' };
}
export interface DebugSessionStateDTO {
  session: SessionRefDTO;
  phase: 'idle' | 'building' | 'launching' | 'stopped' | 'running' | 'pausing' | 'restoring' | 'terminated' | 'failed';
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
  expressionGroups: boolean;
  /** Optional semantic capture advertised independently from ordinary stepping. */
  operationTrace?: boolean;
  controlFlowTrace?: boolean;
  globalPrimitiveReferences?: boolean;
  runtimeOutcomes?: boolean;
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
  code: 'UNSUPPORTED' | 'INVALID_REQUEST' | 'STALE_CONTEXT' | 'STALE_STOP' | 'BUSY' | 'BUILD_FAILED' | 'LAUNCH_FAILED' | 'READ_FAILED' | 'WRITE_FAILED' | 'TIMEOUT' | 'CANCELLED' | 'REPLAY_DIVERGED' | 'EVENT_GAP' | 'HISTORY_EVICTED' | 'LIMIT_EXCEEDED' | 'INTERNAL';
  message: string;
  retryable: boolean;
  detail?: string;
}
export type BackendCommandDTO =
  | { kind: 'capabilities' }
  | { kind: 'build'; source: SourceBundleDTO; configuration: BuildConfigurationDTO; architecture: ArchitectureDTO }
  | { kind: 'launch'; buildId: string; input: SubmittedInputDTO; argv: string[]; environment: Record<string, string>; stopAtEntry: boolean }
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
