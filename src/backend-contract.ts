import type { NativeGprNameDTO, RegisterInterventionDTO, InterventionDTO, ScalarStorageBatchEditDTO, MemoryBatchEditDTO, ScalarStorageProfileDTO, ScalarStorageSnapshotDTO, ScalarStorageValueV1DTO, ScalarStorageValueDTO, MemoryInterventionDTO, InterventionBranchDTO, VtableSnapshotDTO, ModuleSymbolsSnapshotDTO, VariableLayoutSnapshotDTO, ModuleSnapshotDTO, RecorderProbeDTO, RecordingProfileDTO, RecordingStatusDTO } from './backend-runtime-contract';
export type * from './backend-runtime-contract';

/** Debugger protocol DTOs. This file does not implement or expose an IPC bridge. */
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

export type AddressProfileDTO = 'native' | 'fixed-executable';
export type AddressPolicyDTO = 'native' | 'disable-aslr' | 'require-fixed';
export type ElfTypeDTO = 'ET_NONE' | 'ET_REL' | 'ET_EXEC' | 'ET_DYN' | 'ET_CORE' | 'unknown';
export interface ElfProgramHeaderDTO {
  index: number;
  type: 'PT_LOAD' | 'PT_INTERP' | 'PT_GNU_STACK' | 'PT_GNU_RELRO';
  offsetHex: string;
  virtualAddressHex: string;
  fileSizeHex: string;
  memorySizeHex: string;
  alignmentHex: string;
  flags: { read: boolean; write: boolean; execute: boolean };
}
export type ElfInspectionDTO = {
  available: true;
  format: 'ELF';
  class: 64;
  endianness: 'little';
  elfType: ElfTypeDTO;
  elfTypeValue: number;
  architecture: 'x86_64' | 'unsupported';
  machine: number;
  entryAddressHex: string;
  programHeaders: ElfProgramHeaderDTO[];
  /** GNU build ID from PT_NOTE, not the backend artifact ID. */
  buildId: string | null;
} | { available: false; reason: string; detail: string };

export interface BuildConfigurationDTO {
  revisionId: string;
  compiler: string;
  flags: string[];
  outputDirectory: string;
  /** Omitted means native; fixed-executable adds non-PIE flags and verifies ET_EXEC. */
  addressProfile?: AddressProfileDTO;
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
  addressProfile: AddressProfileDTO;
  elf: ElfInspectionDTO;
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
  /** Original launch input; append/EOF updates are represented below. */
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
/** ABI-qualified runtime storage at one stop; inspecting it never calls flush. */
export type RuntimeBufferSnapshotDTO = {
    available: true;
    source: 'glibc-_IO_FILE' | 'libstdc++-stdio_filebuf';
    stream: 'stdout' | 'cout';
    /** cout-synchronized aliases the C buffer: never concatenate it twice. */
    association: 'cout-if-synchronized' | 'cout-synchronized' | 'cout-unsynchronized';
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
export interface OutputSnapshotDTO {
  /** Already emitted bytes; immutable per historical snapshot. */
  text: string;
  totalBytes: number;
  retainedFromByte: number;
  truncated: boolean;
  /** C stdout buffer. Separate pending domains have no implied total order. */
  buffered?: RuntimeBufferSnapshotDTO;
  /** Actual std::cout buffer, or an explicit unsupported/custom-rdbuf reason. */
  coutBuffered?: RuntimeBufferSnapshotDTO;
}
/** Physical output effects survive reverse execution and stop-history eviction. */
export interface OutputCursorDTO {
  source: 'transport' | 'recording-checkpoint' | 'unknown';
  stdoutThroughByte: number | null;
  stderrThroughByte: number | null;
}
export type OutputJournalSegmentDTO =
  | { kind: 'bytes'; fromByte: number; throughByte: number; bytesBase64: string }
  | { kind: 'gap'; fromByte: number; throughByte: number; reason: 'not-retained' };
export interface OutputJournalDTO {
  kind: 'outputJournal';
  stream: 'stdout' | 'stderr';
  processInstanceId: string;
  branchId: string;
  consistent: boolean;
  selectedPoint: HistoryPointDTO | null;
  selectedThroughByte: number | null;
  fromByte: number;
  throughByte: number;
  totalBytes: number;
  retainedFromByte: number;
  retainedBytes: number;
  retentionHasGaps: boolean;
  coverage: 'complete' | 'partial';
  hasMore: boolean;
  segments: OutputJournalSegmentDTO[];
}
export interface MemoryRegionDTO {
  /** Virtual interval [start,end); strings retain the full native address. */
  startAddressHex: string;
  endAddressHex: string;
  permissions: string;
  offsetHex: string;
  device: string;
  inodeDecimal: string;
  /** Exact kernel pathname spelling, including its escapes and deleted suffix. */
  path: string | null;
  pathBytesHex?: string;
  kind: 'file' | 'heap' | 'stack' | 'anonymous' | 'special';
}
export type MemoryMapSnapshotDTO = {
  available: true;
  source: 'linux-proc-maps';
  coverage: 'complete' | 'truncated';
  regions: MemoryRegionDTO[];
  reason?: 'byte-limit' | 'region-limit';
} | {
  available: false;
  source: 'linux-proc-maps';
  coverage: 'none';
  regions: [];
  reason: string;
  detail?: string;
  lineNumber?: number;
};

export interface ProcUnavailableSectionDTO {
  available: false;
  coverage: 'none';
  reason: string;
  detail: string;
}
export type ProcSectionDTO<T> =
  | ({ available: true; coverage: 'complete' | 'partial' } & T)
  | ProcUnavailableSectionDTO;
/** Kernel-reported values may be zeroed by ptrace restrictions; null means absent. */
export interface ProcessAddressBoundariesDTO {
  startCodeHex: string | null;
  endCodeHex: string | null;
  startStackHex: string | null;
  startDataHex: string | null;
  endDataHex: string | null;
  startBrkHex: string | null;
  argStartHex: string | null;
  argEndHex: string | null;
  envStartHex: string | null;
  envEndHex: string | null;
}
export interface ProcessIdentityIdsDTO {
  real: string;
  effective: string;
  saved: string;
  filesystem: string;
}
export type ProcPathDTO = ProcSectionDTO<{
  /** Paths are metadata only; the backend never opens the link target. */
  path: string | null;
  pathBytesHex?: string;
}>;
export type ProcessInspectionDTO = {
  source: 'linux-procfs';
  pid: string;
} & ((ProcUnavailableSectionDTO & { identityVerified: false }) | {
  available: true;
  coverage: 'complete' | 'partial';
  /** starttime verified around reads through one pinned proc-directory descriptor. */
  identityVerified: true;
  stat: ProcSectionDTO<{
    pid: string;
    startTimeTicks: string;
    command: string | null;
    commandBytesHex?: string;
    state: string;
    addresses: ProcessAddressBoundariesDTO;
    addressEvidence: 'kernel-reported-may-be-redacted';
  }>;
  personality: ProcSectionDTO<{
    maskHex: string;
    /** Observed ADDR_NO_RANDOMIZE flag, not proof of allocator/replay determinism. */
    addrNoRandomize: boolean;
  }>;
  status: ProcSectionDTO<{
    state?: string;
    threads?: number;
    tracerPid?: string;
    seccomp?: number;
    noNewPrivs?: boolean;
    uid?: ProcessIdentityIdsDTO;
    gid?: ProcessIdentityIdsDTO;
  }>;
  executable: ProcPathDTO;
  fileDescriptors: ProcUnavailableSectionDTO | {
    available: true;
    coverage: 'complete' | 'partial' | 'truncated';
    reason?: 'descriptor-limit' | 'directory-read-error' | 'malformed-descriptor';
    entries: (ProcPathDTO & { descriptor: number })[];
  };
  memory: ProcSectionDTO<{
    countersBytes: {
      rss?: string;
      pss?: string;
      sharedClean?: string;
      sharedDirty?: string;
      privateClean?: string;
      privateDirty?: string;
      anonymous?: string;
      swap?: string;
      swapPss?: string;
      locked?: string;
    };
  }>;
  system: ProcSectionDTO<{
    kernelRelease: string | null;
    kernelReleaseBytesHex?: string;
    machine: string | null;
    machineBytesHex?: string;
    pageSizeBytes?: string;
  }>;
});

/** Evidence captured at launch, not a guarantee of addresses after future execution. */
export interface ExecutionLayoutDTO {
  addressPolicy: AddressPolicyDTO;
  elfType: ElfTypeDTO | null;
  aslr: {
    requestedDisabled: boolean;
    verifiedDisabled: boolean | null;
    evidence: 'linux-proc-personality' | 'unavailable';
    personalityMaskHex: string | null;
  };
  addresses: ProcessAddressBoundariesDTO | null;
  processStartTimeTicks: string | null;
  runFingerprint: string;
  allocatorDeterminism: 'not-established';
  replayVerified: false;
}

export interface InspectionContextDTO {
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
}
export interface MemoryRangeRequestDTO { addressHex: string; byteCount: number }
export type CapturedMemoryRangeDTO = MemoryRangeRequestDTO & (
  | { available: true; bytesBase64: string; unreadableBytes: 0 }
  | {
    available: false;
    bytesBase64?: string;
    unreadableBytes: number;
    reason: 'read-failed' | 'partial-read' | 'process-exited';
  }
);
/** Immutable retained bytes from selected ranges; contents are not allocation identities. */
export interface MemoryCaptureDTO extends InspectionContextDTO {
  type: 'memoryCapture';
  id: string;
  coverage: 'complete' | 'partial';
  ranges: CapturedMemoryRangeDTO[];
}
export interface MemoryByteChangeDTO {
  addressHex: string;
  byteCount: number;
  beforeBytesHex: string;
  afterBytesHex: string;
}
export interface MemoryCaptureDiffDTO {
  kind: 'memoryCaptureDiff';
  beforeCaptureId: string;
  afterCaptureId: string;
  coverage: 'complete' | 'partial';
  comparedBytes: number;
  changedBytes: number;
  unavailableRanges: (MemoryRangeRequestDTO & { beforeAvailable: boolean; afterAvailable: boolean })[];
  changes: MemoryByteChangeDTO[];
  start: number;
  totalChanges: number;
  hasMore: boolean;
}
/** Exact VMA interval comparison: splitting a mapping produces removed/added intervals. */
export type MemoryMapChangeDTO =
  | { kind: 'added'; before: null; after: MemoryRegionDTO }
  | { kind: 'removed'; before: MemoryRegionDTO; after: null }
  | { kind: 'changed'; before: MemoryRegionDTO; after: MemoryRegionDTO };
export interface MemoryMapDiffDTO {
  kind: 'memoryMapDiff';
  beforePoint: HistoryPointDTO;
  afterPoint: HistoryPointDTO;
  changes: MemoryMapChangeDTO[];
  start: number;
  totalChanges: number;
  hasMore: boolean;
}
export type RegisterValueDTO = { number: number; name: string } & (
  | { available: true; valueHex: string }
  | { available: false; reason: 'not-returned' | 'non-hex-or-unavailable' | 'process-exited' | 'read-failed' }
);
export interface InstructionTraceEntryDTO {
  ordinal: number;
  pcBeforeHex: string | null;
  pcAfterHex: string | null;
  registerChanges: { name: string; before: RegisterValueDTO; after: RegisterValueDTO }[];
  memoryChanges: (MemoryRangeRequestDTO & { before: CapturedMemoryRangeDTO; after: CapturedMemoryRangeDTO })[];
  /** GDB stop reason; a signal/breakpoint does not prove one instruction completed. */
  reason: string;
  instructionCompleted: boolean;
}
export type InstructionTraceStatusDTO = 'complete' | 'terminated' | 'failed';
export interface InstructionTraceDTO {
  type: 'instructionTrace';
  id: string;
  processInstanceId: string;
  beforePoint: HistoryPointDTO;
  beforeStop: StopRefDTO;
  afterPoint: HistoryPointDTO | null;
  afterStop: StopRefDTO | null;
  requestedInstructions: number;
  executedInstructions: number;
  attemptedInstructions: number;
  status: InstructionTraceStatusDTO;
  /** Backend termination category, error code, or a GDB stop reason. */
  terminationReason: string;
  coverage: {
    registers: 'selected-instruction-boundaries';
    memory: 'selected-instruction-boundaries';
    sameValueWrites: false;
    otherThreads: 'not-recorded';
  };
  initialRegisters: RegisterValueDTO[];
  initialMemory: CapturedMemoryRangeDTO[];
  /** Paged entries; initial values always describe the beginning of the entire trace. */
  entries: InstructionTraceEntryDTO[];
}
export interface StopObservationDTO {
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  buildId: string;
  sourceBundleId: string;
  reason: 'entry' | 'step' | 'breakpoint' | 'pause' | 'signal' | 'input-wait' | 'step-timeout' | 'recording-error' | 'recording-seek' | 'reverse-step' | 'mutation' | 'exit';
  /** Actual PC location before the next instruction, not proof this statement has completed. */
  location: SourceSpanDTO | null;
  threadId: string | null;
  stack: StackFrameDTO[];
  input: InputStateDTO;
  stdout: OutputSnapshotDTO;
  stderr: OutputSnapshotDTO;
  /** VMA metadata at this stop, not resident bytes or C++ allocation identity. */
  memoryMap?: MemoryMapSnapshotDTO;
  executionLayout?: ExecutionLayoutDTO;
  outputCursor?: OutputCursorDTO;
  recording?: RecordingStatusDTO;
  /** Procfs data belongs to the actual OS process, including during replay. */
  osEvidenceScope?: 'current-process';
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
  maxTraceInstructions: number;
  maxTraceMemoryBytes: number;
  maxCaptureBytes: number;
  maxInspectionStoreBytes: number;
  maxOutputJournalBytesPerStream: number;
  maxOutputJournalReadBytes: number;
  maxRecordedInstructions: number;
  maxMemoryWriteBytes: number;
  maxMemoryBatchRanges?: number;
  maxMemoryBatchBytes?: number;
  maxScalarStorageBatchItems?: number;
  maxScalarStorageBatchBytes?: number;
  maxMemoryInterventions: number;
  /** Global ledger record cap across memory and register profiles. */
  maxInterventions?: number;
  maxInterventionStoreBytes: number;
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
  memoryWrite: 'native-private-memory-v1' | 'none';
  memoryWriteBatch?: 'native-private-memory-batch-v1' | 'none';
  scalarStorage: 'native-dwarf-scalar-v1' | 'none';
  /** Absent on legacy servers; float bits require an explicit v2 inspection. */
  scalarStorageProfiles?: ScalarStorageProfileDTO[];
  scalarStorageBatch?: 'native-dwarf-scalar-batch-v1' | 'none';
  registerWrite?: 'native-x86_64-gpr-v1' | 'none';
  interventionLog?: boolean;
  interventionBranches: boolean;
  inputTracking: InputStateDTO['tracking'];
  interactiveInput: boolean;
  expressionGroups: boolean;
  history: boolean;
  restore: 'none' | 'verified-replay';
  asm: { currentPc: boolean; sourceRange: boolean };
  memoryRead: boolean;
  memoryMap?: 'linux-proc-maps' | 'none';
  addressProfiles: AddressProfileDTO[];
  addressPolicies: AddressPolicyDTO[];
  processInspection: 'linux-procfs' | 'none';
  registerRead: boolean;
  instructionTrace: 'instruction-boundaries' | 'none';
  memoryCapture: boolean;
  memoryMapDiff: boolean;
  outputJournal: boolean;
  moduleSymbols: 'elf-section-symbol-tables' | 'none';
  variableLayout: 'gdb-python-dwarf' | 'none';
  vtableInspection: 'itanium-x86_64-absolute-v1' | 'none';
  moduleInspection: 'linux-proc-maps-elf' | 'none';
  recorderProbe: boolean;
  recordingProfiles: RecordingProfileDTO[];
  recordingCursor: boolean;
  eventReplay: boolean;
  limits: ResourceLimitsDTO;
}
export interface BreakpointRequestDTO { id: string; range: SourceSpanDTO; enabled: boolean; condition?: string; hitCount?: number }
export interface BreakpointDTO extends BreakpointRequestDTO { verified: boolean; resolvedRange?: SourceSpanDTO; message?: string }
export interface InstructionDTO { addressHex: string; bytesHex: string; text: string; current: boolean; source?: SourceSpanDTO }
export interface BackendErrorDTO {
  code: 'UNSUPPORTED' | 'INVALID_REQUEST' | 'STALE_CONTEXT' | 'STALE_STOP' | 'BUSY' | 'BUILD_FAILED' | 'LAUNCH_FAILED' | 'READ_FAILED' | 'WRITE_FAILED' | 'TIMEOUT' | 'STEP_TIMEOUT' | 'INPUT_WAIT' | 'CANCELLED' | 'REPLAY_DIVERGED' | 'EVENT_GAP' | 'HISTORY_EVICTED' | 'LIMIT_EXCEEDED' | 'INTERNAL';
  message: string;
  retryable: boolean;
  detail?: string;
}
export type BackendCommandDTO =
  | { kind: 'capabilities' }
  | { kind: 'build'; source: SourceBundleDTO; configuration: BuildConfigurationDTO; architecture: ArchitectureDTO }
  | { kind: 'launch'; buildId: string; input: SubmittedInputDTO; argv: string[]; environment: Record<string, string>; stopAtEntry: boolean; addressPolicy?: AddressPolicyDTO; recordingProfile?: RecordingProfileDTO; maxRecordedInstructions?: number }
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
  /** Compare and write raw storage, native/single-thread only. Events are emitted once. */
  | { kind: 'writeMemory'; profile: 'native-private-memory-v1'; addressHex: string; expectedBytesHex: string; replacementBytesHex: string }
  | { kind: 'writeMemoryBatch'; profile: 'native-private-memory-batch-v1'; edits: MemoryBatchEditDTO[] }
  | { kind: 'inspectScalarStorage'; locator: string; profile?: ScalarStorageProfileDTO }
  | { kind: 'readScalarStorage'; snapshotId: string }
  | { kind: 'writeScalarStorage'; profile: 'native-dwarf-scalar-v1'; snapshotId: string; value: ScalarStorageValueV1DTO }
  | { kind: 'writeScalarStorage'; profile: 'native-dwarf-scalar-v2'; snapshotId: string; value: ScalarStorageValueDTO }
  | { kind: 'writeScalarStorageBatch'; profile: 'native-dwarf-scalar-batch-v1'; edits: ScalarStorageBatchEditDTO[] }
  | { kind: 'readMemoryIntervention'; interventionId: string }
  | { kind: 'listMemoryInterventions'; start: number; count: number }
  | { kind: 'writeRegister'; profile: 'native-x86_64-gpr-v1'; register: NativeGprNameDTO; expectedValueHex: string; replacementValueHex: string }
  | { kind: 'readRegisterIntervention'; interventionId: string }
  | { kind: 'listRegisterInterventions'; start: number; count: number }
  | { kind: 'readIntervention'; interventionId: string }
  | { kind: 'listInterventions'; start: number; count: number }
  | { kind: 'listBranches' }
  | { kind: 'readMemory'; addressHex: string; byteCount: number }
  | { kind: 'readOutputJournal'; stream: 'stdout' | 'stderr'; fromByte: number; byteCount: number; point?: HistoryPointDTO }
  | { kind: 'inspectProcess' }
  | { kind: 'inspectModules' }
  | { kind: 'inspectModuleSymbols'; moduleId: string }
  | { kind: 'readModuleSymbols'; snapshotId: string; start: number; count: number }
  | { kind: 'inspectVariableLayout'; locator: string }
  | { kind: 'readVariableLayout'; snapshotId: string }
  | { kind: 'inspectVtable'; abi: 'itanium-x86_64-absolute-v1'; vptrAddressHex: string; maxEntries: number }
  | { kind: 'readVtableSnapshot'; snapshotId: string }
  | { kind: 'readModuleSnapshot'; snapshotId: string }
  | { kind: 'probeRecorders' }
  | { kind: 'readRecording' }
  | { kind: 'seekRecording'; instruction: string }
  | { kind: 'reverseInstruction' }
  | { kind: 'readRegisters'; registers?: string[] }
  /** Executes instructions. Produces observation/state/trace-recorded/commandFinished events. */
  | { kind: 'traceInstructions'; count: number; registers?: string[]; memoryRanges: MemoryRangeRequestDTO[] }
  | { kind: 'captureMemory'; ranges: MemoryRangeRequestDTO[] }
  /** Retained reads/diffs require the session, but no live expectedStop. */
  | { kind: 'readMemoryCapture'; captureId: string }
  | { kind: 'diffMemoryCaptures'; beforeCaptureId: string; afterCaptureId: string; start: number; count: number }
  | { kind: 'diffMemoryMaps'; beforePoint: HistoryPointDTO; afterPoint: HistoryPointDTO; start: number; count: number }
  | { kind: 'readInstructionTrace'; traceId: string; start: number; count: number }
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
  /** Write response includes final event sequence; duplicate request returns this response without emitting events again. */
  | { kind: 'memoryIntervention'; intervention: MemoryInterventionDTO; throughSequence?: number }
  | { kind: 'scalarStorage'; snapshot: ScalarStorageSnapshotDTO }
  | { kind: 'memoryInterventions'; items: MemoryInterventionDTO[]; start: number; total: number; hasMore: boolean }
  | { kind: 'registerIntervention'; intervention: RegisterInterventionDTO; throughSequence?: number }
  | { kind: 'registerInterventions'; items: RegisterInterventionDTO[]; start: number; total: number; hasMore: boolean }
  | { kind: 'intervention'; intervention: InterventionDTO }
  | { kind: 'interventions'; items: InterventionDTO[]; start: number; total: number; hasMore: boolean }
  | { kind: 'branches'; currentBranchId: string; branches: InterventionBranchDTO[] }
  | OutputJournalDTO
  | { kind: 'moduleSnapshot'; snapshot: ModuleSnapshotDTO }
  | { kind: 'moduleSymbols'; snapshot: ModuleSymbolsSnapshotDTO; start: number; totalSymbols: number; hasMore: boolean }
  | { kind: 'variableLayout'; snapshot: VariableLayoutSnapshotDTO }
  | { kind: 'vtableSnapshot'; snapshot: VtableSnapshotDTO }
  | { kind: 'recorderProbe'; probe: RecorderProbeDTO }
  | (InspectionContextDTO & { kind: 'recording'; recording: RecordingStatusDTO })
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
  | (InspectionContextDTO & { kind: 'processInspection'; evidenceScope: 'current-os-state'; inspection: ProcessInspectionDTO })
  | (InspectionContextDTO & { kind: 'registers'; architecture: ArchitectureDTO; registers: RegisterValueDTO[] })
  | { kind: 'memoryCapture'; capture: MemoryCaptureDTO }
  | MemoryCaptureDiffDTO
  | MemoryMapDiffDTO
  | { kind: 'instructionTrace'; trace: InstructionTraceDTO; start: number; totalEntries: number; hasMore: boolean }
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
  | { kind: 'instructionTraceRecorded'; traceId: string; status: InstructionTraceStatusDTO; terminationReason: string; totalEntries: number }
  | { kind: 'commandFinished'; requestId: string; outcome: 'completed' | 'waiting' | 'cancelled' | 'failed'; error?: BackendErrorDTO }
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
/** Adapter seam; implementations must validate all incoming JSON at runtime. */
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
