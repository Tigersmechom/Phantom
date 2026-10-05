/** Runtime inspection and recorder evidence. All imports are type-only. */
import type { ElfInspectionDTO, HistoryPointDTO, MemoryRegionDTO, StopRefDTO } from './backend-contract';

export type RecordingProfileDTO = 'native' | 'gdb-record-full';

/**
 * Instruction positions are decimal strings, not JavaScript numbers. They
 * identify boundaries in the current GDB recording, not observation ordinals.
 * Eviction can make older positions unreachable while observations remain.
 */
export type RecordingStatusDTO = {
  profile: 'gdb-record-full';
  available: true;
  mode: 'record' | 'replay';
  currentInstruction: string;
  firstInstruction: string;
  lastInstruction: string;
  earliestSeekableInstruction: string;
  recordedInstructions: number;
  maxRecordedInstructions: number;
  evicted: boolean;
  coverage: {
    registers: 'gdb-record-full';
    memory: 'gdb-record-full';
    externalEffects: 'not-restored';
    instructionSupport: 'target-dependent';
    osState: 'current-process';
    inputTransport: 'not-restored';
  };
} | {
  profile: RecordingProfileDTO;
  available: false;
  reason:
    | 'recording-not-requested'
    | 'recording-not-active'
    | 'recording-state-unavailable'
    | 'unrecognized-recording-state'
    | 'process-exited';
};

export type RecorderProbeStageDTO = {
  attempted: false;
  ok: false;
  status: 'not-run';
  exitCode: null;
  signal: null;
  stdout: string;
  stderr: string;
  detail: string;
} | {
  attempted: true;
  ok: true;
  status: 'succeeded';
  exitCode: 0;
  signal: 0;
  stdout: string;
  stderr: string;
  detail: null;
} | {
  attempted: true;
  ok: false;
  status:
    | 'spawn-error'
    | 'io-error'
    | 'timeout'
    | 'cancelled'
    | 'output-limit'
    | 'trace-limit'
    | 'exit-error';
  exitCode: number | null;
  signal: number | null;
  /** Bounded diagnostics with invalid UTF-8 replaced for wire transport. */
  stdout: string;
  stderr: string;
  detail: string | null;
};

export interface RrProbeDTO {
  /** True only after both recording and replay of the shipped fixture pass. */
  available: boolean;
  reason: string | null;
  version: RecorderProbeStageDTO;
  record: RecorderProbeStageDTO;
  replay: RecorderProbeStageDTO;
}

export interface GdbRecordFullProbeDTO {
  available: boolean;
  reason: string | null;
  mode: 'synchronous-all-stop';
  version: RecorderProbeStageDTO;
  probe: RecorderProbeStageDTO;
  memoryRestored: boolean;
  pcRestored: boolean;
  forwardReplay: boolean;
}

/**
 * Evidence from isolated child processes. A passing scalar fixture does not
 * promise support for arbitrary library instructions, syscalls or workloads.
 * No user execution history or persistent recorder trace is created by this.
 */
export interface RecorderProbeDTO {
  scope: 'isolated-scalar-fixture';
  elapsedMs: number;
  cancelled: boolean;
  environment: {
    perfEventParanoid: number | null;
    ptraceScope: number | null;
  };
  rr: RrProbeDTO;
  gdbRecordFull: GdbRecordFullProbeDTO;
  limitations: string[];
  detail?: string;
}

/** Evidence applies only to the supplied isolated fixture and fixed script. */
export interface RuntimeProbeEvidenceDTO {
  profile: 'linux-x86_64-syscall-probe-v1';
  pid: number;
  pageSize: number;
  scratchAddressHex: string;
  getpid: boolean;
  allocated: boolean;
  writable: boolean;
  executable: boolean;
  payloadExecuted: boolean;
  released: boolean;
  deniedSyscall: boolean;
  registersRestored: boolean;
  stackUnchanged: boolean;
  errnoUnchanged: boolean;
  signalMaskUnchanged: boolean;
  /** Original syscall site and entry marker, not every executable mapping. */
  codeUnchanged: boolean;
  signalStopVerified: boolean;
  handlerNotRun: boolean;
  registerCount: number;
  stackBytes: number;
}
export interface RuntimeProbeDTO {
  scope: 'isolated-runtime-fixture';
  profile: 'linux-x86_64-syscall-probe-v1';
  /** Never enables runtime injection in the user's session. */
  available: boolean;
  reason: string;
  elapsedMs: number;
  cancelled: boolean;
  gdbVersion: RecorderProbeStageDTO;
  execution: RecorderProbeStageDTO;
  evidence: RuntimeProbeEvidenceDTO | null;
  limitations: string[];
}

export type RuntimeModuleFileDTO = {
  available: true;
  identityVerified: true;
  openedVia: 'map-files' | 'process-exe' | 'process-root';
} | {
  available: false;
  identityVerified: false;
  reason: string;
  detail: string;
};

export interface RuntimeModuleMappedRangeDTO {
  /** Actual mapped intersection, [start,end), not an inferred allocation. */
  startAddressHex: string;
  endAddressHex: string;
  permissions: string;
  backing: 'file' | 'anonymous';
  regionStartAddressHex: string;
}

export interface RuntimeModuleSegmentDTO {
  programHeaderIndex: number;
  /** Relocated ELF PT_LOAD boundaries; mappedRanges describes actual coverage. */
  startAddressHex: string;
  endAddressHex: string;
  fileEndAddressHex: string;
  flags: { read: boolean; write: boolean; execute: boolean };
  mappedRanges: RuntimeModuleMappedRangeDTO[];
}

export interface RuntimeModuleInstanceDTO {
  /** Signed hexadecimal: a negative relocation bias has the form -0x1234. */
  loadBiasHex: string;
  evidence: 'PT_LOAD-file-offset';
  coverage: 'complete' | 'partial';
  segments: RuntimeModuleSegmentDTO[];
}

export interface RuntimeModuleDTO {
  /** File identity, shared by multiple mappings/relocation instances. */
  id: string;
  device: string;
  inodeDecimal: string;
  path: string | null;
  pathBytesHex?: string;
  contentIdentity: 'file-metadata-only';
  file: RuntimeModuleFileDTO;
  elf: ElfInspectionDTO;
  mappedRegions: MemoryRegionDTO[];
  instances: RuntimeModuleInstanceDTO[];
  unassignedRegionStarts: string[];
  instanceReason?: string;
}

/**
 * File-backed mapping inspection, not a dynamic-loader ownership manifest.
 * Anonymous BSS intersections provide address coverage, not proof of ownership.
 * A module may remain listed with unavailable ELF metadata or no load instance.
 */
export type RuntimeModulesDTO = {
  available: true;
  source: 'linux-proc-maps-elf';
  coverage: 'complete' | 'partial' | 'truncated';
  identityVerified: true;
  pid: string;
  pageSizeBytes: string;
  modules: RuntimeModuleDTO[];
  reason?: 'inspection-limit-or-truncated-maps';
} | {
  available: false;
  source: 'linux-proc-maps-elf';
  coverage: 'none';
  identityVerified: false;
  modules: [];
  reason: string;
  detail: string;
};

/** Immutable gateway capture; its OS evidence is not rewound by GDB replay. */
export interface ModuleSnapshotDTO {
  type: 'moduleSnapshot';
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  evidenceScope: 'current-os-state';
  modules: RuntimeModulesDTO;
}

/** Static ELF metadata; file bytes may differ from relocated process memory. */
export interface ElfSectionDTO {
  index: number;
  name: string | null;
  nameBytesHex?: string;
  type: string;
  typeValue: number;
  flagsHex: string;
  flags: { alloc: boolean; write: boolean; execute: boolean; tls: boolean; compressed: boolean };
  addressHex: string;
  offsetHex: string;
  sizeHex: string;
  alignmentHex: string;
  entrySizeHex: string;
  link: number;
  info: number;
  fileBacked: boolean;
}
export interface ElfSymbolDTO {
  tableSectionIndex: number;
  index: number;
  table: 'symtab' | 'dynsym';
  name: string | null;
  nameBytesHex?: string;
  valueHex: string;
  sizeHex: string;
  binding: string;
  bindingValue: number;
  type: string;
  typeValue: number;
  visibility: string;
  visibilityValue: number;
  otherValue: number;
  sectionIndex: number | null;
  rawSectionIndex: number;
  definition: 'section' | 'undefined' | 'absolute' | 'common' | 'reserved';
  valueKind: 'virtual-address' | 'section-offset' | 'tls-offset' | 'absolute' | 'common-alignment' | 'undefined' | 'other';
  /** Prefix evidence only; it does not verify a C++ object's vptr or lifetime. */
  classification: 'vtable' | 'typeinfo' | 'typeinfo-name' | 'vtt' | null;
  classificationEvidence: 'itanium-mangled-prefix' | null;
}
export interface ElfSymbolMetadataDTO {
  available: boolean;
  source: 'elf-section-symbol-tables';
  coverage: 'complete' | 'truncated' | 'none';
  elfType?: string;
  sectionCount?: number;
  symbolCount?: number;
  symbolTables: { sectionIndex: number; kind: 'symtab' | 'dynsym'; symbolCount: number }[];
  reason?: string;
  detail?: string;
}
export interface RuntimeSymbolLocationDTO {
  loadBiasHex: string;
  status: 'mapped' | 'partial' | 'unmapped' | 'overflow' | 'unknown';
  addressHex: string | null;
  endAddressHex: string | null;
  mappedRanges: RuntimeModuleMappedRangeDTO[];
}
export type RuntimeSectionDTO = ElfSectionDTO & {
  runtimeLocations: RuntimeSymbolLocationDTO[];
  runtimeReason?: string;
};
export type RuntimeSymbolDTO = ElfSymbolDTO & {
  runtimeLocations: RuntimeSymbolLocationDTO[];
  runtimeReason?: string;
  runtimeMeaning: 'address' | 'ifunc-resolver' | 'absolute-value' | 'tls-offset' | 'undefined' | 'common' | 'non-runtime-section' | 'unsupported-definition';
};
export interface RuntimeModuleSymbolsDTO {
  available: boolean;
  source: 'linux-proc-maps-elf-symbols';
  coverage: 'complete' | 'partial' | 'truncated' | 'none';
  identityVerified: boolean;
  pid?: string;
  moduleId: string;
  contentIdentity: 'file-metadata-only';
  module?: RuntimeModuleDTO;
  elfMetadata?: ElfSymbolMetadataDTO;
  sections: RuntimeSectionDTO[];
  symbols: RuntimeSymbolDTO[];
  reason?: string;
  detail?: string;
}
export interface ModuleSymbolsSnapshotDTO {
  type: 'moduleSymbolsSnapshot';
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  evidenceScope: 'current-os-state';
  report: RuntimeModuleSymbolsDTO;
}

/** GDB's declared type structure; addresses do not establish C++ lifetime. */
export interface VariableLayoutNodeDTO {
  id: string;
  kind: 'struct' | 'union' | 'array' | 'pointer' | 'reference' | 'integer' | 'float' | 'enum' | 'boolean' | 'void' | 'function' | 'other';
  typeName: string | null;
  byteSize: string | null;
  addressHex: string | null;
  addressReason: string | null;
  fields?: VariableLayoutFieldDTO[];
  targetTypeName?: string | null;
  /** Compact first-element template, not an eagerly expanded allocation. */
  array?: {
    lowerBound: string | null;
    upperBound: string | null;
    elementCount: string | null;
    strideBytes: string | null;
    elementLayout: VariableLayoutNodeDTO | null;
  };
}
export interface VariableLayoutFieldDTO {
  name: string | null;
  kind: 'member' | 'base' | 'static';
  artificial: boolean;
  /** Relative to the enclosing node. Bit order is GDB's target bitpos. */
  bitOffset: string | null;
  byteOffset: string | null;
  bitOffsetInByte: number | null;
  bitSize: string | null;
  offsetEvidence: 'dwarf' | 'unknown';
  reason: string | null;
  type: VariableLayoutNodeDTO | null;
}
export interface VariableLayoutDTO {
  available: boolean;
  source: 'gdb-python-dwarf';
  bitOffsetConvention: 'gdb-target-bitpos';
  locator: string;
  coverage: 'complete' | 'partial' | 'truncated' | 'none';
  lifetime: 'unknown';
  storage: { available: boolean; addressHex: string | null; reason: string | null };
  root: VariableLayoutNodeDTO | null;
  limits: { maxDepth: number; maxNodes: number; maxFields: number; maxNameLength: number; maxResponseBytes: number };
  truncationReasons: string[];
  reason?: string;
}
export interface VariableLayoutSnapshotDTO {
  type: 'variableLayoutSnapshot';
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  layout: VariableLayoutDTO;
}

/** Symbol evidence does not prove that a live C++ object owns this storage. */
export interface VtableSymbolDTO {
  moduleId: string;
  tableSectionIndex: number;
  index: number;
  name: string | null;
  nameBytesHex?: string;
  type: string;
  addressHex: string;
  sizeHex: string;
  kind: 'vtable' | 'construction-vtable' | 'rtti' | 'function';
}
export interface VtableEntryDTO {
  /** Index within the captured word window, not a virtual method index. */
  index: number;
  addressHex: string;
  bytesHex: string;
  valueHex: string;
  classification: 'null' | 'executable-address' | 'other';
  functions: VtableSymbolDTO[];
}
/** Conditional decoding under an explicitly requested absolute-pointer ABI. */
export interface VtableReportDTO {
  available: boolean;
  source: 'itanium-vtable-memory';
  abi: 'itanium-x86_64-absolute-v1';
  abiEvidence: 'requested-profile';
  lifetime: 'unknown';
  consistency: 'sampled-not-atomic';
  sampleStatus: 'stable' | 'changed' | 'unconfirmed';
  coverage: 'complete' | 'partial' | 'truncated' | 'none';
  vptrAddressHex: string;
  requestedEntries: number;
  vptrSlot: { addressHex: string; bytesHex: string; valueHex: string } | null;
  header: {
    addressHex: string;
    bytesHex: string;
    offsetToTopDecimal: string;
    topAddressCandidateHex: string | null;
    rttiAddressHex: string;
  } | null;
  tableSymbols: VtableSymbolDTO[];
  rttiSymbols: VtableSymbolDTO[];
  /** The symbol extent can include secondary tables; it is not a method count. */
  tableEnd: 'unknown';
  scanStop: string;
  entries: VtableEntryDTO[];
  metadata: { requestedModules: number; truncated: boolean };
  reason?: string;
}
export interface VtableSnapshotDTO {
  type: 'vtableSnapshot';
  id: string;
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
  evidenceScope: 'debugger-memory-and-current-os-metadata';
  report: VtableReportDTO;
}

/** Lineage of live native interventions, not a cloned or replayable process. */
export interface InterventionBranchDTO {
  id: string;
  parent: HistoryPointDTO | null;
  interventionId: string | null;
}
/** An in-memory audit retained until the next successful launch/workspace change. */
export interface MemoryInterventionBaseDTO {
  id: string;
  requestId: string;
  processInstanceId: string;
  beforePoint: HistoryPointDTO;
  beforeStop: StopRefDTO;
  afterPoint: HistoryPointDTO | null;
  afterStop: StopRefDTO | null;
  branchId: string | null;
  contextStatus: 'unchanged' | 'refreshed' | 'failed';
  mapping: { startAddressHex: string; endAddressHex: string; permissions: 'rw-p' };
  refreshError: { code: string; message: string } | null;
  report: {
    addressHex: string;
    byteCount: number;
    expectedBytesHex: string | null;
    replacementBytesHex: string | null;
    outcome: 'conflict' | 'unchanged' | 'verified' | 'readback-mismatch' | 'unverified' | 'read-before-failed' | 'write-rejected';
    /** Full bytes or a proven contiguous prefix. Null means no byte evidence. */
    beforeBytesHex: string | null;
    afterBytesHex: string | null;
    beforeMatchesExpected: boolean | null;
    afterMatchesReplacement: boolean | null;
    afterMatchesBefore: boolean | null;
    writeAttempted: boolean;
    writeAcknowledged: boolean;
    /** Last callback liveness, not a promise the later snapshot succeeded. */
    debuggerAlive: boolean;
    atomic: false;
    rollbackAttempted: false;
    errors: { phase: 'read-before' | 'write' | 'read-after'; code: string; message: string }[];
  };
}

/** Ordered, disjoint byte ranges. No C++ type or lifetime is asserted. */
export interface MemoryBatchEditDTO {
  addressHex: string;
  expectedBytesHex: string;
  replacementBytesHex: string;
}
export interface MemoryBatchReadDTO {
  /** Full bytes or a proven contiguous prefix; null means no byte evidence. */
  bytesHex: string | null;
  /** Compared only after a complete, error-free read from a live debugger. */
  matchesExpected: boolean | null;
  error: { code: string; message: string } | null;
}
export interface MemoryBatchReportDTO {
  byteCount: number;
  atomic: false;
  rollbackAttempted: false;
  writeAttempted: boolean;
  debuggerAlive: boolean;
  preflightPassed: boolean;
  outcome: 'preflight-failed' | 'unchanged' | 'verified' | 'interrupted' | 'verification-failed';
  /** First failure encountered; later final-read failures do not replace an
   *  execution failure, even at a smaller item index. Null on success. */
  failureIndex: number | null;
  items: (MemoryBatchEditDTO & {
    index: number;
    byteCount: number;
    /** Null means this range was not sampled in that phase. */
    preflight: MemoryBatchReadDTO | null;
    /** Fresh compare/write/readback, distinct from the earlier preflight. */
    execution: MemoryInterventionBaseDTO['report'] | null;
    /** Sampled after the execution loop, including skipped/no-op ranges.
     *  Only attempted mutations trigger this sweep; no atomic snapshot claim. */
    final: (MemoryBatchReadDTO & { matchesReplacement: boolean | null }) | null;
  })[];
}
export interface MemoryBatchInterventionDTO extends Omit<MemoryInterventionBaseDTO, 'mapping' | 'report'> {
  profile: 'native-private-memory-batch-v1';
  /** One mapping per item, in request order. Mappings may repeat. */
  mappings: MemoryInterventionBaseDTO['mapping'][];
  report: MemoryBatchReportDTO;
}

/** Typed storage edits do not claim a live C++ object or language assignment. */
export type ScalarStorageProfileDTO = 'native-dwarf-scalar-v1' | 'native-dwarf-scalar-v2';
export type ScalarStorageValueV1DTO =
  | { kind: 'integer'; decimal: string; bits: 8 | 16 | 32 | 64; signed: boolean }
  | { kind: 'boolean'; value: boolean };
export type ScalarStorageValueDTO = ScalarStorageValueV1DTO
  /** Exact MSB-first bits: 8/16 lowercase hex digits, no 0x. Never a JS number.
   *  This is numeric bit order, unlike little-endian storage.bytesHex.
   *  Every NaN payload/signaling bit is preserved without FP evaluation. */
  | { kind: 'float'; bits: 32 | 64; rawBitsHex: string };
export type ScalarStorageTypeV1DTO =
  | { kind: 'integer'; byteSize: 1 | 2 | 4 | 8; bits: 8 | 16 | 32 | 64;
      signed: boolean; byteOrder: 'little'; representation: 'twos-complement' | 'unsigned-binary' }
  | { kind: 'boolean'; byteSize: 1; bits: 8; signed: null;
      byteOrder: 'little'; representation: 'boolean-01' };
export type ScalarStorageTypeDTO = ScalarStorageTypeV1DTO
  | { kind: 'float'; byteSize: 4; bits: 32; signed: null;
      byteOrder: 'little'; representation: 'ieee754-binary32' }
  | { kind: 'float'; byteSize: 8; bits: 64; signed: null;
      byteOrder: 'little'; representation: 'ieee754-binary64' };
export interface ScalarStorageTargetDTO<T extends ScalarStorageTypeDTO = ScalarStorageTypeDTO> {
  available: boolean;
  source: 'gdb-python-dwarf';
  locator: string;
  lifetime: 'unknown';
  reason: string | null;
  typeName: string | null;
  scalar: T | null;
  addressHex: string | null;
}
interface ScalarStorageSnapshotBaseDTO {
  id: string;
  type: 'scalarStorageSnapshot';
  point: HistoryPointDTO;
  stop: StopRefDTO;
  processInstanceId: string;
}
interface ScalarStorageContentDTO<V extends ScalarStorageValueDTO> {
  /** True means complete bytes; invalid bool representation still has bytes. */
  available: boolean;
  bytesHex: string | null;
  value: V | null;
  reason: string | null;
}
export type ScalarStorageSnapshotDTO = ScalarStorageSnapshotBaseDTO & (
  | { profile: 'native-dwarf-scalar-v1'; target: ScalarStorageTargetDTO<ScalarStorageTypeV1DTO>;
      storage: ScalarStorageContentDTO<ScalarStorageValueV1DTO> }
  | { profile: 'native-dwarf-scalar-v2'; target: ScalarStorageTargetDTO;
      storage: ScalarStorageContentDTO<ScalarStorageValueDTO> }
);
export interface ScalarStorageInterventionDTO<
  V extends ScalarStorageValueDTO = ScalarStorageValueDTO,
  T extends ScalarStorageTypeDTO = ScalarStorageTypeDTO> {
  snapshotId: string;
  locator: string;
  target: ScalarStorageTargetDTO<T>;
  requestedValue: V;
  beforeValue: V | null;
  afterValue: V | null;
}
export type ScalarStorageBatchEditDTO =
  | { profile: 'native-dwarf-scalar-v1'; snapshotId: string; value: ScalarStorageValueV1DTO }
  | { profile: 'native-dwarf-scalar-v2'; snapshotId: string; value: ScalarStorageValueDTO };
/** Each value decodes only its corresponding raw phase's complete bytes.
 *  Null also covers invalid scalar representation; never infer lifetime. */
export type ScalarStorageBatchItemDTO = { index: number } & (
  | (ScalarStorageInterventionDTO<ScalarStorageValueV1DTO, ScalarStorageTypeV1DTO> & {
      profile: 'native-dwarf-scalar-v1';
      preflightValue: ScalarStorageValueV1DTO | null;
      finalValue: ScalarStorageValueV1DTO | null;
    })
  | (ScalarStorageInterventionDTO & {
      profile: 'native-dwarf-scalar-v2';
      preflightValue: ScalarStorageValueDTO | null;
      finalValue: ScalarStorageValueDTO | null;
    })
);
export interface ScalarStorageBatchInterventionDTO extends Omit<MemoryBatchInterventionDTO, 'profile'> {
  profile: 'native-dwarf-scalar-batch-v1';
  /** Aligned by index with report.items and mappings. */
  scalars: ScalarStorageBatchItemDTO[];
}
export type MemoryInterventionDTO = (MemoryInterventionBaseDTO & (
  | { profile: 'native-private-memory-v1'; scalar?: never }
  | { profile: 'native-dwarf-scalar-v1'; scalar: ScalarStorageInterventionDTO<ScalarStorageValueV1DTO, ScalarStorageTypeV1DTO> }
  | { profile: 'native-dwarf-scalar-v2'; scalar: ScalarStorageInterventionDTO }
)) | MemoryBatchInterventionDTO | ScalarStorageBatchInterventionDTO;

/** Full-width integer data registers of the verified native x86-64 thread.
 *  IP, stack/frame pointers, flags, aliases and vector/system state are excluded. */
export type NativeGprNameDTO = 'rax' | 'rbx' | 'rcx' | 'rdx' | 'rsi' | 'rdi'
  | 'r8' | 'r9' | 'r10' | 'r11' | 'r12' | 'r13' | 'r14' | 'r15';
export interface RegisterInterventionTargetDTO {
  architecture: 'x86_64';
  register: NativeGprNameDTO;
  bits: 64;
  threadId: string;
  frameLevel: 0;
}
export interface RegisterInterventionReportDTO {
  register: NativeGprNameDTO;
  bits: 64;
  /** Canonical numeric bit pattern: 0x and 16 lowercase digits, never JS number. */
  expectedValueHex: string;
  replacementValueHex: string;
  beforeValueHex: string | null;
  afterValueHex: string | null;
  beforeMatchesExpected: boolean | null;
  afterMatchesReplacement: boolean | null;
  afterMatchesBefore: boolean | null;
  outcome: MemoryInterventionBaseDTO['report']['outcome'];
  writeAttempted: boolean;
  writeAcknowledged: boolean;
  debuggerAlive: boolean;
  atomic: false;
  rollbackAttempted: false;
  errors: MemoryInterventionBaseDTO['report']['errors'];
}
export interface RegisterInterventionDTO extends Omit<MemoryInterventionBaseDTO, 'mapping' | 'report'> {
  profile: 'native-x86_64-gpr-v1';
  target: RegisterInterventionTargetDTO;
  report: RegisterInterventionReportDTO;
}
export interface RuntimeHelperManifestDTO {
  profile: 'linux-x86_64-scratch-v1';
  symbol: '__phantom_runtime_syscall_v1';
  addressHex: string;
  bytesHex: '0f05cc';
  helperSha256: string;
}
export interface RuntimeHelperEvidenceDTO {
  pid: number;
  pageSize: number;
  /** Historical address of scratch storage, already unmapped on success. */
  scratchAddressHex: string;
  registerCount: number;
  stackBytes: number;
  getpid: boolean;
  allocated: boolean;
  writable: boolean;
  executable: boolean;
  payloadExecuted: boolean;
  released: boolean;
  registersRestored: boolean;
  stackUnchanged: boolean;
  errnoUnchanged: boolean;
  signalMaskUnchanged: boolean;
  signalPolicyRestored: boolean;
  codeUnchanged: boolean;
  mapsRestored: boolean;
}
export interface RuntimeHelperReportDTO {
  profile: 'linux-x86_64-scratch-v1';
  /** Conservative send boundary, including context edits before any syscall. */
  writeAttempted: boolean;
  /** Execution may have happened even if its acknowledgement was lost. */
  executionAttempted: boolean;
  debuggerAlive: boolean;
  /** Accepted cancellation can arrive after verified execution completed. */
  cancelled: boolean;
  outcome: 'rejected' | 'verified' | 'failed';
  phase: 'prepare' | 'execute' | 'verify';
  evidence: RuntimeHelperEvidenceDTO | null;
  error: { code: string; message: string } | null;
}
export interface RuntimeInterventionDTO extends Omit<MemoryInterventionBaseDTO, 'mapping' | 'report'> {
  profile: 'linux-x86_64-scratch-v1';
  target: RuntimeHelperManifestDTO;
  report: RuntimeHelperReportDTO;
}
export interface RuntimeAllocationEvidenceDTO {
  pid: number;
  pageSize: number;
  addressHex: string;
  /** Page-rounded extent, not a C++ object or enclosing VMA size. */
  byteCount: number;
  registerCount: number;
  stackBytes: number;
  getpid: boolean;
  allocated: boolean;
  released: boolean;
  zeroInitialized: boolean;
  registersRestored: boolean;
  stackUnchanged: boolean;
  errnoUnchanged: boolean;
  signalMaskUnchanged: boolean;
  signalPolicyRestored: boolean;
  codeUnchanged: boolean;
  mappingDeltaVerified: boolean;
}
export interface RuntimeAllocationReportDTO extends Omit<RuntimeHelperReportDTO, 'profile' | 'evidence'> {
  profile: 'linux-x86_64-retained-rw-v1';
  action: 'allocate' | 'release';
  evidence: RuntimeAllocationEvidenceDTO | null;
}
export interface RuntimeAllocationInterventionDTO extends Omit<MemoryInterventionBaseDTO, 'mapping' | 'report'> {
  profile: 'linux-x86_64-retained-rw-v1';
  action: 'allocate' | 'release';
  target: {
    /** Reserved attempt identity; only verified allocations enter the registry. */
    allocationId: string;
    addressHex: string | null;
    requestedBytes: number;
    byteCount: number | null;
  };
  report: RuntimeAllocationReportDTO;
}
/** Readable page protections; writable executable storage is excluded. */
export type RuntimeMemoryPermissionsDTO = 'r--' | 'rw-' | 'r-x';
export interface RuntimeProtectionEvidenceDTO extends Omit<RuntimeAllocationEvidenceDTO,
  'allocated' | 'released' | 'zeroInitialized'> {
  beforePermissions: RuntimeMemoryPermissionsDTO;
  afterPermissions: RuntimeMemoryPermissionsDTO;
  protectionApplied: boolean;
  bytesUnchanged: boolean;
}
export interface RuntimeProtectionReportDTO extends Omit<RuntimeHelperReportDTO, 'profile' | 'evidence'> {
  profile: 'linux-x86_64-owned-protection-v1';
  action: 'protect';
  evidence: RuntimeProtectionEvidenceDTO | null;
}
export interface RuntimeProtectionInterventionDTO extends Omit<MemoryInterventionBaseDTO, 'mapping' | 'report'> {
  profile: 'linux-x86_64-owned-protection-v1';
  action: 'protect';
  target: {
    allocationId: string;
    addressHex: string;
    byteCount: number;
    expectedPermissions: RuntimeMemoryPermissionsDTO;
    replacementPermissions: RuntimeMemoryPermissionsDTO;
  };
  report: RuntimeProtectionReportDTO;
}
/** Current registry view; permissions remain historical after authority ends. */
export interface RuntimeAllocationDTO {
  id: string;
  processInstanceId: string;
  requestedBytes: number;
  byteCount: number;
  addressHex: string;
  createdByInterventionId: string;
  createdAt: HistoryPointDTO | null;
  releasedByInterventionId: string | null;
  permissions: RuntimeMemoryPermissionsDTO;
  lastProtectionInterventionId: string | null;
  state: 'owned' | 'ownership-unknown' | 'released' | 'process-ended';
  invalidatedByRequestId: string | null;
  releaseAllowed: boolean;
  protectionAllowed: boolean;
  authorityStop: StopRefDTO | null;
}
export type InterventionDTO = MemoryInterventionDTO | RegisterInterventionDTO | RuntimeInterventionDTO | RuntimeAllocationInterventionDTO | RuntimeProtectionInterventionDTO;
