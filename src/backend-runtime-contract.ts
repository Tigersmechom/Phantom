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
