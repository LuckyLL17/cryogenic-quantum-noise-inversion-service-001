import type { AnalysisRequest, AnalysisResult } from '../types.ts';

export type AuditKind = 'preview' | 'async';
export type OutcomeStatus = 'success' | 'failed';

/** Per-profile reference: identity + immutable content digest (not just the version id). */
export type CalibrationRef = {
  profileId: string;
  channelId: string;
  validFromNs: number;
  validToNs?: number;
  /** sha256 of the canonical JSON of the full profile payload. */
  contentDigest: string;
};

export type StoredOutcome = {
  status: OutcomeStatus;
  /** Deterministic part of AnalysisResult (analysisId stripped — it is a random UUID). */
  result?: Omit<AnalysisResult, 'analysisId'>;
  error?: { code: string; message: string };
};

/** Flat scalar snapshot used by list views and quick comparisons. Never a substitute for full evidence. */
export type ResultSummary = {
  resultDigest: string;
  noiseClass: string | null;
  amplitudeMean: number | null;
  amplitudeStdDev: number | null;
  phaseDriftRad: number | null;
  decayTimeConstantNs: number | null;
  decayRSquared: number | null;
  whiteLevel: number | null;
  integratedPower: number | null;
  confidence: number | null;
  dominantFrequencyHz: number | null;
  crossChannelCoherence: number | null;
  sampleCount: number | null;
  channelCount: number | null;
  spectrumBins: number | null;
  crossSpectrumBins: number | null;
  warnings: string[];
};

/**
 * Immutable evidence bundle. Once sealed:
 *  - the full input (raw samples + calibrations + options) is stored, not just its digest;
 *  - calibration references bind version ids to content digests;
 *  - algorithm/rule versions are pinned;
 *  - the sealed outcome and a scalar summary are preserved.
 */
export type AuditRecord = {
  recordId: string;
  kind: AuditKind;
  sessionId: string;
  createdAt: string;
  /** Set when the backing file is durable; absent until sealing completes. */
  sealedAt?: string;
  experimentId: string;
  kindOfExperiment: AnalysisRequest['kind'];
  associatedJobId?: string;
  /** Original legacy sha256(JSON.stringify(request)) as returned in AnalysisResult. */
  inputDigest: string;
  /** sha256 of the canonical JSON of the complete request — the evidence-grade digest. */
  inputCanonicalDigest: string;
  request: AnalysisRequest;
  calibrationRefs: CalibrationRef[];
  algorithmVersion: string;
  ruleVersion: string;
  ruleManifest: Record<string, string>;
  outcome: StoredOutcome;
  summary: ResultSummary;
  /** Position in the append-only evidence chain. */
  sequence: number;
  previousRecordDigest: string | null;
  /** sha256 over the canonical JSON of the whole record excluding this field. */
  recordDigest?: string;
};

/** Lightweight projection returned by the list endpoint. */
export type AuditRecordHead = {
  recordId: string;
  sequence: number;
  kind: AuditKind;
  sessionId: string;
  createdAt: string;
  sealedAt?: string;
  experimentId: string;
  kindOfExperiment: AnalysisRequest['kind'];
  associatedJobId?: string;
  inputDigest: string;
  inputCanonicalDigest: string;
  calibrationRefs: CalibrationRef[];
  algorithmVersion: string;
  ruleVersion: string;
  outcome: StoredOutcome;
  summary: ResultSummary;
  recordDigest: string;
  previousRecordDigest: string | null;
  recordState: RecordState;
};

/** Lifecycle/integrity state of an evidence record. */
export type RecordState = 'sealed' | 'unsealed' | 'tampered' | 'orphaned';

/** Why a replay could not run (or ran against something other than the original evidence). */
export type ReplayConditionCode =
  | 'REPLAYED_EXACT'
  | 'NUMERICAL_DRIFT'
  | 'RESULT_DIVERGED'
  | 'ALGORITHM_UPGRADED'
  | 'RULE_VERSION_CHANGED'
  | 'CALIBRATION_MISSING'
  | 'CALIBRATION_CHANGED'
  | 'RECORD_UNSEALED'
  | 'RECORD_ORPHANED'
  | 'RECORD_TAMPERED'
  | 'RECORD_NOT_FOUND'
  | 'OUTCOME_FAILED'
  | 'REPLAY_ERROR'
  | 'CONCURRENT_REPLAY';

/** High-level verdict a caller can branch on. */
export type ReplayStatus =
  | 'reproduced'
  | 'numerical-drift'
  | 'diverged'
  | 'unreplayable'
  | 'not-found';

export type ChangedValue = {
  path: string;
  stored: unknown;
  replayed: unknown;
  delta: number | null;
  kind: 'value' | 'structural';
};

export type DiffOutcome = {
  match: 'exact' | 'within-tolerance' | 'different';
  changes: ChangedValue[];
};

export type ReplayTolerance = {
  /** Absolute difference allowed for floating-point comparisons. */
  absolute: number;
  /** Relative difference allowed: |a-b| / max(|a|,|b|,floor). */
  relative: number;
};

export type ReplayCalibrationOption =
  | { mode?: 'sealed' }
  | { mode: 'registry'; profiles: import('../types.ts').CalibrationProfile[] };

export type ReplayOptions = {
  /**
   * 'sealed' (default): replay with the exact calibration payload embedded in the record.
   * 'registry': replay with supplied current profiles; refs are compared first so a
   * missing/changed calibration is reported rather than silently substituted.
   */
  calibration?: ReplayCalibrationOption;
  tolerance?: Partial<ReplayTolerance>;
};

export type ReplayEvidence = {
  recordId: string;
  recordDigest: string | null;
  recordIntegrity: RecordState | 'not-found';
  chainIntegrity: 'verified' | 'broken' | 'unchecked';
  inputCanonicalDigest: string | null;
  inputDigestMatches: boolean | null;
  sealedAlgorithmVersion: string | null;
  sealedRuleVersion: string | null;
  sealedAt: string | null;
  /** This process session differs from the session that sealed the record. */
  restarted: boolean;
};

export type ReplayReport = {
  replayId: string;
  recordId: string;
  sessionId: string;
  replayedAt: string;
  status: ReplayStatus;
  reproducible: boolean;
  /** Ordered, machine-readable condition codes. CONCURRENT_REPLAY marks a joined replay. */
  conditions: ReplayConditionCode[];
  evidence: ReplayEvidence;
  calibration: {
    mode: 'sealed' | 'registry';
    refs: CalibrationRef[];
    missingProfileIds: string[];
    changedProfileIds: string[];
  };
  versions: {
    sealedAlgorithm: string | null;
    currentAlgorithm: string;
    sealedRule: string | null;
    currentRule: string;
    ruleManifestChanged: boolean;
    /** Rule modules whose pinned version differs from the running code. */
    changedModules: string[];
  };
  tolerance: ReplayTolerance;
  /** Present whenever the replay computation actually executed. */
  replayOutcome?: StoredOutcome;
  summary?: ResultSummary;
  diff?: DiffOutcome;
  storedSummary?: ResultSummary;
  error?: { code: string; message: string };
  concurrentPeers: number;
};

/** Recovery-time observations surfaced through the audit health endpoint. */
export type RecoveryDetail = {
  recordId: string;
  state: RecordState;
  reason: string;
};

export type AuditHealth = {
  sessionId: string;
  recordsSealed: number;
  recordsInMemory: number;
  replaysRecorded: number;
  recovery: {
    recovered: number;
    details: RecoveryDetail[];
    orphaned: number;
    tampered: number;
    unsealed: number;
    tornIndexEntries: number;
    chainBroken: boolean;
  };
};
