import { randomUUID } from 'node:crypto';
import { DomainError } from '../domain/errors.ts';
import type { AnalysisRequest, CalibrationProfile } from '../domain/types.ts';
import { analyzeExperiment } from './analysis-service.ts';
import type { AuditStore } from './audit-store.ts';
import { digestOf } from '../domain/audit/canonical.ts';
import { calibrationProfileDigest, stripAnalysisId, summarizeOutcome } from '../domain/audit/evidence.ts';
import { ALGORITHM_VERSION, currentRuleVersion, diffRuleManifests, getRuleManifest } from '../domain/audit/versions.ts';
import { DEFAULT_TOLERANCE, diffResults } from '../domain/audit/diff.ts';
import type {
  AuditRecord,
  CalibrationRef,
  DiffOutcome,
  ReplayCalibrationOption,
  ReplayConditionCode,
  ReplayEvidence,
  ReplayOptions,
  ReplayReport,
  ReplayStatus,
  ReplayTolerance,
  StoredOutcome,
} from '../domain/audit/types.ts';

type Inflight = { promise: Promise<ReplayReport>; joined: number };

/**
 * Replay orchestrator.
 *
 * Invariants:
 *  - replay ALWAYS starts from the request stored inside the immutable record;
 *    the caller cannot inject a new input;
 *  - by default the calibration payloads embedded in the record are used, never
 *    an ambient/current table. A registry comparison requires explicit opt-in
 *    and reports missing/changed profiles before recomputing;
 *  - no record file is ever written or mutated; only replays/<id>.json is added;
 *  - replays of the same record issued concurrently join one computation, and
 *    the joined reports carry CONCURRENT_REPLAY with identical verdicts.
 */
export class ReplayService {
  private readonly inflight = new Map<string, Inflight>();
  private readonly store: AuditStore;
  private readonly clock: () => string;

  constructor(store: AuditStore, clock: () => string = () => new Date().toISOString()) {
    this.store = store;
    this.clock = clock;
  }

  replay(recordId: string, options: ReplayOptions = {}): Promise<ReplayReport> {
    const existing = this.inflight.get(recordId);
    if (existing) {
      // Join the in-flight computation: the verdict is identical, but the
      // joined report gets its own replayId/timestamp and the concurrency mark.
      existing.joined += 1;
      const peersAtJoin = existing.joined;
      return existing.promise.then((report) => {
        const conditions: ReplayConditionCode[] = report.conditions.includes('CONCURRENT_REPLAY') ? [...report.conditions] : [...report.conditions, 'CONCURRENT_REPLAY'];
        return this.persist({ ...report, replayId: randomUUID(), replayedAt: this.clock(), conditions, concurrentPeers: peersAtJoin });
      });
    }
    const inflight: Inflight = { promise: this.runReplay(recordId, options), joined: 0 };
    this.inflight.set(recordId, inflight);
    inflight.promise.finally(() => {
      if (this.inflight.get(recordId) === inflight) this.inflight.delete(recordId);
    });
    // The initiating call learns how many other callers joined its run.
    return inflight.promise.then((report) => {
      if (inflight.joined > 0 && !report.conditions.includes('CONCURRENT_REPLAY')) report.conditions.push('CONCURRENT_REPLAY');
      return this.persist({ ...report, concurrentPeers: inflight.joined });
    });
  }

  private persist(report: ReplayReport): ReplayReport {
    return this.store.persistReplay(report);
  }

  private tolerance(options: ReplayOptions): ReplayTolerance {
    const absolute = options.tolerance?.absolute ?? DEFAULT_TOLERANCE.absolute;
    const relative = options.tolerance?.relative ?? DEFAULT_TOLERANCE.relative;
    if (!(Number.isFinite(absolute) && absolute >= 0) || !(Number.isFinite(relative) && relative >= 0)) {
      throw new DomainError('INVALID_REPLAY_TOLERANCE', 'Replay tolerances must be finite non-negative numbers', 422);
    }
    return { absolute, relative };
  }

  private async runReplay(recordId: string, options: ReplayOptions): Promise<ReplayReport> {
    const tolerance = this.tolerance(options);
    const located = this.store.locate(recordId);
    const baseEvidence: ReplayEvidence = {
      recordId,
      recordDigest: null,
      recordIntegrity: located.state,
      chainIntegrity: 'unchecked',
      inputCanonicalDigest: null,
      inputDigestMatches: null,
      sealedAlgorithmVersion: null,
      sealedRuleVersion: null,
      sealedAt: null,
      restarted: false,
    };

    if (!located.exists || located.state === 'not-found') {
      return this.notFoundReport(recordId, baseEvidence, tolerance);
    }

    if (located.state === 'unsealed') {
      return this.unreplayableReport(recordId, baseEvidence, tolerance, [], 'RECORD_UNSEALED', located.reason ?? 'Record sealing did not complete; evidence is partial');
    }

    const record = located.record!;
    const integrity = this.store.verifyIntegrity(record);
    const evidence: ReplayEvidence = {
      recordId,
      recordDigest: record.recordDigest ?? null,
      recordIntegrity: integrity.state,
      chainIntegrity: integrity.chain,
      inputCanonicalDigest: record.inputCanonicalDigest,
      inputDigestMatches: digestOf(record.request) === record.inputCanonicalDigest,
      sealedAlgorithmVersion: record.algorithmVersion,
      sealedRuleVersion: record.ruleVersion,
      sealedAt: record.sealedAt ?? null,
      restarted: record.sessionId !== this.store.sessionId,
    };

    if (integrity.state === 'tampered') {
      return this.unreplayableReport(recordId, evidence, tolerance, record.calibrationRefs, 'RECORD_TAMPERED', located.reason ?? 'Record failed digest verification');
    }
    if (integrity.state === 'orphaned') {
      return this.unreplayableReport(recordId, evidence, tolerance, record.calibrationRefs, 'RECORD_ORPHANED', located.reason ?? 'Record is not reachable through the evidence chain');
    }

    // Evidence verified: choose calibration inputs BEFORE any computation.
    const calibrationChoice = this.resolveCalibration(record, options.calibration ?? { mode: 'sealed' });

    const conditions: ReplayConditionCode[] = [];
    if (calibrationChoice.missing.length) conditions.push('CALIBRATION_MISSING');
    if (calibrationChoice.changed.length) conditions.push('CALIBRATION_CHANGED');

    const ruleChanged = record.ruleVersion !== currentRuleVersion();
    const changedModules = diffRuleManifests(record.ruleManifest, getRuleManifest());
    if (record.algorithmVersion !== ALGORITHM_VERSION) conditions.push('ALGORITHM_UPGRADED');
    else if (ruleChanged) conditions.push('RULE_VERSION_CHANGED');

    const versionInfo = this.versionBlock(record, changedModules);

    // A missing profile cannot be substituted: the exact historical input is
    // no longer runnable under the requested registry mode.
    if (calibrationChoice.missing.length) {
      return {
        ...this.baseReport(recordId, tolerance, evidence, conditions),
        status: 'unreplayable',
        reproducible: false,
        calibration: { mode: calibrationChoice.mode, refs: record.calibrationRefs, missingProfileIds: calibrationChoice.missing, changedProfileIds: calibrationChoice.changed },
        versions: versionInfo,
        storedSummary: structuredClone(record.summary),
        error: { code: 'CALIBRATION_MISSING', message: `Current calibration registry is missing profile(s): ${calibrationChoice.missing.join(', ')}` },
      };
    }

    // Re-run from the stored input, deep-cloned so execution cannot alias evidence.
    let replayedOutcome: StoredOutcome;
    try {
      const replayRequest: AnalysisRequest = { ...structuredClone(record.request), calibrations: structuredClone(calibrationChoice.profiles) };
      replayedOutcome = this.execute(record, replayRequest);
    } catch (error) {
      const domain = error instanceof DomainError ? error : new DomainError('REPLAY_FAILED', error instanceof Error ? error.message : 'Replay failed', 500);
      conditions.push('REPLAY_ERROR');
      return {
        ...this.baseReport(recordId, tolerance, evidence, conditions),
        status: 'unreplayable',
        reproducible: false,
        calibration: { mode: calibrationChoice.mode, refs: record.calibrationRefs, missingProfileIds: [], changedProfileIds: calibrationChoice.changed },
        versions: versionInfo,
        storedSummary: structuredClone(record.summary),
        error: { code: domain.code, message: domain.message },
      };
    }

    // Original run itself failed: compare failure identity rather than pretending success.
    if (record.outcome.status === 'failed' || replayedOutcome.status === 'failed') {
      conditions.push('OUTCOME_FAILED');
      const sameFailure = record.outcome.status === replayedOutcome.status && record.outcome.error?.code === replayedOutcome.error?.code;
      const diff = diffResults(record.outcome, replayedOutcome, tolerance);
      const status: ReplayStatus = sameFailure ? 'reproduced' : 'diverged';
      return {
        ...this.baseReport(recordId, tolerance, evidence, conditions),
        status,
        reproducible: status === 'reproduced',
        calibration: { mode: calibrationChoice.mode, refs: record.calibrationRefs, missingProfileIds: [], changedProfileIds: calibrationChoice.changed },
        versions: versionInfo,
        replayOutcome: structuredClone(replayedOutcome),
        summary: summarizeOutcome(replayedOutcome),
        storedSummary: structuredClone(record.summary),
        diff,
      };
    }

    const storedDeterministic = record.outcome.result!;
    const replayedDeterministic = replayedOutcome.result!;
    const diff: DiffOutcome = diffResults(this.computedView(storedDeterministic), this.computedView(replayedDeterministic), tolerance);
    if (diff.match === 'exact') conditions.push('REPLAYED_EXACT');
    else if (diff.match === 'within-tolerance') conditions.push('NUMERICAL_DRIFT');
    else conditions.push('RESULT_DIVERGED');

    const status: ReplayStatus = diff.match === 'exact' ? 'reproduced' : diff.match === 'within-tolerance' ? 'numerical-drift' : 'diverged';
    return {
      ...this.baseReport(recordId, tolerance, evidence, conditions),
      status,
      reproducible: diff.match === 'exact',
      calibration: { mode: calibrationChoice.mode, refs: record.calibrationRefs, missingProfileIds: [], changedProfileIds: calibrationChoice.changed },
      versions: versionInfo,
      replayOutcome: structuredClone(replayedOutcome),
      summary: summarizeOutcome(replayedOutcome),
      storedSummary: structuredClone(record.summary),
      diff,
    };
  }

  /**
   * Diff the *computed* outputs only. inputDigest/calibrationVersions are input
   * references that legitimately change when a registry replay supplies another
   * calibration; they live in evidence/calibration, not in the reproduction diff.
   */
  private computedView(result: NonNullable<StoredOutcome['result']>) {
    const { inputDigest: _inputDigest, calibrationVersions: _calibrationVersions, ...computed } = result;
    return computed;
  }

  private execute(record: AuditRecord, request: AnalysisRequest): StoredOutcome {
    if (record.outcome.status === 'failed') {
      // Re-attempt the exact same input; success now means behavior changed.
      try {
        return { status: 'success', result: stripAnalysisId(analyzeExperiment(request)) };
      } catch (error) {
        const domain = error instanceof DomainError ? error : new DomainError('ANALYSIS_FAILED', error instanceof Error ? error.message : 'Unknown analysis failure');
        return { status: 'failed', error: { code: domain.code, message: domain.message } };
      }
    }
    return { status: 'success', result: stripAnalysisId(analyzeExperiment(request)) };
  }

  private resolveCalibration(record: AuditRecord, option: ReplayCalibrationOption): { mode: 'sealed' | 'registry'; profiles: CalibrationProfile[]; missing: string[]; changed: string[] } {
    const sealedProfiles = record.request.calibrations;
    if (option.mode !== 'registry') return { mode: 'sealed', profiles: sealedProfiles, missing: [], changed: [] };

    const current = option.profiles;
    const byId = new Map(current.map((profile) => [profile.profileId, profile]));
    const refsById = new Map(record.calibrationRefs.map((ref) => [ref.profileId, ref]));
    const missing: string[] = [];
    const changed: string[] = [];
    const profiles: CalibrationProfile[] = [];

    // Compare against every profile the original analysis actually depended on,
    // matched by profileId (calibration version identity).
    for (const originalProfile of sealedProfiles) {
      const ref = refsById.get(originalProfile.profileId);
      const currentProfile = byId.get(originalProfile.profileId);
      if (!currentProfile) {
        missing.push(originalProfile.profileId);
        continue;
      }
      if (ref && calibrationProfileDigest(currentProfile) !== ref.contentDigest) changed.push(originalProfile.profileId);
      profiles.push(currentProfile);
    }
    return { mode: 'registry', missing: [...new Set(missing)].sort(), changed: [...new Set(changed)].sort(), profiles };
  }

  private versionBlock(record: AuditRecord, changedModules: string[]) {
    return {
      sealedAlgorithm: record.algorithmVersion,
      currentAlgorithm: ALGORITHM_VERSION,
      sealedRule: record.ruleVersion,
      currentRule: currentRuleVersion(),
      ruleManifestChanged: changedModules.length > 0,
      changedModules,
    };
  }

  private baseReport(recordId: string, tolerance: ReplayTolerance, evidence: ReplayEvidence, conditions: ReplayConditionCode[]) {
    return {
      replayId: randomUUID(),
      recordId,
      sessionId: this.store.sessionId,
      replayedAt: this.clock(),
      conditions,
      evidence,
      tolerance,
      concurrentPeers: 0,
    };
  }

  private notFoundReport(recordId: string, evidence: ReplayEvidence, tolerance: ReplayTolerance): ReplayReport {
    return {
      ...this.baseReport(recordId, tolerance, evidence, ['RECORD_NOT_FOUND']),
      status: 'not-found',
      reproducible: false,
      calibration: { mode: 'sealed' as const, refs: [], missingProfileIds: [], changedProfileIds: [] },
      versions: { sealedAlgorithm: null, currentAlgorithm: ALGORITHM_VERSION, sealedRule: null, currentRule: currentRuleVersion(), ruleManifestChanged: false, changedModules: [] },
      error: { code: 'AUDIT_RECORD_NOT_FOUND', message: 'No evidence record exists for this id in this store session' },
    };
  }

  private unreplayableReport(recordId: string, evidence: ReplayEvidence, tolerance: ReplayTolerance, refs: CalibrationRef[], code: ReplayConditionCode, reason: string): ReplayReport {
    return {
      ...this.baseReport(recordId, tolerance, evidence, [code]),
      status: 'unreplayable',
      reproducible: false,
      calibration: { mode: 'sealed' as const, refs, missingProfileIds: [], changedProfileIds: [] },
      versions: { sealedAlgorithm: evidence.sealedAlgorithmVersion, currentAlgorithm: ALGORITHM_VERSION, sealedRule: evidence.sealedRuleVersion, currentRule: currentRuleVersion(), ruleManifestChanged: false, changedModules: [] },
      error: { code, message: reason },
    };
  }
}
