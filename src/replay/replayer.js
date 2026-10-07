import { uuid, sha256Canonical } from '../util/hash.js';
import { createHash } from 'node:crypto';
import { diffResults } from '../util/diff.js';
import { currentEngineInfo, executeFrozenRule, executeRule } from '../analysis/engine.js';
import {
  REPLAY_MODE,
  RECORD_STATUS,
  RECORD_PROBLEM,
  verdictOf,
} from '../statuses.js';

/**
 * Replayer — turns an audit record into a deterministic, classified verdict.
 *
 * Invariants:
 *  - Replay NEVER writes to the original record directory; its report is
 *    written to <root>/replays/.
 *  - FAITHFUL mode loads ONLY the calibration/rule versions pinned by the
 *    record.  The registries' "current" versions are never substituted.
 *  - When the live implementation differs from the frozen one, the frozen
 *    source is recompiled and used.  Upgrades opt-in via CURRENT_REFERENCE.
 *  - Every inability to replay yields a distinct status code; callers never
 *    have to infer the reason from free text.
 */

/** Map an integrity problem code to the matching blocked-replay status. */
function problemStatus(code) {
  switch (code) {
    case RECORD_PROBLEM.PARTIAL_WRITE_DEBRIS:
    case RECORD_PROBLEM.EVENT_TORN:
      return 'REPLAY_BLOCKED_RECORD_PARTIAL';
    case RECORD_PROBLEM.META_MISSING:
    case RECORD_PROBLEM.META_CORRUPT:
    case RECORD_PROBLEM.EVENT_LOG_MISSING:
    case RECORD_PROBLEM.EVENT_CHAIN_BROKEN:
    case RECORD_PROBLEM.EVENT_UNEXPECTED:
    case RECORD_PROBLEM.RESULT_SUMMARY_CORRUPT:
    case RECORD_PROBLEM.META_REF_MISMATCH:
    case RECORD_PROBLEM.INPUT_BLOB_CORRUPT:
      return 'REPLAY_BLOCKED_RECORD_CORRUPT';
    case RECORD_PROBLEM.RESULT_DIGEST_MISMATCH:
      return 'REPLAY_BLOCKED_RECORD_TAMPERED';
    case RECORD_PROBLEM.INPUT_BLOB_MISSING:
      return 'REPLAY_BLOCKED_INPUT_MISSING';
    default:
      return 'REPLAY_BLOCKED_RECORD_CORRUPT';
  }
}

export class Replayer {
  /**
   * @param {object} args
   * @param {import('../audit/store.js').AuditStore} args.store
   * @param {import('../registries/calibration.js').CalibrationRegistry} args.calibrations
   * @param {import('../registries/rules.js').NoiseRuleRegistry} args.rules
   * @param {object} [args.engineInfo]
   */
  constructor({ store, calibrations, rules, engineInfo, numericRuntime }) {
    this.store = store;
    this.calibrationRegistry = calibrations;
    this.ruleRegistry = rules;
    this.numericRuntime = numericRuntime ?? null;
    this.engineInfo = engineInfo ?? currentEngineInfo(
      numericRuntime ? { stdlibDigest: numericRuntime.digest } : {},
    );
    /** @type {Map<string, number>} recordId -> concurrent faithful replays */
    this._inflight = new Map();
  }

  /**
   * Replay a stored record.
   * @param {string} recordId
   * @param {object} [options]
   * @param {keyof typeof REPLAY_MODE} [options.mode='FAITHFUL']
   * @param {boolean} [options.compareWithCurrent] also run CURRENT_REFERENCE
   *   after a faithful replay and report what a today-default run would give
   * @param {boolean} [options.allowEngineVersionMismatch] warn instead of block
   * @param {boolean} [options.persist] write the report into the store (default true)
   * @param {object}  [options.tolerance] forwarded to the diff
   */
  async replay(recordId, options = {}) {
    const {
      mode = REPLAY_MODE.FAITHFUL,
      compareWithCurrent = false,
      allowEngineVersionMismatch = false,
      persist = true,
      tolerance,
    } = options;

    const replayId = options.replayId ?? uuid();
    const startedAt = new Date().toISOString();
    const siblingsAtStart = this._inflight.get(recordId) ?? 0;
    let peakInflight = siblingsAtStart + 1;
    this._enter(recordId);
    let report;
    try {
      report = await this._build({
        recordId, replayId, startedAt, mode,
        compareWithCurrent, allowEngineVersionMismatch, tolerance,
      });
      peakInflight = Math.max(peakInflight, (this._inflight.get(recordId) ?? 1));
    } finally {
      this._leave(recordId);
    }
    const siblingsAtFinish = this._inflight.get(recordId) ?? 0;
    report.evidence.concurrency = {
      concurrentReplaysOfSameRecordAtStart: siblingsAtStart,
      peakConcurrentReplaysOfSameRecord: peakInflight,
      concurrentReplaysOfSameRecordAtFinish: siblingsAtFinish,
      totalInflightReplays: [...this._inflight.values()].reduce((a, b) => a + b, 0),
      observedAt: new Date().toISOString(),
      replayStartedAt: startedAt,
    };
    report.finishedAt = new Date().toISOString();
    report.verdict = verdictOf(report.status);
    report.reproducible = report.status === 'REPRODUCIBLE' ||
      report.status === 'REPRODUCIBLE_WITH_TOLERANCE';
    if (persist) report.reportPath = await this.store.writeReplayReport(report);
    return report;
  }

  _enter(recordId) {
    this._inflight.set(recordId, (this._inflight.get(recordId) ?? 0) + 1);
  }

  _leave(recordId) {
    const n = (this._inflight.get(recordId) ?? 1) - 1;
    if (n <= 0) this._inflight.delete(recordId);
    else this._inflight.set(recordId, n);
  }

  /** Number of records currently being replayed (test/observability hook). */
  inflightRecords() {
    return this._inflight.size;
  }

  async _build(ctx) {
    const { recordId, replayId, startedAt, mode, compareWithCurrent,
      allowEngineVersionMismatch, tolerance } = ctx;

    const base = {
      replayId,
      recordId,
      mode,
      requestedAt: startedAt,
      replayEngine: this.engineInfo,
      // Legacy-compatible top-level fields (same semantics as analysis API).
      inputDigest: null,
      calibrationVersions: null,
      ruleVersion: null,
      evidence: {},
      state: {},
      diff: null,
      notes: [],
    };

    const record = await this.store.readRecord(recordId);

    // ------------------------------------------------ record existence --
    if (!record.exists || !record.meta) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RECORD_CORRUPT',
        state: { recordStatus: null, problems: record.problems.map((p) => p.code) },
        evidence: { chainVerified: false },
      };
    }

    base.evidence.recordedAt = record.meta.createdAt;
    base.evidence.recordSessionId = record.meta.sessionId;
    base.evidence.replaySessionId = this.store.sessionId;
    base.evidence.processRestarted = record.meta.sessionId !== this.store.sessionId;
    base.evidence.chainVerified =
      record.events.brokenAt === -1 && !record.events.torn;
    base.evidence.recoveryEvents = record.events.valid
      .filter((e) => e.payload.type === 'RECOVERED_AFTER_RESTART')
      .map((e) => e.payload);
    base.evidence.debris = record.debris;

    // ------------------------------------------------- integrity gate --
    if (record.problems.length > 0) {
      // Pick the most specific code deterministically (tamper first).
      const order = [
        RECORD_PROBLEM.RESULT_DIGEST_MISMATCH,
        RECORD_PROBLEM.INPUT_BLOB_MISSING,
        RECORD_PROBLEM.EVENT_TORN,
        RECORD_PROBLEM.PARTIAL_WRITE_DEBRIS,
      ];
      const codes = record.problems.map((p) => p.code);
      const chosen = order.find((c) => codes.includes(c)) ?? codes[0];
      return {
        ...base,
        status: problemStatus(chosen),
        state: {
          recordStatus: record.status,
          problems: codes,
        },
      };
    }

    // ------------------------------------------------- lifecycle gate --
    if (record.status === RECORD_STATUS.INTERRUPTED) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RECORD_INTERRUPTED',
        state: {
          recordStatus: record.status,
          terminal: false,
          lastEventType: lastEventType(record),
          recoveredAfterRestart: base.evidence.recoveryEvents.length > 0,
        },
      };
    }
    if (record.status === RECORD_STATUS.FAILED) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RECORD_INTERRUPTED',
        state: {
          recordStatus: 'FAILED',
          terminal: true,
          failure: record.error?.error ?? null,
          note: 'Original analysis failed; there is no success result to reproduce.',
        },
      };
    }
    if (record.status !== RECORD_STATUS.COMPLETED) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RECORD_INTERRUPTED',
        state: { recordStatus: record.status, terminal: false },
      };
    }

    const meta = record.meta;
    const request = record.request;
    const recordedResult = record.result.result;
    base.inputDigest = sha256Canonical(request.input);
    base.calibrationVersions = Object.fromEntries(
      meta.calibrations.map((c) => [c.name, c.version]),
    );
    base.ruleVersion = meta.rule.version;
    base.evidence.inputRef = meta.input;
    base.evidence.ruleRef = meta.rule;
    base.evidence.calibrationRefs = meta.calibrations;
    base.evidence.recordedResultDigest = record.result.digest;
    base.evidence.currentStoreSession = this.store.sessionId;

    // ---------------------------------------------- CURRENT_REFERENCE --
    if (mode === REPLAY_MODE.CURRENT_REFERENCE) {
      return this._currentReference(base, request, recordedResult, { tolerance });
    }

    // ================================================= FAITHFUL PATH ==

    // ---- engine identity ----
    const engineCheck = checkEngine(meta.engine, this.engineInfo, allowEngineVersionMismatch);
    base.evidence.engineCheck = engineCheck;
    if (engineCheck.blocked) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_ENGINE_MISMATCH',
        state: { recordStatus: record.status },
      };
    }

    // ---- frozen calibrations (never the live registry) ----
    const calibrationChecks = [];
    const resolvedPayloads = {};
    for (const ref of meta.calibrations) {
      const check = { name: ref.name, calibrationId: ref.calibrationId,
        version: ref.version, sha256: ref.content.sha256 };
      const frozen = await this.store.readFrozenCalibration(ref.content.sha256);
      check.frozenStatus = frozen.status;
      if (frozen.status !== 'OK') {
        calibrationChecks.push(check);
        continue;
      }
      // registry comparison is informational only; replay uses the frozen blob
      const live = this.calibrationRegistry.get(ref.calibrationId, ref.version);
      if (!live) check.registryStatus = 'NOT_REGISTERED';
      else if (live.content.sha256 !== ref.content.sha256) {
        check.registryStatus = 'DRIFTED';
      } else check.registryStatus = 'MATCH';
      resolvedPayloads[ref.name] = {
        calibrationId: frozen.blob.calibrationId,
        version: frozen.blob.version,
        payload: frozen.blob.payload,
      };
      calibrationChecks.push(check);
    }
    base.evidence.calibrationChecks = calibrationChecks;
    const firstBadCal = calibrationChecks.find((c) => c.frozenStatus !== 'OK');
    if (firstBadCal) {
      const status = firstBadCal.frozenStatus === 'MISSING'
        ? 'REPLAY_BLOCKED_CALIBRATION_MISSING'
        : 'REPLAY_BLOCKED_CALIBRATION_SNAPSHOT_CORRUPT';
      return {
        ...base,
        status,
        state: { recordStatus: record.status, failingRef: firstBadCal },
      };
    }
    const drifted = calibrationChecks.find((c) => c.registryStatus === 'DRIFTED');
    if (drifted) {
      // Faithful replay can proceed on the frozen copy, but the binding drift
      // is surfaced prominently; it never silently replaces anything.
      base.notes.push(
        `Calibration binding ${drifted.calibrationId}@${drifted.version} DRIFTED ` +
        `in the registry since recording; replay used the immutable frozen copy.`,
      );
    }

    // ---- frozen rule spec + implementation ----
    const ruleRef = meta.rule;
    const specBlob = await this.store.readFrozenRuleSpec(ruleRef.specSha256);
    const ruleCheck = {
      ruleSetId: ruleRef.ruleSetId,
      version: ruleRef.version,
      specSha256: ruleRef.specSha256,
      implDigest: ruleRef.implDigest,
      frozenSpecStatus: specBlob.status,
    };
    if (specBlob.status !== 'OK') {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE',
        state: { recordStatus: record.status, ruleCheck },
      };
    }
    const liveRule = this.ruleRegistry.get(ruleRef.ruleSetId, ruleRef.version);
    if (!liveRule) {
      ruleCheck.registryStatus = 'NOT_REGISTERED';
    } else if (liveRule.specSha256 !== ruleRef.specSha256) {
      ruleCheck.registryStatus = 'SPEC_DRIFTED';
    } else {
      ruleCheck.registryStatus = 'MATCH';
      ruleCheck.liveImplMatches = liveRule.implDigest === ruleRef.implDigest;
    }

    // Upgrade availability is evidence, never an automatic substitution.
    const currentVersion = this.ruleRegistry.currentVersion(ruleRef.ruleSetId);
    ruleCheck.currentVersion = currentVersion ?? null;
    ruleCheck.upgradeAvailable = !!currentVersion && currentVersion !== ruleRef.version;

    if (ruleCheck.registryStatus === 'SPEC_DRIFTED') {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_RULE_SPEC_DRIFT',
        state: { recordStatus: record.status, ruleCheck },
      };
    }

    // Choose implementation: frozen source if the live one differs or is gone.
    let execution;
    let usedFrozenImplementation = false;
    if (liveRule && liveRule.implDigest === ruleRef.implDigest) {
      execution = () => executeRule({
        ruleEntry: liveRule, request, calibrations: resolvedPayloads,
        std: this.numericRuntime?.std,
      });
      ruleCheck.implementationUsed = 'LIVE_MATCHING';
    } else {
      const source = await this.store.readFrozenRuleSource(ruleRef.implDigest);
      if (source === null) {
        return {
          ...base,
          status: 'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE',
          state: {
            recordStatus: record.status,
            ruleCheck: { ...ruleCheck, frozenImplStatus: 'MISSING' },
          },
        };
      }
      if (sha256OfSource(source) !== ruleRef.implDigest) {
        return {
          ...base,
          status: 'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE',
          state: {
            recordStatus: record.status,
            ruleCheck: { ...ruleCheck, frozenImplStatus: 'CORRUPT' },
          },
        };
      }
      usedFrozenImplementation = true;
      execution = () => executeFrozenRule({
        implSource: source,
        ruleMeta: {
          ruleSetId: ruleRef.ruleSetId,
          version: ruleRef.version,
          specSha256: ruleRef.specSha256,
          implDigest: ruleRef.implDigest,
        },
        request,
        calibrations: resolvedPayloads,
        std: this.numericRuntime?.std,
      });
      ruleCheck.implementationUsed = 'FROZEN_RECOMPILED';
    }
    base.evidence.ruleCheck = ruleCheck;

    // ---- run ----
    let replayResult;
    try {
      replayResult = execution();
    } catch (err) {
      return {
        ...base,
        status: 'REPLAY_BLOCKED_EXECUTION_ERROR',
        state: {
          recordStatus: record.status,
          executionError: { code: err.code ?? 'REPLAY_RUNTIME_ERROR', message: err.message },
        },
      };
    }
    const replayDigest = {
      sha256: sha256Canonical(replayResult),
    };

    // ---- classify ----
    const diff = diffResults(recordedResult, replayResult, tolerance ?? {});
    let status;
    if (diff.status === 'EXACT') status = 'REPRODUCIBLE';
    else if (diff.status === 'WITHIN_TOLERANCE') status = 'REPRODUCIBLE_WITH_TOLERANCE';
    else status = 'DIVERGED';

    const report = {
      ...base,
      status,
      state: {
        recordStatus: record.status,
        usedFrozenImplementation,
        calibrationRegistryDrift: calibrationChecks
          .filter((c) => c.registryStatus === 'DRIFTED')
          .map((c) => `${c.calibrationId}@${c.version}`),
        upgradeAvailable: ruleCheck.upgradeAvailable,
      },
      replayResult,
      replayedResultDigest: replayDigest,
      diff,
    };

    if (compareWithCurrent) {
      report.currentReference = await this._currentReferenceComparison(
        request, recordedResult, { tolerance },
      );
    }
    return report;
  }

  // ------------------------------------------------- current-reference --

  async _currentReference(base, request, recordedResult, { tolerance }) {
    const comparison = await this._currentReferenceComparison(
      request, recordedResult, { tolerance },
    );
    return {
      ...base,
      status: comparison.matchesRecorded
        ? 'CURRENT_REFERENCE_MATCH'
        : 'CURRENT_REFERENCE_MISMATCH',
      state: {
        note: 'Explicit what-if run with CURRENT default calibration/rule. ' +
          'This is not a faithful replay verdict.',
      },
      replayResult: comparison.result,
      replayedResultDigest: comparison.digest,
      diff: comparison.diff,
      currentReference: comparison,
    };
  }

  async _currentReferenceComparison(request, recordedResult, { tolerance } = {}) {
    const ruleEntry = this.ruleRegistry.getCurrent(request.rule?.ruleSetId ?? 'acoustic-noise');
    const calibrations = {};
    const resolved = {};
    for (const name of Object.keys(request.calibrations ?? { primary: {} })) {
      const ref = request.calibrations?.[name] ?? {};
      const entry = this.calibrationRegistry.getCurrent(ref.calibrationId ?? 'mic-array-A');
      if (!entry) {
        return {
          possible: false,
          reason: 'CALIBRATION_MISSING',
          missing: ref.calibrationId ?? 'mic-array-A',
        };
      }
      calibrations[name] = entry.version;
      resolved[name] = { calibrationId: entry.calibrationId, version: entry.version, payload: entry.payload };
    }
    if (!ruleEntry) {
      return { possible: false, reason: 'RULE_VERSION_UNAVAILABLE' };
    }
    const result = executeRule({
      ruleEntry, request, calibrations: resolved,
      std: this.numericRuntime?.std,
    });
    const digest = { sha256: sha256Canonical(result) };
    const diff = diffResults(recordedResult, result, tolerance ?? {});
    return {
      possible: true,
      ruleVersion: ruleEntry.version,
      ruleSpecSha256: ruleEntry.specSha256,
      ruleImplDigest: ruleEntry.implDigest,
      calibrationVersions: calibrations,
      result,
      digest,
      diff,
      matchesRecorded: diff.status === 'EXACT',
    };
  }
}

// ---------------------------------------------------------------- helpers --

function lastEventType(record) {
  const ev = record.events.valid[record.events.valid.length - 1];
  return ev ? ev.payload.type : null;
}

function sha256OfSource(source) {
  return createHash('sha256').update(source).digest('hex');
}

/**
 * Compare recorded engine vs replay engine.  Family mismatch is always
 * blocking (different numeric semantics); version mismatch blocks unless the
 * caller explicitly accepts it; stdlib digest mismatch downgrades an exact
 * verdict to tolerance-aware via a warning (the diff itself decides).
 */
function checkEngine(recorded, current, allowVersionMismatch) {
  const check = {
    recorded,
    current: {
      name: current.name,
      version: current.version,
      engineFamily: current.engineFamily,
      node: current.node,
      platform: current.platform,
      arch: current.arch,
      stdlibDigest: current.stdlibDigest,
    },
    warnings: [],
    blocked: false,
    reason: null,
  };
  if (!recorded) {
    check.warnings.push('Record carries no engine descriptor.');
    return check;
  }
  if (recorded.engineFamily && current.engineFamily &&
      recorded.engineFamily !== current.engineFamily) {
    check.blocked = true;
    check.reason = 'ENGINE_FAMILY_MISMATCH';
    return check;
  }
  if (!recorded.engineFamily && recorded.name !== current.name) {
    check.blocked = true;
    check.reason = 'ENGINE_FAMILY_MISMATCH';
    return check;
  }
  if (recorded.version && recorded.version !== current.version) {
    if (allowVersionMismatch) {
      check.warnings.push(`Engine version ${recorded.version} -> ${current.version} allowed by caller.`);
    } else {
      check.blocked = true;
      check.reason = 'ENGINE_VERSION_MISMATCH';
      return check;
    }
  }
  if (recorded.stdlibDigest && current.stdlibDigest &&
      recorded.stdlibDigest !== current.stdlibDigest) {
    check.warnings.push('RULE_STDLIB digest differs; treating result under tolerance policy.');
  }
  return check;
}
