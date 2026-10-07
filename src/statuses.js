/**
 * Canonical outcome codes for audit records and replay reports.
 *
 * Every failure mode that a caller must be able to distinguish has its own
 * stable string code.  Codes never double up: e.g. "calibration cannot be
 * found" (CALIBRATION_MISSING) is different from "the calibration found under
 * that id changed" (CALIBRATION_DRIFT).
 *
 * @typedef {'REPRODUCIBLE'
 *   | 'REPRODUCIBLE_WITH_TOLERANCE'
 *   | 'DIVERGED'
 *   | 'CURRENT_REFERENCE_MISMATCH'
 *   | 'CURRENT_REFERENCE_MATCH'
 *   | 'REPLAY_BLOCKED_RECORD_INTERRUPTED'
 *   | 'REPLAY_BLOCKED_RECORD_PARTIAL'
 *   | 'REPLAY_BLOCKED_RECORD_CORRUPT'
 *   | 'REPLAY_BLOCKED_RECORD_TAMPERED'
 *   | 'REPLAY_BLOCKED_INPUT_MISSING'
 *   | 'REPLAY_BLOCKED_CALIBRATION_MISSING'
 *   | 'REPLAY_BLOCKED_CALIBRATION_DRIFT'
 *   | 'REPLAY_BLOCKED_CALIBRATION_SNAPSHOT_CORRUPT'
 *   | 'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE'
 *   | 'REPLAY_BLOCKED_RULE_SPEC_DRIFT'
 *   | 'REPLAY_BLOCKED_ENGINE_MISMATCH'
 *   | 'REPLAY_BLOCKED_EXECUTION_ERROR'
 * } ReplayStatus
 */

/** Replay statuses grouped by the coarse verdict. */
export const VERDICTS = Object.freeze({
  REPRODUCIBLE: 'REPRODUCIBLE',
  REPRODUCIBLE_WITH_TOLERANCE: 'REPRODUCIBLE_WITH_TOLERANCE',
  DIVERGED: 'DIVERGED',
  BLOCKED: 'BLOCKED',
  INFORMATIONAL: 'INFORMATIONAL',
});

/**
 * Map a fine-grained replay status to its coarse verdict.  Callers that only
 * need "did it reproduce?" can use this; callers that need the precise reason
 * use the raw status.
 * @param {string} status
 * @returns {string}
 */
export function verdictOf(status) {
  switch (status) {
    case 'REPRODUCIBLE':
      return VERDICTS.REPRODUCIBLE;
    case 'REPRODUCIBLE_WITH_TOLERANCE':
      return VERDICTS.REPRODUCIBLE_WITH_TOLERANCE;
    case 'DIVERGED':
      return VERDICTS.DIVERGED;
    case 'CURRENT_REFERENCE_MISMATCH':
    case 'CURRENT_REFERENCE_MATCH':
      return VERDICTS.INFORMATIONAL;
    default:
      return VERDICTS.BLOCKED;
  }
}

/** Lifecycle status of an audit record (derived from its event chain). */
export const RECORD_STATUS = Object.freeze({
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  INTERRUPTED: 'INTERRUPTED', // recovered after a process restart mid-flight
});

/**
 * Structural integrity problems detected while reading a record.
 * Each maps to a distinguishable blocked-replay status.
 */
export const RECORD_PROBLEM = Object.freeze({
  META_MISSING: 'META_MISSING',
  META_CORRUPT: 'META_CORRUPT',
  EVENT_LOG_MISSING: 'EVENT_LOG_MISSING',
  EVENT_CHAIN_BROKEN: 'EVENT_CHAIN_BROKEN',
  EVENT_TORN: 'EVENT_TORN',
  EVENT_UNEXPECTED: 'EVENT_UNEXPECTED',
  RESULT_DIGEST_MISMATCH: 'RESULT_DIGEST_MISMATCH',
  RESULT_SUMMARY_CORRUPT: 'RESULT_SUMMARY_CORRUPT',
  INPUT_BLOB_MISSING: 'INPUT_BLOB_MISSING',
  INPUT_BLOB_CORRUPT: 'INPUT_BLOB_CORRUPT',
  META_REF_MISMATCH: 'META_REF_MISMATCH',
  PARTIAL_WRITE_DEBRIS: 'PARTIAL_WRITE_DEBRIS',
});

/** Replay execution modes. */
export const REPLAY_MODE = Object.freeze({
  /**
   * Faithful replay: use EXACTLY the calibration version pinned by the record
   * and EXACTLY the rule version pinned by the record.  The "current"
   * calibration/algorithm are never consulted.  This is the default.
   */
  FAITHFUL: 'FAITHFUL',
  /**
   * Explicit what-if mode: re-run the recorded INPUT with whatever the
   * registries currently consider current.  Never overwrites the faithful
   * verdict; the result is reported separately as an informational reference.
   */
  CURRENT_REFERENCE: 'CURRENT_REFERENCE',
});

/** Event types appended to a record's hash-chained journal. */
export const EVENT_TYPE = Object.freeze({
  RECORD_CREATED: 'RECORD_CREATED',
  JOB_ENQUEUED: 'JOB_ENQUEUED',
  JOB_STARTED: 'JOB_STARTED',
  RESULT_PERSISTED: 'RESULT_PERSISTED',
  ANALYSIS_FAILED: 'ANALYSIS_FAILED',
  RECOVERED_AFTER_RESTART: 'RECOVERED_AFTER_RESTART',
});
