import { sha256Canonical, contentRef } from '../util/hash.js';
import { currentEngineInfo, executeRule } from './engine.js';
import { RECORD_STATUS } from '../statuses.js';

/**
 * Analysis service — the only public entry point for running analyses.
 *
 * It preserves the historical response contract exactly (inputDigest,
 * calibrationVersions, ruleVersion, result) and adds ONE supplementary field
 * (`audit`) carrying the record id and evidence references.  Nothing about
 * the old fields changes semantics.
 *
 * Request:
 *   { input: {seriesId, samples, baseline?, samplingRateHz?},
 *     params?: object,
 *     calibrations?: Record<name,{calibrationId,version}>, // default: current
 *     rule?: {ruleSetId, version} }                        // default: current
 */

export class ResolutionError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export class AnalysisService {
  /**
   * @param {object} args
   * @param {import('../audit/store.js').AuditStore} args.store
   * @param {import('../registries/calibration.js').CalibrationRegistry} args.calibrations
   * @param {import('../registries/rules.js').NoiseRuleRegistry} args.rules
   * @param {object} [args.engineInfo]
   * @param {(job:Function)=>void} [args.scheduler]
   */
  constructor({ store, calibrations, rules, engineInfo, scheduler, numericRuntime }) {
    this.store = store;
    this.calibrationRegistry = calibrations;
    this.ruleRegistry = rules;
    this.numericRuntime = numericRuntime ?? null;
    this.engineInfo = engineInfo ?? currentEngineInfo(
      numericRuntime ? { stdlibDigest: numericRuntime.digest } : {},
    );
    // Default async scheduler: run after the current turn.  Injected by tests
    // that need to simulate a crash between ENQUEUED and STARTED.
    this._schedule = scheduler ?? setImmediate;
    /** @type {Map<string,{jobId:string,recordId:string,status:string,error?:any,result?:any}>} */
    this.jobs = new Map();
    /** jobId -> recordId index for retrieval of crashed jobs' evidence */
    this._jobIndex = new Map();
  }

  /** Legacy-compatible digest: hash of the INPUT portion only. */
  static inputDigestOf(request) {
    return sha256Canonical(request.input);
  }

  // ---------------------------------------------------------- resolution --

  /**
   * Resolve and FREEZE everything an invocation depends on.  Freezing here is
   * what makes later replay independent of registry churn.
   */
  async _resolveAndFreeze(request) {
    // Rule: explicit pin, else registry default.
    const ruleRefReq = request.rule;
    let ruleEntry;
    if (ruleRefReq?.version) {
      ruleEntry = this.ruleRegistry.get(ruleRefReq.ruleSetId ?? 'acoustic-noise', ruleRefReq.version);
      if (!ruleEntry) {
        throw new ResolutionError(
          'RULE_VERSION_UNAVAILABLE',
          `Rule ${ruleRefReq.ruleSetId ?? 'acoustic-noise'}@${ruleRefReq.version} is not registered`,
        );
      }
    } else {
      const id = ruleRefReq?.ruleSetId ?? 'acoustic-noise';
      ruleEntry = this.ruleRegistry.getCurrent(id);
      if (!ruleEntry) {
        throw new ResolutionError('RULE_VERSION_UNAVAILABLE', `No current rule for ${id}`);
      }
    }
    const frozenRule = await this.store.freezeRule(ruleEntry);

    // Calibrations: explicit pins, else registry current per name.
    const names = Object.keys(request.calibrations ?? { primary: {} });
    const frozenCalibrations = {};
    const calibrationRefs = [];
    const resolvedPayloads = {};
    for (const name of names) {
      const ref = request.calibrations?.[name] ?? {};
      let entry;
      if (ref.version) {
        entry = this.calibrationRegistry.get(ref.calibrationId ?? 'mic-array-A', ref.version);
        if (!entry) {
          throw new ResolutionError(
            'CALIBRATION_MISSING',
            `Calibration ${ref.calibrationId ?? 'mic-array-A'}@${ref.version} is not registered`,
          );
        }
      } else {
        const id = ref.calibrationId ?? 'mic-array-A';
        entry = this.calibrationRegistry.getCurrent(id);
        if (!entry) {
          throw new ResolutionError(
            'CALIBRATION_MISSING',
            `No current calibration for ${id}`,
          );
        }
      }
      frozenCalibrations[name] = await this.store.freezeCalibration(
        entry.calibrationId, entry.version, entry.payload,
      );
      calibrationRefs.push({
        name,
        calibrationId: entry.calibrationId,
        version: entry.version,
        content: frozenCalibrations[name].content,
      });
      resolvedPayloads[name] = {
        calibrationId: entry.calibrationId,
        version: entry.version,
        payload: entry.payload,
      };
    }

    return {
      ruleEntry,
      frozenRule,
      calibrationRefs,
      resolvedPayloads,
      calibrationVersions: Object.fromEntries(
        calibrationRefs.map((c) => [c.name, c.version]),
      ),
    };
  }

  // -------------------------------------------------------------- preview --

  /**
   * Run a synchronous preview.  Same return shape as the legacy preview,
   * plus `audit`.
   */
  async preview(request) {
    const resolved = await this._resolveAndFreeze(request);
    const inputRef = contentRef(request); // full request snapshot ref
    const recordId = await this.store.createRecord({
      kind: 'PREVIEW',
      request,
      inputRef,
      calibrationRefs: resolved.calibrationRefs,
      ruleRef: resolved.frozenRule,
      engineInfo: this.engineInfo,
    });
    try {
      const result = executeRule({
        ruleEntry: resolved.ruleEntry,
        request,
        calibrations: resolved.resolvedPayloads,
        std: this.numericRuntime?.std,
      });
      await this.store.completeWithResult(recordId, result);
      return this._legacyResponse({ request, resolved, result, recordId, kind: 'PREVIEW' });
    } catch (err) {
      await this.store.completeWithFailure(recordId, err).catch(() => {});
      throw err;
    }
  }

  // --------------------------------------------------------- async jobs --

  /**
   * Enqueue an async analysis.  Returns the legacy job shape immediately;
   * the job executes on the injected scheduler.
   */
  async analyzeAsync(request, { jobId } = {}) {
    const resolved = await this._resolveAndFreeze(request);
    const id = jobId ?? `job-${contentRef(request).sha256.slice(0, 12)}-${Date.now().toString(36)}`;
    const inputRef = contentRef(request);
    const recordId = await this.store.createRecord({
      kind: 'ASYNC_ANALYSIS',
      request,
      inputRef,
      calibrationRefs: resolved.calibrationRefs,
      ruleRef: resolved.frozenRule,
      jobId: id,
      engineInfo: this.engineInfo,
    });
    const state = { jobId: id, recordId, status: 'ENQUEUED', kind: 'ASYNC_ANALYSIS' };
    this.jobs.set(id, state);
    this._jobIndex.set(id, recordId);

    this._schedule(() => {
      this._runJob(id, recordId, request, resolved).catch(() => {
        // failure is captured on the job state and the audit record
      });
    });

    return {
      // ---- legacy fields ----
      jobId: id,
      status: 'ENQUEUED',
      inputDigest: AnalysisService.inputDigestOf(request),
      calibrationVersions: resolved.calibrationVersions,
      ruleVersion: resolved.ruleEntry.version,
      // ---- supplementary audit field ----
      audit: {
        recordId,
        kind: 'ASYNC_ANALYSIS',
        rule: {
          ruleSetId: resolved.ruleEntry.ruleSetId,
          version: resolved.ruleEntry.version,
          specSha256: resolved.frozenRule.specSha256,
          implDigest: resolved.frozenRule.implDigest,
        },
        calibrations: resolved.calibrationRefs,
        inputRef,
        engine: this.engineInfo,
      },
    };
  }

  async _runJob(jobId, recordId, request, resolved) {
    const state = this.jobs.get(jobId);
    state.status = 'RUNNING';
    await this.store.markRunning(recordId);
    try {
      const result = executeRule({
        ruleEntry: resolved.ruleEntry,
        request,
        calibrations: resolved.resolvedPayloads,
        std: this.numericRuntime?.std,
      });
      await this.store.completeWithResult(recordId, result);
      state.status = 'SUCCEEDED';
      state.result = result;
    } catch (err) {
      await this.store.completeWithFailure(recordId, err).catch(() => {});
      state.status = 'FAILED';
      state.error = { code: err.code ?? 'ANALYSIS_ERROR', message: err.message };
    }
  }

  /**
   * @param {{waitMs?:number}} [opts] poll until the job leaves ENQUEUED/RUNNING
   */
  async getJob(jobId, { waitMs = 0 } = {}) {
    const deadline = Date.now() + waitMs;
    let state = this.jobs.get(jobId);
    while (state && ['ENQUEUED', 'RUNNING'].includes(state.status) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5));
      state = this.jobs.get(jobId);
    }
    return state ? { ...state } : undefined;
  }

  /** Map a (possibly crashed) job to its audit record. */
  recordIdForJob(jobId) {
    return this._jobIndex.get(jobId);
  }

  /** In-flight counts exposed for concurrency evidence. */
  activeJobCount() {
    return [...this.jobs.values()].filter((j) =>
      j.status === 'ENQUEUED' || j.status === 'RUNNING').length;
  }

  // ------------------------------------------------------------- helpers --

  _legacyResponse({ request, resolved, result, recordId, kind }) {
    return {
      // ---- legacy fields (unchanged semantics) ----
      inputDigest: AnalysisService.inputDigestOf(request),
      calibrationVersions: resolved.calibrationVersions,
      ruleVersion: resolved.ruleEntry.version,
      result: { metrics: result.metrics, flags: result.flags },
      // ---- supplementary audit field (additive only) ----
      audit: {
        recordId,
        kind,
        rule: {
          ruleSetId: resolved.ruleEntry.ruleSetId,
          version: resolved.ruleEntry.version,
          specSha256: resolved.frozenRule.specSha256,
          implDigest: resolved.frozenRule.implDigest,
        },
        calibrations: resolved.calibrationRefs,
        inputRef: contentRef(request),
        engine: this.engineInfo,
      },
    };
  }
}

export { RECORD_STATUS };
