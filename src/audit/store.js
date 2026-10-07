import {
  mkdir,
  readdir,
  readFile,
  appendFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import {
  canonicalJSON,
  sha256Raw,
  sha256Canonical,
  contentRef,
  uuid,
  atomicWrite,
  fsyncDir,
} from '../util/hash.js';
import { LockManager } from '../util/locks.js';
import { EVENT_TYPE, RECORD_STATUS, RECORD_PROBLEM } from '../statuses.js';

/**
 * Append-only audit store.
 *
 * On-disk layout:
 *
 *   <root>/
 *     session.log                     append-only process session markers
 *     index.json                      recordId -> { kind, jobId?, createdAt }
 *     calibrations/<sha>.json         frozen calibration blobs (content-addressed)
 *     rules/<specSha>.json            frozen rule spec blobs
 *     rules/impl-<implDigest>.js      frozen rule implementation sources
 *     locks/<hash>/                   cross-process writer locks
 *     records/<recordId>/
 *       meta.json                     immutable manifest (atomic write)
 *       events.log                    hash-chained JSONL (appended under lock)
 *       input.json                    COMPLETE input snapshot (atomic write)
 *       result.json                   result summary + digest (atomic write)
 *       error.json                    failure detail (atomic write)
 *     replays/<replayId>.json         replay reports (independent of records)
 *
 * Event chaining: every event carries prevSha (sha of previous canonical
 * event line) and its own sha = sha256(prevSha + canonicalJSON(payload)).
 * Verifying the chain detects reordering, truncation and tampering.
 */

const META_VERSION = 1;

/**
 * @typedef {Object} StoreOptions
 * @property {string} root directory (created on demand)
 * @property {() => string} [now]
 * @property {{name:string,version:string}} [engine]
 * @property {string} [engineVersion]
 * @property {string} [stdlibDigest]
 * @property {number} [lockTtlMs]
 */

export class AuditStore {
  /** @param {StoreOptions} options */
  constructor(options) {
    if (!options?.root) throw new Error('AuditStore requires { root }');
    this.root = options.root;
    this.now = options.now ?? (() => new Date().toISOString());
    this.engine = options.engine ?? { name: 'noise-analysis-service', version: '1.0.0' };
    this.stdlibDigestValue = options.stdlibDigest ?? null;
    this.locks = new LockManager(join(this.root, 'locks'), {
      staleTtlMs: options.lockTtlMs ?? 30_000,
    });
    this.recordsDir = join(this.root, 'records');
    this.calDir = join(this.root, 'calibrations');
    this.ruleDir = join(this.root, 'rules');
    this.replaysDir = join(this.root, 'replays');
    this.indexPath = join(this.root, 'index.json');
    this.sessionLog = join(this.root, 'session.log');
    this.sessionId = uuid();
    this._index = null;
    /** @type {Map<string,string[]>} recordId -> session ids that recovered it */
    this.recoveryEventsByRecord = new Map();
    this.debris = [];
    this.recoveryReport = { recovered: [], debris: [], startedAt: null };
  }

  /**
   * Open the store: create directories, register this process session, and
   * recover records left non-terminal by a previous process.
   * @param {{recover?:boolean}} [opts]
   */
  async open({ recover = true } = {}) {
    await mkdir(this.recordsDir, { recursive: true });
    await mkdir(this.calDir, { recursive: true });
    await mkdir(this.ruleDir, { recursive: true });
    await mkdir(this.replaysDir, { recursive: true });
    await mkdir(join(this.root, 'locks'), { recursive: true });
    this.recoveryReport.startedAt = this.now();
    await appendFile(
      this.sessionLog,
      JSON.stringify({ type: 'SESSION_START', sessionId: this.sessionId, at: this.now() }) + '\n',
    ).catch(() => {});
    await this._loadIndex();
    if (recover) await this.recover();
    return this;
  }

  // ---------------------------------------------------------------- index --

  async _loadIndex() {
    try {
      this._index = JSON.parse(await readFile(this.indexPath, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this._index = { records: {} };
    }
    if (!this._index.records) this._index.records = {};
  }

  async _indexRecord(recordId, entry) {
    this._index.records[recordId] = entry;
    await atomicWrite(this.indexPath, canonicalJSON(this._index));
  }

  async listRecordIds() {
    let names;
    try {
      names = await readdir(this.recordsDir);
    } catch {
      return [];
    }
    return names.filter((n) => !n.includes('.'));
  }

  getIndexEntry(recordId) {
    return this._index?.records?.[recordId];
  }

  // ------------------------------------------------------------- freezing --

  /**
   * Freeze a calibration payload into the content-addressed area.
   * Idempotent: identical content shares one blob.
   * @returns {Promise<{calibrationId:string,version:string,content:object}>}
   */
  async freezeCalibration(calibrationId, version, payload) {
    const content = contentRef(payload);
    const p = join(this.calDir, `${content.sha256}.json`);
    await atomicWrite(p, canonicalJSON({ calibrationId, version, payload, content }));
    return { calibrationId, version, content };
  }

  /** Read back a frozen calibration, verifying its content hash. */
  async readFrozenCalibration(sha) {
    const p = join(this.calDir, `${sha}.json`);
    let raw;
    try {
      raw = await readFile(p, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { status: 'MISSING' };
      throw err;
    }
    let blob;
    try {
      blob = JSON.parse(raw);
    } catch {
      return { status: 'CORRUPT' };
    }
    if (sha256Canonical(blob.payload) !== sha || blob.content?.sha256 !== sha) {
      return { status: 'CORRUPT' };
    }
    return { status: 'OK', blob };
  }

  /** Freeze a rule spec and its implementation source. */
  async freezeRule(ruleEntry) {
    await atomicWrite(
      join(this.ruleDir, `${ruleEntry.specSha256}.json`),
      canonicalJSON({
        ruleSetId: ruleEntry.ruleSetId,
        version: ruleEntry.version,
        spec: ruleEntry.spec,
        specSha256: ruleEntry.specSha256,
      }),
    );
    await atomicWrite(
      join(this.ruleDir, `impl-${ruleEntry.implDigest}.js`),
      ruleEntry.implSource,
    );
    return {
      ruleSetId: ruleEntry.ruleSetId,
      version: ruleEntry.version,
      specSha256: ruleEntry.specSha256,
      implDigest: ruleEntry.implDigest,
    };
  }

  async readFrozenRuleSpec(specSha) {
    let raw;
    try {
      raw = await readFile(join(this.ruleDir, `${specSha}.json`), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { status: 'MISSING' };
      throw err;
    }
    let blob;
    try {
      blob = JSON.parse(raw);
    } catch {
      return { status: 'CORRUPT' };
    }
    if (sha256Canonical(blob.spec) !== specSha) return { status: 'CORRUPT' };
    return { status: 'OK', blob };
  }

  async readFrozenRuleSource(implDigest) {
    try {
      return await readFile(join(this.ruleDir, `impl-${implDigest}.js`), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  // ------------------------------------------------------------- creation --

  /**
   * Create an immutable audit record for one analysis invocation.
   * Writes input.json + meta.json atomically, then appends RECORD_CREATED
   * (plus JOB_ENQUEUED for async) as the first chained event.
   *
   * @param {object} p
   * @param {'PREVIEW'|'ASYNC_ANALYSIS'} p.kind
   * @param {object} p.request            complete analysis request
   * @param {object} p.inputRef           {sha256, bytes, encoding} of input snapshot
   * @param {object[]} p.calibrationRefs  frozen calibration refs
   * @param {object} p.ruleRef            frozen rule ref
   * @param {string} [p.jobId]
   * @param {object} [p.engineInfo]
   */
  async createRecord({ kind, request, inputRef, calibrationRefs, ruleRef, jobId = null, engineInfo }) {
    const recordId = uuid();
    const dir = join(this.recordsDir, recordId);
    await mkdir(dir, { recursive: true });

    // 1. Complete input snapshot first; its ref is embedded in meta/events.
    await atomicWrite(join(dir, 'input.json'), canonicalJSON(request));

    const meta = {
      formatVersion: META_VERSION,
      recordId,
      kind,
      jobId,
      createdAt: this.now(),
      sessionId: this.sessionId,
      input: inputRef,
      calibrations: calibrationRefs,
      rule: ruleRef,
      engine: engineInfo ?? {
        name: this.engine.name,
        version: this.engine.version,
        stdlibDigest: this.stdlibDigestValue,
      },
    };
    await atomicWrite(join(dir, 'meta.json'), canonicalJSON(meta));

    // 2. Hash-chained event journal starts here.
    const createdPayload = {
      type: EVENT_TYPE.RECORD_CREATED,
      at: this.now(),
      kind,
      inputRef,
      calibrationRefs,
      ruleRef,
    };
    await this._appendEvent(recordId, createdPayload, null);
    if (kind === 'ASYNC_ANALYSIS') {
      await this._appendEvent(recordId, {
        type: EVENT_TYPE.JOB_ENQUEUED,
        at: this.now(),
        jobId: jobId ?? recordId,
      }, null);
    }

    await this._indexRecord(recordId, {
      kind,
      jobId,
      createdAt: meta.createdAt,
    });
    await fsyncDir(this.recordsDir);
    return recordId;
  }

  /**
   * Append an event under the per-record writer lock, extending the hash
   * chain.  Lock + line-per-event + chain hash make concurrent appends safe
   * and tampering visible.
   */
  async appendEvent(recordId, payload) {
    return this.locks.withLock(`record:${recordId}:events`, async () =>
      this._appendEventLocked(recordId, payload, null));
  }

  async markRunning(recordId) {
    await this.appendEvent(recordId, {
      type: EVENT_TYPE.JOB_STARTED,
      at: this.now(),
      sessionId: this.sessionId,
    });
  }

  // -------------------------------------------------------------- journal --

  /**
   * @param {string} recordId
   * @param {object} payload must include `type`
   * @param {string|null} prevSha
   */
  async _appendEvent(recordId, payload, prevSha) {
    return this.locks.withLock(`record:${recordId}:events`,
      () => this._appendEventLocked(recordId, payload, prevSha));
  }

  async _appendEventLocked(recordId, payload, _prevSha = null) {
    // Sequence and prev-hash always come from the on-disk tail, which the
    // caller's per-record lock protects from concurrent appends.
    const info = await this._tailInfo(recordId);
    const event = {
      seq: info.nextSeq,
      payload,
      at: payload.at ?? this.now(),
      prevSha: info.sha,
    };
    event.sha = sha256Raw(
      `${event.seq}\n${event.prevSha ?? ''}\n${canonicalJSON(payload)}`,
    );
    const line = canonicalJSON(event) + '\n';
    await appendFile(join(this.recordsDir, recordId, 'events.log'), line);
    return event;
  }

  /** @returns {Promise<{sha: string|null, nextSeq: number}>} */
  async _tailInfo(recordId) {
    let raw;
    try {
      raw = await readFile(join(this.recordsDir, recordId, 'events.log'), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { sha: null, nextSeq: 0 };
      throw err;
    }
    const lines = raw.split('\n');
    let sha = null;
    let nextSeq = 0;
    for (const line of lines) {
      if (!line.trim()) continue;
      const ev = JSON.parse(line);
      sha = ev.sha;
      nextSeq = ev.seq + 1;
    }
    return { sha, nextSeq };
  }

  async _tailShaUnchecked(recordId) {
    return (await this._tailInfo(recordId)).sha;
  }

  // --------------------------------------------------------------- reads --

  /**
   * Read and fully verify a record.  NEVER throws for record-integrity
   * problems — they are returned as `problems` with distinct codes so replay
   * can classify them deterministically.
   *
   * @returns {Promise<object>}
   */
  async readRecord(recordId) {
    const dir = join(this.recordsDir, recordId);
    const problems = [];
    const debris = [];

    let meta = null;
    try {
      meta = JSON.parse(await readFile(join(dir, 'meta.json'), 'utf8'));
    } catch (err) {
      problems.push({
        code: err.code === 'ENOENT' ? RECORD_PROBLEM.META_MISSING : RECORD_PROBLEM.META_CORRUPT,
      });
    }

    // Partial-write debris: temp files left by a crashed atomic write.
    try {
      for (const name of await readdir(dir)) {
        if (name.includes('.tmp.')) {
          debris.push(name);
          problems.push({ code: RECORD_PROBLEM.PARTIAL_WRITE_DEBRIS, detail: name });
        }
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        return {
          recordId, exists: false, meta: null, problems: [
            { code: RECORD_PROBLEM.META_MISSING },
          ],
          events: { valid: [], validThrough: -1, torn: false },
          result: null, request: null, status: RECORD_STATUS.INTERRUPTED, debris: [],
        };
      }
      throw err;
    }

    // ---- event log verification ----
    const eventResult = await this._readEvents(recordId);
    if (eventResult.missing) {
      problems.push({ code: RECORD_PROBLEM.EVENT_LOG_MISSING });
    }
    if (eventResult.torn) {
      problems.push({ code: RECORD_PROBLEM.EVENT_TORN, detail: eventResult.tornDetail });
    }
    if (eventResult.brokenAt !== -1) {
      problems.push({
        code: RECORD_PROBLEM.EVENT_CHAIN_BROKEN,
        detail: `event seq ${eventResult.brokenAt}`,
      });
    }

    // ---- meta/event cross-check: manifest refs must match the first event
    // ever chained, so a swapped meta.json cannot repoint a record ----
    if (meta) {
      const created = eventResult.valid.find(
        (e) => e.payload.type === EVENT_TYPE.RECORD_CREATED,
      );
      if (created) {
        const p = created.payload;
        const refOk =
          p.inputRef?.sha256 === meta.input?.sha256 &&
          canonicalJSON(p.ruleRef) === canonicalJSON(meta.rule) &&
          canonicalJSON(p.calibrationRefs) === canonicalJSON(meta.calibrations) &&
          p.kind === meta.kind;
        if (!refOk) problems.push({ code: RECORD_PROBLEM.META_REF_MISMATCH });
      }
    }

    // ---- input snapshot ----
    let request = null;
    try {
      request = JSON.parse(await readFile(join(dir, 'input.json'), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') {
        problems.push({ code: RECORD_PROBLEM.INPUT_BLOB_MISSING });
      } else {
        problems.push({ code: RECORD_PROBLEM.INPUT_BLOB_CORRUPT });
      }
    }
    if (request && meta?.input?.sha256 && sha256Canonical(request) !== meta.input.sha256) {
      problems.push({ code: RECORD_PROBLEM.INPUT_BLOB_CORRUPT, detail: 'input digest mismatch' });
      request = null;
    }

    // ---- result summary ----
    let resultEnvelope = null;
    try {
      resultEnvelope = JSON.parse(await readFile(join(dir, 'result.json'), 'utf8'));
      if (sha256Canonical(resultEnvelope.result) !== resultEnvelope.digest?.sha256) {
        problems.push({ code: RECORD_PROBLEM.RESULT_DIGEST_MISMATCH });
        resultEnvelope = { ...resultEnvelope, digestVerified: false };
      } else {
        resultEnvelope.digestVerified = true;
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        problems.push({ code: RECORD_PROBLEM.RESULT_SUMMARY_CORRUPT });
      }
    }

    // Cross-check RESULT_PERSISTED event digest vs the result envelope.
    const persistedEvent = eventResult.valid.find(
      (e) => e.payload.type === EVENT_TYPE.RESULT_PERSISTED,
    );
    if (persistedEvent && resultEnvelope?.digest &&
        persistedEvent.payload.resultDigest?.sha256 !== resultEnvelope.digest.sha256) {
      problems.push({
        code: RECORD_PROBLEM.RESULT_DIGEST_MISMATCH,
        detail: 'result.json digest does not match RESULT_PERSISTED event',
      });
    }

    let errorEnvelope = null;
    try {
      errorEnvelope = JSON.parse(await readFile(join(dir, 'error.json'), 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') errorEnvelope = { unreadable: true };
    }

    const status = this._deriveStatus(eventResult.valid, errorEnvelope);
    return {
      recordId,
      exists: true,
      meta,
      events: {
        all: eventResult.all,
        valid: eventResult.valid,
        validThrough: eventResult.valid.length - 1,
        brokenAt: eventResult.brokenAt,
        torn: eventResult.torn,
        tornDetail: eventResult.tornDetail,
      },
      request,
      result: resultEnvelope,
      error: errorEnvelope,
      status,
      problems,
      debris,
      recoveredSessions: this.recoveryEventsByRecord.get(recordId) ?? [],
    };
  }

  async _readEvents(recordId) {
    let raw;
    try {
      raw = await readFile(join(this.recordsDir, recordId, 'events.log'), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return { all: [], valid: [], missing: true, brokenAt: -1, torn: false };
      throw err;
    }
    const all = [];
    const valid = [];
    let brokenAt = -1;
    let torn = false;
    let tornDetail = null;
    let prevSha = null;
    const lines = raw.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      let ev;
      try {
        ev = JSON.parse(line);
      } catch {
        torn = true;
        tornDetail = `unparseable line ${i + 1}`;
        continue;
      }
      const expectedSha = sha256Raw(
        `${ev.seq}\n${ev.prevSha ?? ''}\n${canonicalJSON(ev.payload)}`,
      );
      if (ev.seq !== valid.length || ev.prevSha !== prevSha || ev.sha !== expectedSha) {
        if (brokenAt === -1) brokenAt = ev.seq ?? i;
        continue;
      }
      all.push(ev);
      valid.push(ev);
      prevSha = ev.sha;
    }
    return { all, valid, missing: false, brokenAt, torn, tornDetail };
  }

  _deriveStatus(validEvents, errorEnvelope) {
    const types = new Set(validEvents.map((e) => e.payload.type));
    if (types.has(EVENT_TYPE.RESULT_PERSISTED)) return RECORD_STATUS.COMPLETED;
    if (types.has(EVENT_TYPE.ANALYSIS_FAILED)) return RECORD_STATUS.FAILED;
    if (types.has(EVENT_TYPE.RECOVERED_AFTER_RESTART)) {
      return RECORD_STATUS.INTERRUPTED;
    }
    if (types.has(EVENT_TYPE.JOB_STARTED)) return RECORD_STATUS.RUNNING;
    if (types.has(EVENT_TYPE.JOB_ENQUEUED)) return RECORD_STATUS.PENDING;
    // RECORD_CREATED only: a preview that died before persisting, or a
    // recovered record whose recovery marker failed to append (unlikely but
    // handled by recovery scan at next open).
    return RECORD_STATUS.RUNNING;
  }

  // ------------------------------------------------------------ recovery --

  /**
   * Scan all records on open.  Non-terminal records created in a DIFFERENT
   * process session are marked INTERRUPTED via RECOVERED_AFTER_RESTART.
   * Also detects leftover .tmp debris at store level.
   */
  async recover() {
    const ids = await this.listRecordIds();
    for (const recordId of ids) {
      const read = await this.readRecord(recordId);
      const meta = read.meta;
      if (!meta) continue;
      const terminal = read.status === RECORD_STATUS.COMPLETED ||
        read.status === RECORD_STATUS.FAILED;
      if (!terminal && meta.sessionId !== this.sessionId) {
        const event = {
          type: EVENT_TYPE.RECOVERED_AFTER_RESTART,
          at: this.now(),
          recoveredBySession: this.sessionId,
          originalSession: meta.sessionId,
          observedStatus: read.status,
          problemsAtRecovery: read.problems.map((p) => p.code),
        };
        try {
          await this.locks.withLock(`record:${recordId}:events`,
            () => this._appendEventLocked(recordId, event,
              read.events.valid[read.events.valid.length - 1]?.sha ?? null));
          const list = this.recoveryEventsByRecord.get(recordId) ?? [];
          list.push(this.sessionId);
          this.recoveryEventsByRecord.set(recordId, list);
          this.recoveryReport.recovered.push({ recordId, observedStatus: read.status });
        } catch (err) {
          this.recoveryReport.recovered.push({
            recordId, observedStatus: read.status, recoveryAppendFailed: String(err),
          });
        }
      }
      for (const d of read.debris) {
        this.recoveryReport.debris.push({ recordId, file: d });
        this.debris.push({ recordId, file: d });
      }
    }
    return this.recoveryReport;
  }

  // ------------------------------------------------------- result/failure -

  /**
   * Persist final result and close the chain with a digest-bearing terminal
   * event.  @see writeResult uses this internally.
   */
  async completeWithResult(recordId, resultSummary) {
    const dir = join(this.recordsDir, recordId);
    const digest = contentRef(resultSummary);
    const envelope = { result: resultSummary, digest, persistedAt: this.now() };
    await atomicWrite(join(dir, 'result.json'), canonicalJSON(envelope));
    await this.appendEvent(recordId, {
      type: EVENT_TYPE.RESULT_PERSISTED,
      at: this.now(),
      resultDigest: digest,
    });
    return digest;
  }

  async completeWithFailure(recordId, failure) {
    const dir = join(this.recordsDir, recordId);
    const envelope = {
      error: { code: failure.code ?? 'ANALYSIS_ERROR', message: failure.message ?? String(failure) },
      at: this.now(),
    };
    await atomicWrite(join(dir, 'error.json'), canonicalJSON(envelope));
    await this.appendEvent(recordId, {
      type: EVENT_TYPE.ANALYSIS_FAILED,
      at: this.now(),
      errorCode: envelope.error.code,
    });
  }

  // -------------------------------------------------------------- replays -

  /** Persist a replay report.  Replay reports are immutable and live OUTSIDE
   * the record directory so replaying never writes near the original. */
  async writeReplayReport(report) {
    const p = join(this.replaysDir, `${report.replayId}.json`);
    await atomicWrite(p, canonicalJSON(report));
    return p;
  }

  async listReplayIds() {
    try {
      return (await readdir(this.replaysDir)).filter((n) => n.endsWith('.json'))
        .map((n) => n.replace(/\.json$/, ''));
    } catch {
      return [];
    }
  }

  async readReplayReport(replayId) {
    return JSON.parse(await readFile(join(this.replaysDir, `${replayId}.json`), 'utf8'));
  }
}
