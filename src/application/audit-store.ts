import { existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, writeFileSync, writeSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DomainError } from '../domain/errors.ts';
import { digestOf } from '../domain/audit/canonical.ts';
import { buildCalibrationRefs, legacyInputDigest, storeFailure, storeSuccess, summarizeOutcome } from '../domain/audit/evidence.ts';
import { ALGORITHM_VERSION, currentRuleVersion, getRuleManifest } from '../domain/audit/versions.ts';
import type { AnalysisRequest, AnalysisResult } from '../domain/types.ts';
import type { AuditHealth, AuditKind, AuditRecord, AuditRecordHead, RecoveryDetail, RecordState, StoredOutcome } from '../domain/audit/types.ts';
import type { ReplayReport } from '../domain/audit/types.ts';

type IndexEntry = { recordId: string; sequence: number; digest: string; prev: string | null; sealedAt: string };
type SealedFile = { record: AuditRecord; digest: string };

type IndexRecovery = {
  entries: IndexEntry[];
  details: RecoveryDetail[];
  torn: number;
  chainBroken: boolean;
};

export type SealInput = {
  kind: AuditKind;
  request: AnalysisRequest;
  associatedJobId?: string;
  outcome: StoredOutcome;
  /** Override timestamps for deterministic testing. */
  now?: string;
  /** Override the record id for crash simulation. */
  recordId?: string;
};

export type AuditStoreOptions = {
  dir: string;
  sessionId?: string;
  clock?: () => string;
};

const INDEX_FILE = 'index.log';
const RECORDS_DIR = 'records';
const STAGING_DIR = 'staging';
const REPLAYS_DIR = 'replays';

/**
 * Append-only, tamper-evident evidence store backed by the local filesystem.
 *
 * Layout:
 *   index.log              one canonical JSON line per sealed record, chained
 *   records/<id>.json      atomically sealed record (tmp + rename)
 *   staging/<id>.json      partial write left behind by a crash mid-seal
 *   replays/<id>.json      append-only replay reports (independent chain)
 *
 * Records are immutable: replay never writes to records/, and sealing a record
 * never mutates a previously sealed one.
 */
export class AuditStore {
  readonly sessionId: string;
  readonly dir: string;
  private readonly recordsDir: string;
  private readonly stagingDir: string;
  private readonly replaysDir: string;
  private readonly indexPath: string;
  private readonly clock: () => string;
  private readonly records = new Map<string, AuditRecord>();
  private readonly headsByJob = new Map<string, string>();
  /** Quarantine state discovered during recovery or a later live verification. */
  private readonly quarantine = new Map<string, { state: RecordState; reason: string }>();
  /** Staging-file record ids: a partial write is distinguishable from "never existed". */
  private readonly stagedIds = new Set<string>();
  private readonly recovery = { recovered: 0, details: [] as RecoveryDetail[], orphaned: 0, tampered: 0, unsealed: 0, tornIndexEntries: 0, chainBroken: false };
  private replayCount = 0;
  private sealChainLock: Promise<unknown> = Promise.resolve();

  constructor(options: AuditStoreOptions) {
    this.dir = options.dir;
    this.sessionId = options.sessionId ?? randomUUID();
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.recordsDir = join(this.dir, RECORDS_DIR);
    this.stagingDir = join(this.dir, STAGING_DIR);
    this.replaysDir = join(this.dir, REPLAYS_DIR);
    this.indexPath = join(this.dir, INDEX_FILE);
    mkdirSync(this.recordsDir, { recursive: true });
    mkdirSync(this.stagingDir, { recursive: true });
    mkdirSync(this.replaysDir, { recursive: true });
    this.recover();
  }

  // ---------------------------------------------------------------- recovery

  private readIndex(): IndexRecovery {
    const result: IndexRecovery = { entries: [], details: [], torn: 0, chainBroken: false };
    if (!existsSync(this.indexPath)) return result;
    const lines = readFileSync(this.indexPath, 'utf8').split('\n');
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      let entry: IndexEntry;
      try {
        entry = JSON.parse(line) as IndexEntry;
      } catch {
        // A torn (non-parseable) final line is a partial index append: it is
        // quarantined as evidence of a partial write, never silently truncated.
        result.torn += 1;
        result.chainBroken = true;
        result.details.push({ recordId: `index-torn-${result.torn}`, state: 'unsealed', reason: 'TORN_INDEX_ENTRY: index line is not parseable after a crash mid-append' });
        continue;
      }
      const previous = result.entries.at(-1);
      const expectedPrev = previous ? previous.digest : null;
      if (entry.prev !== expectedPrev || entry.sequence !== result.entries.length + 1 || typeof entry.digest !== 'string' || typeof entry.recordId !== 'string') {
        result.chainBroken = true;
        result.details.push({ recordId: entry.recordId ?? 'unknown', state: 'tampered', reason: 'CHAIN_BROKEN: index entry fails sequence/prev-digest linkage' });
        // Stop trusting the chain past the first broken link.
        break;
      }
      result.entries.push(entry);
    }
    return result;
  }

  private readRecordFile(recordId: string): SealedFile | null {
    const path = join(this.recordsDir, `${recordId}.json`);
    if (!existsSync(path)) return null;
    try {
      const record = JSON.parse(readFileSync(path, 'utf8')) as AuditRecord;
      const digest = record.recordDigest;
      if (typeof digest !== 'string') return null;
      return { record, digest };
    } catch {
      return null;
    }
  }

  private digestOfRecordBody(record: AuditRecord): string {
    const { recordDigest: _omitted, ...body } = record;
    return digestOf(body);
  }

  private quarantineRecord(recordId: string, state: RecordState, reason: string): void {
    this.quarantine.set(recordId, { state, reason });
  }

  private recover(): void {
    const index = this.readIndex();
    this.recovery.tornIndexEntries = index.torn;
    this.recovery.chainBroken = index.chainBroken;
    for (const detail of index.details) this.recovery.details.push(detail);

    for (const entry of index.entries) {
      const loaded = this.readRecordFile(entry.recordId);
      if (!loaded) {
        // Indexed but file missing/unreadable: evidence is incomplete.
        this.quarantineRecord(entry.recordId, 'tampered', 'INDEXED_RECORD_MISSING: index entry exists but the sealed record file is absent or unreadable');
        this.recovery.details.push({ recordId: entry.recordId, state: 'tampered', reason: this.quarantine.get(entry.recordId)!.reason });
        this.recovery.tampered += 1;
        continue;
      }
      const bodyDigest = this.digestOfRecordBody(loaded.record);
      if (bodyDigest !== loaded.digest || loaded.digest !== entry.digest) {
        this.records.set(entry.recordId, Object.freeze({ ...loaded.record, recordDigest: loaded.digest }));
        this.quarantineRecord(entry.recordId, 'tampered', 'EVIDENCE_TAMPERED: stored record digest does not match its content or the index entry');
        this.recovery.details.push({ recordId: entry.recordId, state: 'tampered', reason: this.quarantine.get(entry.recordId)!.reason });
        this.recovery.tampered += 1;
        continue;
      }
      this.records.set(entry.recordId, Object.freeze(loaded.record));
      if (loaded.record.associatedJobId) this.headsByJob.set(loaded.record.associatedJobId, entry.recordId);
      this.recovery.recovered += 1;
    }

    // Sealed files with no valid index entry: the seal protocol never finished.
    for (const file of readdirSync(this.recordsDir)) {
      if (!file.endsWith('.json')) continue;
      const recordId = file.slice(0, -'.json'.length);
      if (this.records.has(recordId) || this.quarantine.has(recordId)) continue;
      const loaded = this.readRecordFile(recordId);
      if (!loaded) continue;
      this.records.set(recordId, Object.freeze({ ...loaded.record, recordDigest: loaded.digest }));
      const intact = this.digestOfRecordBody(loaded.record) === loaded.digest;
      this.quarantineRecord(recordId, 'orphaned', intact
        ? 'ORPHANED_SEALED_FILE: record file sealed but the chained index append did not complete'
        : 'ORPHANED_SEALED_FILE: record file sealed but the index append did not complete; content digest also mismatches');
      this.recovery.details.push({ recordId, state: 'orphaned', reason: this.quarantine.get(recordId)!.reason });
      this.recovery.orphaned += 1;
    }

    // Partial writes abandoned in staging (crash between write and rename).
    for (const file of readdirSync(this.stagingDir)) {
      if (!file.endsWith('.json')) continue;
      const fileRecordId = file.slice(0, -'.json'.length);
      let recordId = fileRecordId;
      let reason = 'UNSEALED_RECORD: crash interrupted sealing before the atomic rename; record is partial evidence';
      try {
        const staged = JSON.parse(readFileSync(join(this.stagingDir, file), 'utf8')) as Partial<AuditRecord>;
        if (typeof staged.recordId === 'string') recordId = staged.recordId;
      } catch {
        reason = 'UNSEALED_RECORD: staging file is not parseable; crash interrupted a partial write';
      }
      this.stagedIds.add(recordId);
      this.quarantineRecord(recordId, 'unsealed', reason);
      this.recovery.details.push({ recordId, state: 'unsealed', reason });
      this.recovery.unsealed += 1;
    }
  }

  // ------------------------------------------------------------------ seals

  private recordState(record: AuditRecord): RecordState {
    const flagged = this.quarantine.get(record.recordId);
    if (flagged) return flagged.state;
    if (!record.recordDigest || !record.sealedAt) return 'unsealed';
    return 'sealed';
  }

  private lastIndexEntry(): IndexEntry | null {
    if (!existsSync(this.indexPath)) return null;
    const lines = readFileSync(this.indexPath, 'utf8').split('\n').map((line: string) => line.trim()).filter(Boolean);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      try {
        return JSON.parse(lines[index]) as IndexEntry;
      } catch {
        continue;
      }
    }
    return null;
  }

  private appendIndex(entry: IndexEntry): void {
    const fd = openSync(this.indexPath, 'a');
    try {
      writeSync(fd, `${JSON.stringify(entry)}\n`);
    } finally {
      closeSync(fd);
    }
  }

  private sealRecord(input: SealInput): AuditRecord {
    const recordId = input.recordId ?? randomUUID();
    const now = input.now ?? this.clock();
    const request = structuredClone(input.request);
    const outcome = structuredClone(input.outcome);
    const previous = this.lastIndexEntry();
    const record: AuditRecord = {
      recordId,
      kind: input.kind,
      sessionId: this.sessionId,
      createdAt: now,
      experimentId: request.experimentId,
      kindOfExperiment: request.kind,
      ...(input.associatedJobId ? { associatedJobId: input.associatedJobId } : {}),
      inputDigest: legacyInputDigest(request),
      inputCanonicalDigest: digestOf(request),
      request,
      calibrationRefs: buildCalibrationRefs(request.calibrations),
      algorithmVersion: ALGORITHM_VERSION,
      ruleVersion: currentRuleVersion(),
      ruleManifest: getRuleManifest(),
      outcome,
      summary: summarizeOutcome(outcome),
      sequence: previous ? previous.sequence + 1 : 1,
      previousRecordDigest: previous ? previous.digest : null,
    };
    const sealedAt = now;
    const full: AuditRecord = { ...record, sealedAt };
    const recordDigest = digestOf((() => { const { recordDigest: _d, ...body } = full; return body; })());
    const sealed: AuditRecord = Object.freeze({ ...full, recordDigest });

    // Two-phase write: full JSON to staging, atomic rename, then chained index append.
    // Storage uses standard JSON.stringify (parse-round-trip safe); only hashing
    // goes through the key-sorted canonical form.
    const stagingPath = join(this.stagingDir, `${recordId}.json`);
    const finalPath = join(this.recordsDir, `${recordId}.json`);
    writeFileSync(stagingPath, JSON.stringify(sealed), 'utf8');
    renameSync(stagingPath, finalPath);
    this.records.set(recordId, sealed);
    this.quarantine.delete(recordId);
    this.stagedIds.delete(recordId);
    if (input.associatedJobId) this.headsByJob.set(input.associatedJobId, recordId);
    this.appendIndex({ recordId, sequence: sealed.sequence, digest: recordDigest, prev: sealed.previousRecordDigest, sealedAt: now });
    return sealed;
  }

  /**
   * Seal evidence. Concurrent seals are serialized so the hash chain can never
   * fork; callers receive the order the records actually landed in.
   */
  seal(input: SealInput): Promise<AuditRecord> {
    const run = this.sealChainLock.then(() => this.sealRecord(input));
    this.sealChainLock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  sealSuccess(kind: AuditKind, request: AnalysisRequest, result: AnalysisResult, associatedJobId?: string): Promise<AuditRecord> {
    return this.seal({ kind, request: structuredClone(request), outcome: storeSuccess(result), associatedJobId });
  }

  sealFailure(kind: AuditKind, request: AnalysisRequest, error: { code: string; message: string }, associatedJobId?: string): Promise<AuditRecord> {
    return this.seal({ kind, request: structuredClone(request), outcome: storeFailure(error), associatedJobId });
  }

  // ----------------------------------------------------------------- reads

  get(recordId: string): AuditRecord {
    const record = this.records.get(recordId);
    if (!record) throw new DomainError('AUDIT_RECORD_NOT_FOUND', 'Audit record was not found in this store', 404, { recordId });
    return record;
  }

  /** Distinguishes a complete record, a partial write (staging only), and an unknown id. */
  locate(recordId: string): { exists: boolean; record?: AuditRecord; state: RecordState | 'not-found'; reason?: string } {
    const record = this.records.get(recordId);
    if (record) return { exists: true, record, state: this.recordState(record), reason: this.quarantine.get(recordId)?.reason };
    if (this.stagedIds.has(recordId)) return { exists: true, state: 'unsealed', reason: this.quarantine.get(recordId)?.reason };
    if (this.quarantine.has(recordId)) return { exists: true, state: this.quarantine.get(recordId)!.state, reason: this.quarantine.get(recordId)!.reason };
    return { exists: false, state: 'not-found' };
  }

  getHead(record: AuditRecord): AuditRecordHead {
    return {
      recordId: record.recordId,
      sequence: record.sequence,
      kind: record.kind,
      sessionId: record.sessionId,
      createdAt: record.createdAt,
      ...(record.sealedAt ? { sealedAt: record.sealedAt } : {}),
      experimentId: record.experimentId,
      kindOfExperiment: record.kindOfExperiment,
      ...(record.associatedJobId ? { associatedJobId: record.associatedJobId } : {}),
      inputDigest: record.inputDigest,
      inputCanonicalDigest: record.inputCanonicalDigest,
      calibrationRefs: record.calibrationRefs,
      algorithmVersion: record.algorithmVersion,
      ruleVersion: record.ruleVersion,
      outcome: structuredClone(record.outcome),
      summary: structuredClone(record.summary),
      recordDigest: record.recordDigest ?? '',
      previousRecordDigest: record.previousRecordDigest,
      recordState: this.recordState(record),
    };
  }

  list(filter?: { jobId?: string; experimentId?: string; kind?: AuditKind }): AuditRecordHead[] {
    return [...this.records.values()]
      .filter((record) => (!filter?.jobId || record.associatedJobId === filter.jobId) && (!filter?.experimentId || record.experimentId === filter.experimentId) && (!filter?.kind || record.kind === filter.kind))
      .sort((a, b) => a.sequence - b.sequence)
      .map((record) => this.getHead(record));
  }

  findByJob(jobId: string): AuditRecord | undefined {
    const recordId = this.headsByJob.get(jobId);
    return recordId ? this.records.get(recordId) : undefined;
  }

  /** Independent, append-only replay chain. Replays never touch record files. */
  persistReplay(report: ReplayReport): ReplayReport {
    const path = join(this.replaysDir, `${report.replayId}.json`);
    writeFileSync(path, JSON.stringify(report), 'utf8');
    this.replayCount += 1;
    return report;
  }

  health(): AuditHealth {
    const sealed = [...this.records.values()].filter((record) => this.recordState(record) === 'sealed').length;
    return {
      sessionId: this.sessionId,
      recordsSealed: sealed,
      recordsInMemory: this.records.size,
      replaysRecorded: this.replayCount,
      recovery: structuredClone({ recovered: this.recovery.recovered, details: this.recovery.details, orphaned: this.recovery.orphaned, tampered: this.recovery.tampered, unsealed: this.recovery.unsealed, tornIndexEntries: this.recovery.tornIndexEntries, chainBroken: this.recovery.chainBroken }),
    };
  }

  // ------------------------------------------------------ integrity helpers

  /**
   * Live integrity verification of a record against its own digest and the
   * append chain. Used by replay so a tampered/orphaned record cannot be reproduced.
   */
  verifyIntegrity(record: AuditRecord): { state: RecordState; chain: 'verified' | 'broken' } {
    const flagged = this.quarantine.get(record.recordId);
    if (flagged) return { state: flagged.state, chain: 'broken' };
    if (!record.recordDigest || !record.sealedAt) return { state: 'unsealed', chain: 'broken' };
    // Verify the bytes on disk, not the frozen in-memory copy, so external
    // tampering of the record file is detected on every replay.
    const loaded = this.readRecordFile(record.recordId);
    const onDiskIntact = loaded !== null && this.digestOfRecordBody(loaded.record) === loaded.digest && loaded.digest === record.recordDigest;
    if (!onDiskIntact) {
      this.quarantineRecord(record.recordId, 'tampered', 'EVIDENCE_TAMPERED: record digest no longer matches the bytes on disk');
      return { state: 'tampered', chain: 'broken' };
    }
    const index = this.readIndex();
    const entry = index.entries.find((candidate) => candidate.recordId === record.recordId);
    if (!entry || entry.digest !== record.recordDigest) {
      this.quarantineRecord(record.recordId, 'orphaned', 'ORPHANED_SEALED_FILE: record is not reachable through the chained index');
      return { state: 'orphaned', chain: 'broken' };
    }
    if (index.chainBroken) return { state: 'sealed', chain: 'broken' };
    return { state: 'sealed', chain: 'verified' };
  }

  // ------------------------------------------------------- crash simulation

  /**
   * Test-only seam: write a staging file and never rename it, reproducing a
   * crash in the middle of sealing a record (partial write).
   */
  stagePartialRecord(partial?: { recordId?: string; request?: Partial<AnalysisRequest>; outcome?: StoredOutcome }): string {
    const recordId = partial?.recordId ?? randomUUID();
    const staged: Partial<AuditRecord> = {
      recordId,
      sessionId: this.sessionId,
      createdAt: this.clock(),
      experimentId: partial?.request?.experimentId ?? 'partial',
      kind: 'async',
      kindOfExperiment: (partial?.request?.kind as AuditRecord['kindOfExperiment']) ?? 't1',
      inputDigest: 'partial',
      inputCanonicalDigest: 'partial',
      request: partial?.request as AnalysisRequest | undefined,
      calibrationRefs: [],
      algorithmVersion: ALGORITHM_VERSION,
      ruleVersion: currentRuleVersion(),
      ruleManifest: getRuleManifest(),
      outcome: partial?.outcome ?? { status: 'failed', error: { code: 'PARTIAL', message: 'sealing interrupted' } },
      summary: summarizeOutcome(partial?.outcome ?? { status: 'failed', error: { code: 'PARTIAL', message: 'sealing interrupted' } }),
      sequence: 0,
      previousRecordDigest: null,
    };
    writeFileSync(join(this.stagingDir, `${recordId}.json`), JSON.stringify(staged), 'utf8');
    this.stagedIds.add(recordId);
    const reason = 'UNSEALED_RECORD: crash interrupted sealing before the atomic rename; record is partial evidence';
    if (!this.quarantine.has(recordId)) {
      this.quarantine.set(recordId, { state: 'unsealed', reason });
      this.recovery.details.push({ recordId, state: 'unsealed', reason });
      this.recovery.unsealed += 1;
    }
    return recordId;
  }

  /** Test-only seam: append a non-parseable trailing line to the index log. */
  appendTornIndexLine(line = '{"recordId":"torn","sequence":999,"digest":"abc'): void {
    const fd = openSync(this.indexPath, 'a');
    try {
      writeSync(fd, `${line}\n`);
    } finally {
      closeSync(fd);
    }
  }

  /** Test-only seam: mutate a sealed record file without updating digest or index. */
  tamperRecordFile(recordId: string, mutate: (raw: string) => string): void {
    const path = join(this.recordsDir, `${recordId}.json`);
    if (!existsSync(path)) throw new DomainError('AUDIT_RECORD_NOT_FOUND', 'Cannot tamper a missing record', 404, { recordId });
    writeFileSync(path, mutate(readFileSync(path, 'utf8')), 'utf8');
    this.quarantineRecord(recordId, 'tampered', 'EVIDENCE_TAMPERED: stored record digest does not match its content or the index entry');
  }
}
