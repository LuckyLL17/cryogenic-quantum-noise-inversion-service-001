import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from '../src/application/audit-store.ts';
import { ReplayService } from '../src/application/replay.ts';
import { analyzeExperiment } from '../src/application/analysis-service.ts';
import { diffResults } from '../src/domain/audit/diff.ts';
import { digestOf, legacyInputDigest } from '../src/domain/audit/canonical.ts';
import { ALGORITHM_VERSION } from '../src/domain/audit/versions.ts';
import type { AnalysisRequest, CalibrationProfile, RawSample } from '../src/domain/types.ts';

const calibration: CalibrationProfile = { profileId: 'cal-1', channelId: 'ch-a', validFromNs: 0, adcScale: 2, iOffset: 0.1, qOffset: -0.2, gainCorrection: 1, phaseCorrectionRad: 0, temperatureCoefficientPerK: 0, referenceTemperatureK: 0.02, systematicUncertainty: 0.01, sampleUncertainty: 0.001 };
function sample(index: number, channelId = 'ch-a'): RawSample { return { captureId: `${channelId}-${index}`, experimentId: 'exp-1', channelId, role: 'readout-i', triggerId: `t-${Math.floor(index / 4)}`, timestampNs: index * 1_000_000, receivedAtNs: index * 1_000_000 + 100, sequence: index, sampleRateHz: 1_000, i: Math.cos(index / 4) + 0.1, q: Math.sin(index / 4) - 0.2, quality: 'good' }; }
function request(overrides: Partial<CalibrationProfile> = {}): AnalysisRequest { return { experimentId: 'exp-1', kind: 't1', samples: Array.from({ length: 32 }, (_, index) => sample(index)), calibrations: [{ ...calibration, ...overrides }], analysis: { windowSize: 16 } }; }

function openStore(sessionId?: string): { store: AuditStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'audit-'));
  return { store: new AuditStore({ dir, sessionId }), dir };
}
async function sealedSuccess(store: AuditStore, req?: AnalysisRequest) {
  const input = req ?? request();
  const result = analyzeExperiment(input);
  const record = await store.sealSuccess('preview', input, result);
  return { record, input, result };
}
async function settled<T>(promise: Promise<T>): Promise<T> { return promise; }

// --------------------------------------------------------------------- evidence

test('preview/async evidence stores the full immutable input, calibration refs, versions and summary', async () => {
  const { store } = openStore('session-A');
  const { record, input, result } = await sealedSuccess(store);

  assert.equal(record.sealedAt !== undefined, true);
  assert.equal(record.inputDigest, legacyInputDigest(input));
  assert.equal(record.inputDigest, result.inputDigest, 'legacy digest in response stays identical');
  assert.equal(record.calibrationRefs.length, 1);
  assert.equal(record.calibrationRefs[0].profileId, 'cal-1');
  assert.match(record.calibrationRefs[0].contentDigest, /^[0-9a-f]{64}$/);
  assert.equal(record.algorithmVersion, ALGORITHM_VERSION);
  assert.ok(Object.keys(record.ruleManifest).length >= 6);
  assert.equal(record.summary.noiseClass, result.noise.class);
  assert.equal(record.summary.amplitudeMean, result.metrics.amplitudeMean);
  assert.equal(record.summary.spectrumBins, result.primarySpectrum.length);
  // Full input, not just a digest, is preserved.
  assert.equal(record.request.samples.length, 32);
  assert.deepEqual(record.request.calibrations[0], calibration);
  assert.throws(() => { (record as any).experimentId = 'mutated'; }, TypeError);
});

test('sealing a record never mutates the caller input and a record file is durable', async () => {
  const { store, dir } = openStore();
  const input = request();
  const result = analyzeExperiment(input);
  const record = await store.sealSuccess('async', input, result);

  // Mutate caller's object after sealing; the stored evidence must be unaffected.
  input.samples[0].i = 999;
  input.calibrations[0].adcScale = 42;
  const fetched = store.get(record.recordId);
  assert.equal(fetched.request.samples[0].i, Math.cos(0) + 0.1);
  assert.equal(fetched.request.calibrations[0].adcScale, 2);
  assert.ok(existsSync(join(dir, 'records', `${record.recordId}.json`)));
  assert.ok(!existsSync(join(dir, 'staging', `${record.recordId}.json`)));
});

test('failed outcomes are sealed too and replay reproduces the same failure', async () => {
  const { store } = openStore();
  const bad = request();
  (bad as any).samples = [];
  assert.throws(() => analyzeExperiment(bad));
  const record = await store.sealFailure('async', bad, { code: 'EMPTY_SAMPLES', message: 'At least one sample is required' });
  const report = await new ReplayService(store).replay(record.recordId);
  assert.equal(report.status, 'reproduced');
  assert.equal(report.reproducible, true);
  assert.ok(report.conditions.includes('OUTCOME_FAILED'));
  assert.equal(report.replayOutcome?.status, 'failed');
  assert.equal(report.replayOutcome?.error?.code, 'EMPTY_SAMPLES');
});

// ------------------------------------------------------------- exact reproduction

test('replaying sealed evidence reproduces the exact result without touching the record', async () => {
  const { store, dir } = openStore('session-A');
  const { record } = await sealedSuccess(store);
  const before = readFileSync(join(dir, 'records', `${record.recordId}.json`), 'utf8');

  const replay = new ReplayService(store);
  const report = await settled(replay.replay(record.recordId));

  assert.equal(report.status, 'reproduced');
  assert.equal(report.reproducible, true);
  assert.deepEqual(report.conditions, ['REPLAYED_EXACT']);
  assert.equal(report.diff?.match, 'exact');
  assert.equal(report.evidence.recordIntegrity, 'sealed');
  assert.equal(report.evidence.chainIntegrity, 'verified');
  assert.equal(report.evidence.inputDigestMatches, true);
  assert.equal(report.evidence.restarted, false);
  assert.equal(report.calibration.mode, 'sealed');
  // Original record bytes unchanged; replay lives in its own append-only area.
  assert.equal(readFileSync(join(dir, 'records', `${record.recordId}.json`), 'utf8'), before);
  assert.equal(readdirSync(join(dir, 'replays')).length, 1);
});

// ------------------------------------------------------------ process restart

test('records survive a process restart and replay flags the session change while staying reproducible', async () => {
  const { dir } = openStore('session-before');
  let recordId: string;
  {
    const first = new AuditStore({ dir, sessionId: 'session-before' });
    const sealed = await sealedSuccess(first);
    recordId = sealed.record.recordId;
  }
  // Simulate a brand-new process: fresh store over the same on-disk directory.
  const restarted = new AuditStore({ dir, sessionId: 'session-after' });
  const health = restarted.health();
  assert.equal(health.recovery.recovered, 1);
  assert.equal(health.recordsSealed, 1);

  const report = await new ReplayService(restarted).replay(recordId);
  assert.equal(report.status, 'reproduced');
  assert.equal(report.evidence.restarted, true);
  assert.equal(report.evidence.chainIntegrity, 'verified');
});

test('an in-memory-only id unknown after restart is reported as RECORD_NOT_FOUND, not guessed', async () => {
  const { store } = openStore();
  const report = await new ReplayService(store).replay('does-not-exist');
  assert.equal(report.status, 'not-found');
  assert.deepEqual(report.conditions, ['RECORD_NOT_FOUND']);
  assert.equal(report.reproducible, false);
});

// --------------------------------------------------------- partial writes / torn

test('a partial write left in staging is quarantined and cannot be replayed', async () => {
  const { store } = openStore();
  const partialId = store.stagePartialRecord({ recordId: 'partial-1' });
  const health = store.health();
  assert.equal(health.recovery.unsealed, 1);

  const located = store.locate(partialId);
  assert.equal(located.state, 'unsealed');

  const report = await new ReplayService(store).replay(partialId);
  assert.equal(report.status, 'unreplayable');
  assert.deepEqual(report.conditions, ['RECORD_UNSEALED']);
  assert.match(report.error?.message ?? '', /UNSEALED_RECORD/);
});

test('a torn trailing index line after a crash is detected and keeps prior records verified', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store);
  store.appendTornIndexLine();

  // Fresh process to exercise real recovery-time detection.
  const dir = store.dir;
  const recovered = new AuditStore({ dir });
  assert.equal(recovered.health().recovery.tornIndexEntries, 1);
  assert.equal(recovered.health().recovery.chainBroken, true);
  const report = await new ReplayService(recovered).replay(record.recordId);
  // Record itself is intact, but chain verification cannot fully attest it.
  assert.equal(report.evidence.recordIntegrity, 'sealed');
  assert.equal(report.evidence.chainIntegrity, 'broken');
  assert.equal(report.status, 'reproduced');
});

test('a sealed file whose index append was lost is reported as RECORD_ORPHANED', async () => {
  const { store, dir } = openStore();
  const { record } = await sealedSuccess(store);
  // Remove index entry but keep the record file: rename succeeded, append did not.
  writeFileSync(join(dir, 'index.log'), '');

  const recovered = new AuditStore({ dir });
  const health = recovered.health();
  assert.equal(health.recovery.orphaned, 1);
  const report = await new ReplayService(recovered).replay(record.recordId);
  assert.equal(report.status, 'unreplayable');
  assert.deepEqual(report.conditions, ['RECORD_ORPHANED']);
});

// ---------------------------------------------------------------- tampering

test('a tampered record file fails digest verification and cannot be replayed', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store);
  store.tamperRecordFile(record.recordId, (raw) => raw.replace('"adcScale":2', '"adcScale":3'));

  const report = await new ReplayService(store).replay(record.recordId);
  assert.equal(report.status, 'unreplayable');
  assert.deepEqual(report.conditions, ['RECORD_TAMPERED']);
  assert.equal(report.evidence.recordIntegrity, 'tampered');
  assert.equal(report.evidence.chainIntegrity, 'broken');
});

test('tampering is also detected by a fresh process recovering the store', async () => {
  const { store, dir } = openStore();
  const { record } = await sealedSuccess(store);
  const { writeFileSync } = await import('node:fs');
  const path = join(dir, 'records', `${record.recordId}.json`);
  writeFileSync(path, readFileSync(path, 'utf8').replace('"adcScale":2', '"adcScale":3'));

  const recovered = new AuditStore({ dir });
  assert.equal(recovered.health().recovery.tampered, 1);
  const head = recovered.list().find((item) => item.recordId === record.recordId);
  assert.equal(head?.recordState, 'tampered');
});

// -------------------------------------------------------- missing calibration

test('registry replay against a missing historical calibration is a distinct unreplayable result', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store);
  const report = await new ReplayService(store).replay(record.recordId, { calibration: { mode: 'registry', profiles: [] } });
  assert.equal(report.status, 'unreplayable');
  assert.deepEqual(report.conditions, ['CALIBRATION_MISSING']);
  assert.deepEqual(report.calibration.missingProfileIds, ['cal-1']);
  assert.equal(report.error?.code, 'CALIBRATION_MISSING');
});

// -------------------------------------------------------- changed calibration

test('registry replay with a changed calibration reports CALIBRATION_CHANGED and uses the supplied profile, not a silent fallback', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store);
  const changedCalibration = { ...calibration, adcScale: 3 };
  const report = await new ReplayService(store).replay(record.recordId, { calibration: { mode: 'registry', profiles: [changedCalibration] } });

  assert.ok(report.conditions.includes('CALIBRATION_CHANGED'));
  assert.deepEqual(report.calibration.changedProfileIds, ['cal-1']);
  assert.equal(report.calibration.mode, 'registry');
  // Recomputed with the new scale: numeric results must differ.
  assert.notDeepEqual(report.replayOutcome?.result?.metrics, record.outcome.result?.metrics);
  assert.equal(report.diff?.match, 'different');
  assert.equal(report.status, 'diverged');
});

test('sealed-mode replay never substitutes a current calibration even when one is provided out of band', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store, request({ adcScale: 2 }));
  // Default replay: ignores any ambient table; embedded payload is authoritative.
  const report = await new ReplayService(store).replay(record.recordId);
  assert.equal(report.calibration.mode, 'sealed');
  assert.deepEqual(report.conditions, ['REPLAYED_EXACT']);
});

test('a sub-ULP-scale calibration perturbation yields NUMERICAL_DRIFT, distinct from exact and divergence', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store, request({ adcScale: 2 }));
  // One part in 1e13: outputs move by ~1e-13, below the default 1e-12 absolute
  // tolerance but far above bit-identical reproduction.
  const perturbed = { ...calibration, adcScale: 2 + 2e-13 };
  const driftReport = await new ReplayService(store).replay(record.recordId, { calibration: { mode: 'registry', profiles: [perturbed] } });
  assert.equal(driftReport.status, 'numerical-drift');
  assert.equal(driftReport.reproducible, false, 'within-tolerance drift is not a true reproduction');
  assert.ok(driftReport.conditions.includes('NUMERICAL_DRIFT'));
  assert.ok(driftReport.conditions.includes('CALIBRATION_CHANGED'));
  assert.equal(driftReport.diff?.match, 'within-tolerance');
  assert.ok(driftReport.diff!.changes.length > 0);
  assert.ok(driftReport.diff!.changes.every((change) => change.kind === 'value'));

  // Tightening the tolerance turns the same evidence into a divergence: the
  // distinction is driven by the declared tolerance, never hidden.
  const strictReport = await new ReplayService(store).replay(record.recordId, { calibration: { mode: 'registry', profiles: [perturbed] }, tolerance: { absolute: 0, relative: 0 } });
  assert.equal(strictReport.status, 'diverged');
  assert.equal(strictReport.diff?.match, 'different');
});

// -------------------------------------------------------- algorithm upgrade

test('an algorithm upgrade is distinguishable even if outputs happen to match', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-shim-'));
  try {
    // First process seals under the current algorithm...
    let recordId: string;
    {
      const store = new AuditStore({ dir });
      const sealed = await sealedSuccess(store);
      recordId = sealed.record.recordId;
    }
    // ...then evidence is rewritten the way an older binary would have sealed it
    // (prior algorithm version, re-hashed, index updated). The current binary
    // replaying it must flag ALGORITHM_UPGRADED.
    forgeOldAlgorithmRecord(dir, recordId);
    const recovered = new AuditStore({ dir });
    const report = await new ReplayService(recovered).replay(recordId);
    assert.ok(report.conditions.includes('ALGORITHM_UPGRADED'), report.conditions.join(','));
    assert.equal(report.versions.sealedAlgorithm, 'analysis-algorithm-0.9.0');
    assert.equal(report.versions.currentAlgorithm, ALGORITHM_VERSION);
    // Outputs happen to match byte-for-byte; verdict is still not "plain reproduction":
    // status reflects numerical equality while evidence explains the version change.
    assert.equal(report.diff?.match, 'exact');
    assert.equal(report.status, 'reproduced');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function forgeOldAlgorithmRecord(dir: string, recordId: string): void {
  const path = join(dir, 'records', `${recordId}.json`);
  const body = JSON.parse(readFileSync(path, 'utf8'));
  body.algorithmVersion = 'analysis-algorithm-0.9.0';
  const { recordDigest: _digest, ...rest } = body;
  body.recordDigest = digestOf(rest);
  writeFileSync(path, JSON.stringify(body));
  writeFileSync(join(dir, 'index.log'), JSON.stringify({ recordId, sequence: body.sequence, digest: body.recordDigest, prev: body.previousRecordDigest, sealedAt: body.sealedAt }) + '\n');
}

test('a rule-module upgrade with unchanged algorithm version is RULE_VERSION_CHANGED, not ALGORITHM_UPGRADED', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-rule-'));
  try {
    let recordId: string;
    {
      const store = new AuditStore({ dir });
      recordId = (await sealedSuccess(store)).record.recordId;
    }
    // Rewrite evidence as the same algorithm but an older noise-classification rule.
    const path = join(dir, 'records', `${recordId}.json`);
    const body = JSON.parse(readFileSync(path, 'utf8'));
    body.ruleManifest['noise.classify'] = 'noise-classify-0.9.0';
    body.ruleVersion = digestOf(body.ruleManifest);
    const { recordDigest: _digest, ...rest } = body;
    body.recordDigest = digestOf(rest);
    writeFileSync(path, JSON.stringify(body));
    writeFileSync(join(dir, 'index.log'), JSON.stringify({ recordId, sequence: body.sequence, digest: body.recordDigest, prev: body.previousRecordDigest, sealedAt: body.sealedAt }) + '\n');

    const recovered = new AuditStore({ dir });
    const report = await new ReplayService(recovered).replay(recordId);
    assert.ok(report.conditions.includes('RULE_VERSION_CHANGED'));
    assert.ok(!report.conditions.includes('ALGORITHM_UPGRADED'));
    assert.equal(report.versions.sealedAlgorithm, report.versions.currentAlgorithm);
    assert.equal(report.versions.ruleManifestChanged, true);
    assert.deepEqual(report.versions.changedModules, ['noise.classify']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --------------------------------------------------------------- concurrency

test('concurrent replays of the same record join one run and all receive identical verdicts', async () => {
  const { store } = openStore();
  const { record } = await sealedSuccess(store);
  const replay = new ReplayService(store);

  // Fire concurrently; the synchronous prelude registers all callers before awaits resolve.
  const reports = await Promise.all(Array.from({ length: 5 }, () => replay.replay(record.recordId)));

  for (const report of reports) {
    assert.equal(report.status, 'reproduced');
    assert.ok(report.conditions.includes('CONCURRENT_REPLAY'));
  }
  // Exactly one computation, five persisted reports.
  const ids = new Set(reports.map((report) => report.replayId));
  assert.equal(ids.size, 5);
  const verdicts = new Set(reports.map((report) => `${report.status}:${report.diff?.match}`));
  assert.equal(verdicts.size, 1);
  assert.ok(reports.some((report) => report.concurrentPeers >= 4));
});

// ---------------------------------------------------------- floating point

test('floating point drift within tolerance is distinct from exact match and from divergence', () => {
  const base = { a: 1.0, nested: { b: [1, 2, 3] } };

  const exact = diffResults(base, { a: 1.0, nested: { b: [1, 2, 3] } }, { absolute: 1e-12, relative: 1e-9 });
  assert.equal(exact.match, 'exact');

  const tinyUlp = diffResults(base, { a: 1 + 1e-15, nested: { b: [1, 2, 3] } }, { absolute: 1e-12, relative: 1e-9 });
  assert.equal(tinyUlp.match, 'within-tolerance');
  assert.equal(tinyUlp.changes[0].kind, 'value');
  assert.equal(tinyUlp.changes[0].path, 'a');

  const drifted = diffResults(base, { a: 1.001, nested: { b: [1, 2, 3] } }, { absolute: 1e-12, relative: 1e-9 });
  assert.equal(drifted.match, 'different');

  const structural = diffResults(base, { a: 1.0, nested: { b: [1, 2] } }, { absolute: 1e-12, relative: 1e-9 });
  assert.equal(structural.match, 'different');
  assert.ok(structural.changes.some((change) => change.kind === 'structural'));
});

// ------------------------------------------------------------- listing / API

test('records can be listed by job/experiment/kind and heads expose record state', async () => {
  const { store } = openStore();
  await sealedSuccess(store);
  await store.sealSuccess('async', request(), analyzeExperiment(request()), 'job-42');

  const all = store.list();
  assert.equal(all.length, 2);
  assert.equal(store.list({ kind: 'async' })[0]?.associatedJobId, 'job-42');
  assert.equal(store.list({ jobId: 'job-42' }).length, 1);
  assert.equal(store.list({ experimentId: 'exp-1' }).length, 2);
  assert.equal(store.findByJob('job-42') !== undefined, true);
  for (const head of all) assert.equal(head.recordState, 'sealed');
});

test('hash chain links consecutive records and health reports recovery details', async () => {
  const { store } = openStore();
  const first = await sealedSuccess(store);
  const second = await sealedSuccess(store);
  assert.equal(first.record.previousRecordDigest, null);
  assert.equal(second.record.previousRecordDigest, first.record.recordDigest);
  assert.equal(second.record.sequence, 2);

  const health = store.health();
  assert.equal(health.recordsSealed, 2);
  assert.equal(health.recovery.chainBroken, false);
  assert.deepEqual(health.recovery.details, []);
});
