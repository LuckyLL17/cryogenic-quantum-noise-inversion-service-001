#!/usr/bin/env node
/**
 * End-to-end demonstration of auditable replay.
 *
 * Walks through:
 *   1. Preview + async analysis with full evidence capture
 *   2. Faithful replay  -> REPRODUCIBLE (exact)
 *   3. Historical calibration missing from the live registry
 *   4. Calibration binding drift (frozen copy still used)
 *   5. Algorithm upgrade (v1 -> v2) + compareWithCurrent reference
 *   6. Process restart mid-job -> INTERRUPTED
 *   7. Partial write debris / torn journal / tampering
 *   8. Concurrent replays
 *   9. Floating-point drift within tolerance
 *
 * Run:  node examples/demo.js
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync, appendFileSync, rmSync, readFileSync } from 'node:fs';
import {
  AuditStore,
  AnalysisService,
  Replayer,
  CalibrationRegistry,
  NoiseRuleRegistry,
  registerBuiltinRules,
  RULE_STDLIB,
  stdlibDigest,
  REPLAY_MODE,
} from '../src/index.js';

const root = mkdtempSync(join(tmpdir(), 'noise-audit-demo-'));
console.log(`audit store: ${root}\n`);

const line = (title) => console.log(`\n=== ${title} ===`);
const verdict = (r) =>
  `${r.status.padEnd(42)} verdict=${r.verdict.padEnd(24)} reproducible=${r.reproducible}`;

// ---- shared registries --------------------------------------------------
const calibrations = new CalibrationRegistry();
calibrations.register({
  calibrationId: 'mic-array-A',
  version: 'v2025-09',
  payload: { gain: 1.0002, offset: -0.01, noiseFloor: 0.05 },
});
calibrations.publish('mic-array-A', 'v2025-09');

const rules = new NoiseRuleRegistry();
registerBuiltinRules(rules); // v1.0.0 + v2.0.0 (current)

const store = await new AuditStore({ root }).open();
const service = new AnalysisService({ store, calibrations, rules });
const replayer = new Replayer({ store, calibrations, rules });

const samples = Array.from({ length: 256 }, (_, i) =>
  0.11 + Math.sin(i / 9) * 0.004 + ((i * 7919) % 100) / 100 * 0.001);

// ---- 1. preview: legacy response preserved + audit ---------------------
line('1. preview — legacy fields preserved, evidence added');
const preview = await service.preview({
  input: { seriesId: 'run-1412', samples, baseline: 0, samplingRateHz: 1000 },
  params: {},
});
console.log('legacy keys:', Object.keys(preview).filter((k) => k !== 'audit').join(', '));
console.log('inputDigest       =', preview.inputDigest.slice(0, 24) + '…');
console.log('calibrationVersions =', JSON.stringify(preview.calibrationVersions));
console.log('ruleVersion       =', preview.ruleVersion);
console.log('audit.recordId    =', preview.audit.recordId);
console.log('rule impl digest  =', preview.audit.rule.implDigest.slice(0, 16) + '…');
const previewRecordId = preview.audit.recordId;

// ---- 2. faithful replay -------------------------------------------------
line('2. faithful replay of the preview');
console.log(verdict(await replayer.replay(previewRecordId)));

// ---- 3. async analysis + replay ----------------------------------------
line('3. async analysis completes and replays');
const job = await service.analyzeAsync({
  input: { seriesId: 'run-1413', samples: samples.slice(0, 64), baseline: 0 },
  params: {},
});
const done = await service.getJob(job.jobId, { waitMs: 2000 });
console.log('job', job.jobId.slice(0, 18) + '…', '->', done.status);
console.log(verdict(await replayer.replay(done.recordId)));

// ---- 4. historical calibration missing from live registry --------------
line('4. new process whose registry dropped v2025-09');
const newCal = new CalibrationRegistry();
newCal.register({
  calibrationId: 'mic-array-A', version: 'v2026-01',
  payload: { gain: 1.0003, offset: -0.009, noiseFloor: 0.04 },
});
newCal.publish('mic-array-A', 'v2026-01');
const rpNewCal = new Replayer({ store, calibrations: newCal, rules });
const r4 = await rpNewCal.replay(previewRecordId);
console.log(verdict(r4));
console.log('calibration evidence:',
  r4.evidence.calibrationChecks.map((c) =>
    `${c.version}: frozen=${c.frozenStatus} registry=${c.registryStatus}`).join('; '));

// ---- 5. algorithm upgrade -----------------------------------------------
line('5. record pinned to rule v1 while v2 is current');
const v1resp = await service.preview({
  input: { seriesId: 'run-legacy', samples: samples.slice(0, 128), baseline: 0 },
  rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' },
});
const r5 = await replayer.replay(v1resp.audit.recordId, {
  compareWithCurrent: true,
});
console.log(verdict(r5));
console.log('upgrade available:', r5.state.upgradeAvailable,
  '| current:', r5.evidence.ruleCheck.currentVersion,
  '| pinned:', r5.ruleVersion);
console.log('current-reference would produce v2 fields:',
  Object.keys(r5.currentReference.result.metrics).filter((k) =>
    ['stddev', 'driftSlope', 'correctedSnrDb'].includes(k)).join(', '));
console.log('explicit current-reference mode:',
  (await replayer.replay(v1resp.audit.recordId, { mode: REPLAY_MODE.CURRENT_REFERENCE })).status);

// ---- 6. process restart --------------------------------------------------
line('6. process restart while an async job is enqueued');
const svcBeforeRestart = new AnalysisService({
  store, calibrations, rules, scheduler: () => {},
});
const killed = await svcBeforeRestart.analyzeAsync({
  input: { seriesId: 'run-killed', samples: samples.slice(0, 32) },
});
// simulate a brand-new process opening the same store directory
const reopenedStore = await new AuditStore({ root }).open();
const rpAfter = new Replayer({
  store: reopenedStore, calibrations, rules,
});
const r6 = await rpAfter.replay(killed.audit.recordId);
console.log(verdict(r6));
console.log('recovery events:',
  r6.evidence.recoveryEvents.length,
  '| processRestarted evidence:', r6.evidence.processRestarted);

// ---- 7. partial write / torn journal / tampering ------------------------
line('7. on-disk failure modes are classified distinctly');

const partialId = (await service.preview({
  input: { seriesId: 'partial', samples: samples.slice(0, 8) },
})).audit.recordId;
writeFileSync(
  join(root, 'records', partialId, 'result.json.tmp.4242.aband'),
  '{"partial"',
);
console.log('temp debris      =>', (await replayer.replay(partialId)).status);

const tornId = (await service.preview({
  input: { seriesId: 'torn', samples: samples.slice(0, 8) },
})).audit.recordId;
appendFileSync(join(root, 'records', tornId, 'events.log'), '{"seq":99,"payload":{');
console.log('torn event line  =>', (await replayer.replay(tornId)).status);

const tamperId = (await service.preview({
  input: { seriesId: 'tamper', samples: samples.slice(0, 8) },
})).audit.recordId;
const resultPath = join(root, 'records', tamperId, 'result.json');
const envelope = JSON.parse(readFileSync(resultPath, 'utf8'));
envelope.result.metrics.mean += 1;
writeFileSync(resultPath, JSON.stringify(envelope));
console.log('result tampered  =>', (await replayer.replay(tamperId)).status);

calibrations.register({
  calibrationId: 'mic-spare-Z', version: 'v2025-04',
  payload: { gain: 0.999, offset: 0.002, noiseFloor: 0.07 },
});
// A record pinned to the spare calibration; deleting ONLY its
// content-addressed blob does not affect the primary calibration records
// used by the other sections.
const spareResp = await service.preview({
  input: { seriesId: 'nocal', samples: samples.slice(0, 8) },
  calibrations: { primary: { calibrationId: 'mic-spare-Z', version: 'v2025-04' } },
});
const spareSha = spareResp.audit.calibrations[0].content.sha256;
rmSync(join(root, 'calibrations', `${spareSha}.json`));
console.log('calibration gone =>', (await replayer.replay(spareResp.audit.recordId)).status);

// ---- 8. concurrent replays ----------------------------------------------
line('8. concurrent replays of the same record');
const concurrent = await Promise.all(
  Array.from({ length: 8 }, () => replayer.replay(previewRecordId)),
);
console.log('all statuses:', new Set(concurrent.map((r) => r.status)).has('REPRODUCIBLE')
  ? '8 × REPRODUCIBLE' : 'UNEXPECTED');
console.log('peak concurrency observed:',
  Math.max(...concurrent.map((r) =>
    r.evidence.concurrency.peakConcurrentReplaysOfSameRecord)));

// ---- 9. float drift ------------------------------------------------------
line('9. rebuilt numeric runtime (Kahan summation) -> tolerance verdict');
const kahanStd = {
  naiveSum(v) {
    let s = 0, c = 0;
    for (const x of v) { const y = x - c; const t = s + y; c = (t - s) - y; s = t; }
    return s;
  },
  pairwiseSum: RULE_STDLIB.pairwiseSum,
  mean: RULE_STDLIB.mean, log10: Math.log10, pow: Math.pow,
};
const longSeries = Array.from({ length: 2000 }, (_, i) =>
  100 + (i % 4 < 2 ? 1 : -1) * 1e-12 + i * 1e-9);
const svcV1 = new AnalysisService({
  store, calibrations, rules,
  numericRuntime: { std: RULE_STDLIB, digest: stdlibDigest(RULE_STDLIB) },
});
const longRecord = (await svcV1.preview({
  input: { seriesId: 'long', samples: longSeries, baseline: 100 },
  rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' },
})).audit.recordId;
const rpKahan = new Replayer({
  store, calibrations, rules,
  numericRuntime: { std: kahanStd, digest: stdlibDigest(kahanStd) },
});
const r9 = await rpKahan.replay(longRecord);
console.log(verdict(r9));
console.log(`diff: ${r9.diff.status}, toleranceFields=${r9.diff.counts.toleranceFields}, maxULPs=${r9.diff.maxUlps}`);

console.log(`\nReplay reports persisted under ${join(root, 'replays')}`);
