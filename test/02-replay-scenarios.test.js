import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSystem,
  cleanup,
  typicalRequest,
} from './helpers.js';
import {
  AnalysisService,
  Replayer,
  AuditStore,
  CalibrationRegistry,
  CalibrationConflictError,
  SPEC_V2,
  analyzeV2,
} from '../src/index.js';

let root;
let sys;

beforeEach(async () => {
  sys = await buildSystem();
  root = sys.root;
});
afterEach(async () => {
  await cleanup(root);
});

describe('faithful replay — baseline reproducibility', () => {
  test('a fresh preview replays bit-for-bit: REPRODUCIBLE / EXACT', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.verdict, 'REPRODUCIBLE');
    assert.equal(report.reproducible, true);
    assert.equal(report.diff.status, 'EXACT');
    assert.equal(report.diff.counts.mismatchFields, 0);
    assert.equal(report.diff.counts.toleranceFields, 0);
    // Same pinned calibration and rule versions are echoed back.
    assert.deepEqual(report.calibrationVersions, { primary: 'v2025-09' });
    assert.equal(report.ruleVersion, '2.0.0');
    // Report is persisted outside the record directory.
    assert.match(report.reportPath, /replays/);
  });

  test('async completed jobs replay identically', async () => {
    const job = await sys.service.analyzeAsync(typicalRequest());
    const final = await sys.service.getJob(job.jobId, { waitMs: 1000 });
    assert.equal(final.status, 'SUCCEEDED');
    const report = await sys.replayer.replay(final.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.diff.status, 'EXACT');
  });

  test('replay never writes into the original record directory', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const before = await snapshotRecordDir(sys.root, resp.audit.recordId);
    await sys.replayer.replay(resp.audit.recordId);
    await sys.replayer.replay(resp.audit.recordId);
    const after = await snapshotRecordDir(sys.root, resp.audit.recordId);
    assert.deepEqual(after, before);
  });

  test('replayed result digest equals recorded result digest on success', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const record = await sys.store.readRecord(resp.audit.recordId);
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(
      report.replayedResultDigest.sha256,
      record.result.digest.sha256,
    );
  });
});

describe('historical calibration missing or drifted', () => {
  test('historical calibration absent from a post-restart registry => CALIBRATION_MISSING (frozen copy still replays)', async () => {
    const resp = await sys.service.preview(typicalRequest());
    // Simulate a NEW process whose registry only knows a newer calibration:
    // historical version is simply not registered anymore.
    const freshCal = new (sys.calibrations.constructor)();
    freshCal.register({
      calibrationId: 'mic-array-A',
      version: 'v2026-01',
      payload: { gain: 1.0003, offset: -0.009, noiseFloor: 0.04 },
    });
    freshCal.publish('mic-array-A', 'v2026-01');
    const replayer2 = new Replayer({
      store: sys.store, calibrations: freshCal, rules: sys.rules,
    });
    const report = await replayer2.replay(resp.audit.recordId);
    // Frozen copy makes faithful replay possible...
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.diff.status, 'EXACT');
    // ...and the evidence clearly says the historical binding is gone from
    // the live registry, while the frozen content was used.
    const check = report.evidence.calibrationChecks[0];
    assert.equal(check.frozenStatus, 'OK');
    assert.equal(check.registryStatus, 'NOT_REGISTERED');
  });

  test('frozen calibration blob deleted => distinct CALIBRATION_MISSING block', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const sha = resp.audit.calibrations[0].content.sha256;
    const { rm } = await import('node:fs/promises');
    await rm(joinStore(sys.root, 'calibrations', `${sha}.json`));
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_CALIBRATION_MISSING');
    assert.equal(report.verdict, 'BLOCKED');
    assert.equal(report.reproducible, false);
    assert.equal(report.state.failingRef.version, 'v2025-09');
  });

  test('frozen calibration blob corrupted => CALIBRATION_SNAPSHOT_CORRUPT', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const sha = resp.audit.calibrations[0].content.sha256;
    const { writeFile } = await import('node:fs/promises');
    await writeFile(
      joinStore(sys.root, 'calibrations', `${sha}.json`),
      JSON.stringify({ calibrationId: 'mic-array-A', version: 'v2025-09', payload: { gain: 9 }, content: { sha256: sha } }),
    );
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_CALIBRATION_SNAPSHOT_CORRUPT');
    assert.equal(report.verdict, 'BLOCKED');
  });

  test('registry binding for the pinned id@version drifts => flagged but frozen copy is used, still REPRODUCIBLE', async () => {
    const resp = await sys.service.preview(typicalRequest());
    // Attempt to overwrite same id@version with different payload: registry
    // refuses it outright.
    assert.throws(
      () => sys.calibrations.register({
        calibrationId: 'mic-array-A',
        version: 'v2025-09',
        payload: { gain: 2.5, offset: 0, noiseFloor: 0.01 },
      }),
      (err) => err instanceof CalibrationConflictError,
    );
    // Simulate a drifted external registry by mutating a clone around the
    // same id@version hash -> DRIFTED evidence path.
    const driftedCal = cloneRegistryWithDrift(sys.calibrations, {
      calibrationId: 'mic-array-A',
      version: 'v2025-09',
      payload: { gain: 2.5, offset: 0, noiseFloor: 0.01 },
    });
    const replayer2 = new Replayer({
      store: sys.store, calibrations: driftedCal, rules: sys.rules,
    });
    const report = await replayer2.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.diff.status, 'EXACT'); // frozen copy used
    const check = report.evidence.calibrationChecks[0];
    assert.equal(check.registryStatus, 'DRIFTED');
    assert.deepEqual(report.state.calibrationRegistryDrift, ['mic-array-A@v2025-09']);
    assert.ok(report.notes.some((n) => n.includes('DRIFTED')));
  });

  test('faithful replay does NOT silently use a newer current calibration', async () => {
    const resp = await sys.service.preview(typicalRequest());
    // New calibration published as current; record pinned the old one.
    sys.calibrations.register({
      calibrationId: 'mic-array-A',
      version: 'v2026-01',
      payload: { gain: 5, offset: 0, noiseFloor: 0.04 },
    });
    sys.calibrations.publish('mic-array-A', 'v2026-01');
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.deepEqual(report.calibrationVersions, { primary: 'v2025-09' });
    assert.equal(report.replayResult.calibrationVersions.primary, 'v2025-09');
  });
});

describe('algorithm upgrades', () => {
  test('record pinned v1: faithful replay uses v1 even though v2 is current', async () => {
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);
    assert.equal(resp.ruleVersion, '1.0.0');
    assert.equal(Object.keys(resp.result.metrics).includes('stddev'), false);
    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.ruleVersion, '1.0.0');
    assert.equal(report.state.upgradeAvailable, true);
    assert.equal(report.evidence.ruleCheck.currentVersion, '2.0.0');
    assert.equal('stddev' in report.replayResult.metrics, false);
  });

  test('compareWithCurrent reports what v2 WOULD produce without changing the verdict', async () => {
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);
    const report = await sys.replayer.replay(resp.audit.recordId, {
      compareWithCurrent: true,
    });
    assert.equal(report.status, 'REPRODUCIBLE'); // faithful verdict untouched
    const ref = report.currentReference;
    assert.equal(ref.possible, true);
    assert.equal(ref.ruleVersion, '2.0.0');
    assert.ok('stddev' in ref.result.metrics);
    // v2 adds fields => structural difference is reported explicitly
    assert.equal(ref.diff.status, 'STRUCTURAL_MISMATCH');
    assert.ok(ref.diff.structuralIssues.some((i) => i.key === 'stddev' || i.kind === 'extra-key'));
  });

  test('explicit CURRENT_REFERENCE mode yields an informational verdict, not a replay claim', async () => {
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);
    const report = await sys.replayer.replay(resp.audit.recordId, {
      mode: 'CURRENT_REFERENCE',
    });
    assert.equal(report.verdict, 'INFORMATIONAL');
    assert.ok(['CURRENT_REFERENCE_MATCH', 'CURRENT_REFERENCE_MISMATCH'].includes(report.status));
    assert.equal(report.ruleVersion, '1.0.0'); // pinned ref still reported
    assert.equal(report.currentReference.ruleVersion, '2.0.0');
  });

  test('historical rule version unregistered and no frozen source => RULE_VERSION_UNAVAILABLE', async () => {
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);
    // New process: v1 was never re-registered, AND frozen spec/source removed.
    const freshRules = new sys.rules.constructor();
    // only v2
    freshRules.register({
      ruleSetId: 'acoustic-noise', version: '2.0.0',
      spec: JSON.parse(JSON.stringify(SPEC_V2)), analyze: analyzeV2,
    });
    freshRules.publish('acoustic-noise', '2.0.0');
    const { rm } = await import('node:fs/promises');
    const ruleRef = resp.audit.rule;
    await rm(joinStore(sys.root, 'rules', `${ruleRef.specSha256}.json`), { force: true });
    const replayer2 = new Replayer({
      store: sys.store, calibrations: sys.calibrations, rules: freshRules,
    });
    const report = await replayer2.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE');
    assert.equal(report.verdict, 'BLOCKED');
  });
});

// ---------------------------------------------------------------- helpers --

import { readdir, readFile } from 'node:fs/promises';

function joinStore(root, ...parts) {
  return [root, ...parts].reduce((a, b) => `${a}/${b}`);
}

async function snapshotRecordDir(root, recordId) {
  const dir = `${root}/records/${recordId}`;
  const names = await readdir(dir);
  const out = {};
  for (const name of names.sort()) {
    out[name] = await readFile(`${dir}/${name}`, 'utf8');
  }
  return out;
}

/**
 * Build a registry that looks like the original but serves DIFFERENT content
 * under the same id@version (models external store drift / side-channel
 * tampering with the live binding).
 */
function cloneRegistryWithDrift(original, replacement) {
  const cloned = new CalibrationRegistry();
  for (const id of original.ids()) {
    for (const v of original.listVersions(id)) {
      if (v.version === replacement.version && id === replacement.calibrationId) continue;
      const e = original.get(id, v.version);
      cloned.register({ calibrationId: id, version: v.version, payload: e.payload });
    }
  }
  cloned.register({
    calibrationId: replacement.calibrationId,
    version: replacement.version,
    payload: replacement.payload,
  });
  return cloned;
}
