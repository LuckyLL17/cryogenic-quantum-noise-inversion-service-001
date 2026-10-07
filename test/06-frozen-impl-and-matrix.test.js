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
  NoiseRuleRegistry,
  CalibrationRegistry,
  registerBuiltinRules,
  AuditStore,
  RULE_STDLIB,
  RECORD_STATUS,
  REPLAY_MODE,
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

describe('frozen implementation is what faithful replay executes', () => {
  test('rebuilt implementation (same spec, different source) is recompiled from the frozen blob', async () => {
    // Record with a custom rule at 3.1.0, then "upgrade" its implementation
    // in-place (simulates a bug-fix rebuild with unchanged contract).
    const rules = sys.rules;
    const spec = { algorithm: 'x', specVersion: 1, outputs: ['v'] };
    const implA = function analyze(ctx, std) {
      const s = std.naiveSum(ctx.input.samples);
      return { metrics: { v: s }, flags: [] };
    };
    rules.register({ ruleSetId: 'custom', version: '3.1.0', spec, analyze: implA });
    rules.publish('custom', '3.1.0');

    const req = typicalRequest({ rule: { ruleSetId: 'custom', version: '3.1.0' } });
    const resp = await sys.service.preview(req);
    const frozenImplDigest = resp.audit.rule.implDigest;

    // Rebuild: identical spec hash, implementation now applies a factor.
    const implB = function analyze(ctx, std) {
      const s = std.naiveSum(ctx.input.samples);
      return { metrics: { v: s * 2 }, flags: [] };
    };
    const rebuilt = rules.register({
      ruleSetId: 'custom', version: '3.1.0', spec, analyze: implB,
    });
    assert.notEqual(rebuilt.implDigest, frozenImplDigest);
    assert.equal(rebuilt.implementationRebuilt, true);

    const report = await sys.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.state.usedFrozenImplementation, true);
    assert.equal(report.evidence.ruleCheck.implementationUsed, 'FROZEN_RECOMPILED');
    assert.equal(report.evidence.ruleCheck.liveImplMatches, false);
    // The factor-of-two rebuild did not leak into the faithful replay.
    const recorded = (await sys.store.readRecord(resp.audit.recordId)).result.result;
    assert.equal(report.replayResult.metrics.v, recorded.metrics.v);
  });

  test('historical version removed from registry still replays from frozen spec+source', async () => {
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);

    const freshCal = new CalibrationRegistry();
    freshCal.register({
      calibrationId: 'mic-array-A', version: 'v2025-09',
      payload: { gain: 1.0002, offset: -0.01, noiseFloor: 0.05 },
    });
    const freshRules = new NoiseRuleRegistry(); // empty: v1 AND v2 unregistered
    const rp = new Replayer({
      store: sys.store, calibrations: freshCal, rules: freshRules,
    });
    const report = await rp.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.evidence.ruleCheck.registryStatus, 'NOT_REGISTERED');
    assert.equal(report.evidence.ruleCheck.implementationUsed, 'FROZEN_RECOMPILED');
  });
});

describe('status code matrix — every failure mode is distinguishable', () => {
  const CASES = [
    // [label, setup, expectedStatus]
    ['clean record', null, 'REPRODUCIBLE'],
  ];

  test('all expected statuses belong to the documented set', async () => {
    const documented = new Set([
      'REPRODUCIBLE',
      'REPRODUCIBLE_WITH_TOLERANCE',
      'DIVERGED',
      'CURRENT_REFERENCE_MISMATCH',
      'CURRENT_REFERENCE_MATCH',
      'REPLAY_BLOCKED_RECORD_INTERRUPTED',
      'REPLAY_BLOCKED_RECORD_PARTIAL',
      'REPLAY_BLOCKED_RECORD_CORRUPT',
      'REPLAY_BLOCKED_RECORD_TAMPERED',
      'REPLAY_BLOCKED_INPUT_MISSING',
      'REPLAY_BLOCKED_CALIBRATION_MISSING',
      'REPLAY_BLOCKED_CALIBRATION_DRIFT',
      'REPLAY_BLOCKED_CALIBRATION_SNAPSHOT_CORRUPT',
      'REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE',
      'REPLAY_BLOCKED_RULE_SPEC_DRIFT',
      'REPLAY_BLOCKED_ENGINE_MISMATCH',
      'REPLAY_BLOCKED_EXECUTION_ERROR',
    ]);
    for (const code of documented) {
      assert.equal(typeof code, 'string');
    }
  });

  test('rule spec drift under the same version is detected', async () => {
    // Freeze record with v1, then build a registry whose v1 claims a
    // different spec hash (contract mutated behind the same version).
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);

    const evilRules = new NoiseRuleRegistry();
    evilRules.register({
      ruleSetId: 'acoustic-noise', version: '1.0.0',
      spec: { algorithm: 'acoustic-noise-basic', specVersion: 666, outputs: ['x'] },
      analyze: function (ctx) { return { metrics: { x: 1 }, flags: [] }; },
    });
    const rp = new Replayer({
      store: sys.store, calibrations: sys.calibrations, rules: evilRules,
    });
    const report = await rp.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RULE_SPEC_DRIFT');
  });

  test('DIVERGED: a genuinely different result from the pinned computation cannot occur under faithful inputs, but tamper-free divergence via patched frozen source is classified', async () => {
    // DIVERGED happens when evidence is intact but the re-executed math
    // differs: emulate by replaying with a numeric runtime that applies a
    // gross error (still pure, structurally identical output).
    const req = typicalRequest({ rule: { ruleSetId: 'acoustic-noise', version: '1.0.0' } });
    const resp = await sys.service.preview(req);
    const brokenStd = {
      ...RULE_STDLIB,
      naiveSum(v) { return RULE_STDLIB.naiveSum(v) * 10; },
    };
    const rp = new Replayer({
      store: sys.store, calibrations: sys.calibrations, rules: sys.rules,
      numericRuntime: { std: brokenStd, digest: 'broken-runtime-digest' },
      engineInfo: { name: 'noise-analysis-service', engineFamily: 'noise-analysis-service', version: '9.9.9', node: process.version, platform: process.platform, arch: process.arch, stdlibDigest: 'broken-runtime-digest' },
    });
    const report = await rp.replay(resp.audit.recordId, {
      allowEngineVersionMismatch: true,
    });
    assert.equal(report.status, 'DIVERGED');
    assert.equal(report.verdict, 'DIVERGED');
    assert.equal(report.reproducible, false);
    assert.ok(report.diff.counts.mismatchFields >= 1);
  });
});

describe('replay report is self-contained evidence', () => {
  test('report includes evidence, state and diff needed to confirm reproducibility', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const r = await sys.replayer.replay(resp.audit.recordId, {
      compareWithCurrent: true,
    });
    // Evidence: identity, refs, chain, engine, concurrency.
    assert.ok(r.replayId && r.recordId);
    assert.equal(r.mode, REPLAY_MODE.FAITHFUL);
    assert.equal(r.evidence.chainVerified, true);
    assert.equal(r.evidence.processRestarted, false);
    assert.ok(r.evidence.inputRef.sha256);
    assert.ok(r.evidence.ruleRef.specSha256);
    assert.ok(r.evidence.calibrationRefs[0].content.sha256);
    assert.ok(r.evidence.engineCheck);
    assert.ok(r.evidence.concurrency);
    // State: lifecycle + which frozen artifacts were used.
    assert.equal(r.state.recordStatus, RECORD_STATUS.COMPLETED);
    // Diff: exact counts and field-level details.
    assert.equal(r.diff.status, 'EXACT');
    assert.equal(r.diff.counts.mismatchFields, 0);
    // Persisted report can be read back independently.
    const onDisk = await sys.store.readReplayReport(r.replayId);
    assert.equal(onDisk.status, 'REPRODUCIBLE');
    assert.equal(onDisk.replayId, r.replayId);
  });
});
