import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import {
  buildSystem,
  cleanup,
  typicalRequest,
} from './helpers.js';
import {
  AuditStore,
  AnalysisService,
  Replayer,
  CalibrationRegistry,
  NoiseRuleRegistry,
  registerBuiltinRules,
  RECORD_STATUS,
  EVENT_TYPE,
} from '../src/index.js';

let root;
afterEach(async () => {
  if (root) await cleanup(root);
});

describe('process restart and interrupted records', () => {
  test('async job left ENQUEUED by a dead process is marked INTERRUPTED on reopen', async () => {
    sys1 = await freshSystem({
      // Scheduler captures the job but never runs it, simulating an
      // immediate process kill after enqueue.
      scheduler: () => {},
    });
    root = sys1.root;
    const job = await sys1.service.analyzeAsync(typicalRequest());
    assert.equal(job.status, 'ENQUEUED');

    // --- new process opens the same store; recovery runs ---
    const sys2 = await reopen(root);
    const record = await sys2.store.readRecord(job.audit.recordId);
    assert.equal(record.status, RECORD_STATUS.INTERRUPTED);
    const recovered = record.events.valid.find(
      (e) => e.payload.type === EVENT_TYPE.RECOVERED_AFTER_RESTART,
    );
    assert.ok(recovered, 'RECOVERED_AFTER_RESTART event appended');
    assert.equal(recovered.payload.originalSession, sys1.store.sessionId);
    assert.equal(recovered.payload.recoveredBySession, sys2.store.sessionId);
    assert.notEqual(sys1.store.sessionId, sys2.store.sessionId);

    // Replay is blocked with the distinct interrupted status.
    const report = await sys2.replayer.replay(job.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_INTERRUPTED');
    assert.equal(report.verdict, 'BLOCKED');
    assert.equal(report.reproducible, false);
    assert.equal(report.state.recoveredAfterRestart, true);
    assert.equal(report.evidence.processRestarted, true);
  });

  test('job that died mid-RUNNING is INTERRUPTED, not mistaken for success', async () => {
    // Enqueue with a scheduler that never runs the job, then deterministically
    // persist JOB_STARTED before the "crash".
    sys1 = await freshSystem({ scheduler: () => {} });
    root = sys1.root;
    const job = await sys1.service.analyzeAsync(typicalRequest());
    await sys1.store.markRunning(job.audit.recordId);
    const mid = await sys1.store.readRecord(job.audit.recordId);
    assert.equal(mid.status, RECORD_STATUS.RUNNING);

    const sys2 = await reopen(root);
    const record = await sys2.store.readRecord(job.audit.recordId);
    assert.equal(record.status, RECORD_STATUS.INTERRUPTED);
    const report = await sys2.replayer.replay(job.audit.recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_INTERRUPTED');
    assert.equal(report.state.lastEventType, EVENT_TYPE.RECOVERED_AFTER_RESTART);
  });

  test('a preview that crashed after RECORD_CREATED is INTERRUPTED on reopen', async () => {
    sys1 = await freshSystem({});
    root = sys1.root;
    // White-box: create a record directly without completing it.
    const { contentRef } = await import('../src/index.js');
    const request = typicalRequest();
    const resolved = await sys1.service._resolveAndFreeze(request);
    const recordId = await sys1.store.createRecord({
      kind: 'PREVIEW',
      request,
      inputRef: contentRef(request),
      calibrationRefs: resolved.calibrationRefs,
      ruleRef: resolved.frozenRule,
      engineInfo: sys1.engineInfo,
    });

    const sys2 = await reopen(root);
    const record = await sys2.store.readRecord(recordId);
    assert.equal(record.status, RECORD_STATUS.INTERRUPTED);
    const report = await sys2.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_INTERRUPTED');
  });

  test('completed records survive restart and still replay EXACT', async () => {
    sys1 = await freshSystem({});
    root = sys1.root;
    const resp = await sys1.service.preview(typicalRequest());
    const sys2 = await reopen(root);
    const record = await sys2.store.readRecord(resp.audit.recordId);
    assert.equal(record.status, RECORD_STATUS.COMPLETED);
    const report = await sys2.replayer.replay(resp.audit.recordId);
    assert.equal(report.status, 'REPRODUCIBLE');
    assert.equal(report.evidence.processRestarted, true);
  });

  test('completed records are not decorated with recovery events', async () => {
    sys1 = await freshSystem({});
    root = sys1.root;
    const resp = await sys1.service.preview(typicalRequest());
    await reopen(root);
    await reopen(root); // multiple restarts
    const sys3 = await reopen(root);
    const record = await sys3.store.readRecord(resp.audit.recordId);
    const recoveries = record.events.valid.filter(
      (e) => e.payload.type === EVENT_TYPE.RECOVERED_AFTER_RESTART,
    );
    assert.equal(recoveries.length, 0);
  });

  test('session log records process sessions; evidence cites both session ids', async () => {
    sys1 = await freshSystem({});
    root = sys1.root;
    const resp = await sys1.service.preview(typicalRequest());
    const sys2 = await reopen(root);
    const raw = await readFile(`${root}/session.log`, 'utf8');
    const starts = raw.trim().split('\n').map(JSON.parse)
      .filter((e) => e.type === 'SESSION_START');
    assert.ok(starts.length >= 2);
    const report = await sys2.replayer.replay(resp.audit.recordId);
    assert.equal(report.evidence.recordSessionId, sys1.store.sessionId);
    assert.equal(report.evidence.replaySessionId, sys2.store.sessionId);
  });
});

// ---------------------------------------------------------------- helpers --

let sys1;

async function freshSystem(opts) {
  return buildSystem(opts);
}

async function reopen(dir) {
  const calibrations = new CalibrationRegistry();
  calibrations.register({
    calibrationId: 'mic-array-A',
    version: 'v2025-09',
    payload: { gain: 1.0002, offset: -0.01, noiseFloor: 0.05 },
  });
  calibrations.publish('mic-array-A', 'v2025-09');
  const rules = new NoiseRuleRegistry();
  registerBuiltinRules(rules);
  const store = await new AuditStore({ root: dir }).open();
  const service = new AnalysisService({ store, calibrations, rules });
  const replayer = new Replayer({ store, calibrations, rules });
  return { store, service, replayer, calibrations, rules };
}
