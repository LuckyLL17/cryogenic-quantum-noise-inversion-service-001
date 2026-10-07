import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  buildSystem,
  cleanup,
  typicalRequest,
  wait,
  sha256Canonical,
} from './helpers.js';
import { RECORD_STATUS } from '../src/index.js';

let root;
let sys;

beforeEach(async () => {
  sys = await buildSystem();
  root = sys.root;
});
afterEach(async () => {
  await cleanup(root);
});

describe('legacy response contract', () => {
  test('preview keeps the historical shape and adds only audit', async () => {
    const resp = await sys.service.preview(typicalRequest());
    // Legacy fields, unchanged semantics.
    assert.equal(typeof resp.inputDigest, 'string');
    assert.match(resp.inputDigest, /^[0-9a-f]{64}$/);
    assert.deepEqual(resp.calibrationVersions, { primary: 'v2025-09' });
    assert.equal(resp.ruleVersion, '2.0.0');
    assert.ok(resp.result.metrics);
    assert.ok(Array.isArray(resp.result.flags));
    // Exactly one new field.
    assert.deepEqual(
      Object.keys(resp).sort(),
      ['audit', 'calibrationVersions', 'inputDigest', 'result', 'ruleVersion'].sort(),
    );
    // inputDigest matches the legacy definition (hash of input only).
    assert.equal(resp.inputDigest, sha256Canonical(typicalRequest().input));
  });

  test('async response keeps the historical job shape', async () => {
    const job = await sys.service.analyzeAsync(typicalRequest());
    assert.deepEqual(
      Object.keys(job).sort(),
      ['audit', 'calibrationVersions', 'inputDigest', 'jobId', 'ruleVersion', 'status'].sort(),
    );
    assert.equal(job.status, 'ENQUEUED');
    const final = await sys.service.getJob(job.jobId, { waitMs: 1000 });
    assert.equal(final.status, 'SUCCEEDED');
  });
});

describe('immutable evidence preservation', () => {
  test('the COMPLETE input (not only inputDigest) is stored and verifies', async () => {
    const req = typicalRequest();
    const resp = await sys.service.preview(req);
    const record = await sys.store.readRecord(resp.audit.recordId);
    assert.equal(record.status, RECORD_STATUS.COMPLETED);
    // Full request snapshot round-trips identically.
    assert.deepEqual(record.request, req);
    // Stored digest equals canonical hash of the complete request.
    assert.equal(record.meta.input.sha256, sha256Canonical(req));
    assert.equal(record.meta.input.encoding, 'canonical-json');
    assert.ok(record.meta.input.bytes > 0);
  });

  test('calibration references pin id+version+content hash', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const record = await sys.store.readRecord(resp.audit.recordId);
    const ref = record.meta.calibrations[0];
    assert.equal(ref.calibrationId, 'mic-array-A');
    assert.equal(ref.version, 'v2025-09');
    assert.match(ref.content.sha256, /^[0-9a-f]{64}$/);
    // Frozen blob exists and re-hashes identically.
    const frozen = await sys.store.readFrozenCalibration(ref.content.sha256);
    assert.equal(frozen.status, 'OK');
    assert.equal(sha256Canonical(frozen.blob.payload), ref.content.sha256);
  });

  test('rule reference pins set, version, spec and implementation digests', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const r = resp.audit.rule;
    assert.equal(r.ruleSetId, 'acoustic-noise');
    assert.equal(r.version, '2.0.0');
    assert.match(r.specSha256, /^[0-9a-f]{64}$/);
    assert.match(r.implDigest, /^[0-9a-f]{64}$/);
    const spec = await sys.store.readFrozenRuleSpec(r.specSha256);
    assert.equal(spec.status, 'OK');
    assert.equal(spec.blob.version, '2.0.0');
    const source = await sys.store.readFrozenRuleSource(r.implDigest);
    assert.equal(typeof source, 'string');
    assert.ok(source.includes('pairwiseSum'));
  });

  test('result summary is persisted with a digest anchored in the event chain', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const record = await sys.store.readRecord(resp.audit.recordId);
    assert.ok(record.result.digestVerified);
    const persistedEvent = record.events.valid.find(
      (e) => e.payload.type === 'RESULT_PERSISTED',
    );
    assert.ok(persistedEvent);
    assert.equal(persistedEvent.payload.resultDigest.sha256, record.result.digest.sha256);
  });

  test('event journal is hash-chained from RECORD_CREATED to terminal event', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const raw = await readFile(
      join(sys.root, 'records', resp.audit.recordId, 'events.log'), 'utf8',
    );
    const events = raw.trim().split('\n').map(JSON.parse);
    assert.equal(events[0].payload.type, 'RECORD_CREATED');
    assert.equal(events[events.length - 1].payload.type, 'RESULT_PERSISTED');
    assert.equal(events[0].prevSha, null);
    for (let i = 1; i < events.length; i++) {
      assert.equal(events[i].prevSha, events[i - 1].sha);
      assert.equal(events[i].seq, i);
    }
  });

  test('async analysis persists ENQUEUED -> RUNNING -> RESULT_PERSISTED', async () => {
    const job = await sys.service.analyzeAsync(typicalRequest());
    await sys.service.getJob(job.jobId, { waitMs: 1000 });
    const record = await sys.store.readRecord(job.audit.recordId);
    const types = record.events.valid.map((e) => e.payload.type);
    assert.deepEqual(types, [
      'RECORD_CREATED', 'JOB_ENQUEUED', 'JOB_STARTED', 'RESULT_PERSISTED',
    ]);
  });

  test('engine descriptor (family/version/stdlib digest) is in the evidence', async () => {
    const resp = await sys.service.preview(typicalRequest());
    const record = await sys.store.readRecord(resp.audit.recordId);
    assert.equal(record.meta.engine.engineFamily, 'noise-analysis-service');
    assert.equal(record.meta.engine.version, '1.0.0');
    assert.match(record.meta.engine.stdlibDigest, /^[0-9a-f]{64}$/);
  });
});
