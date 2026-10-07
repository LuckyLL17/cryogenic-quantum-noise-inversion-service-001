import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { AuditStore } from '../src/application/audit-store.ts';
import { createServer } from '../src/http/server.ts';
import type { AnalysisRequest, CalibrationProfile, RawSample } from '../src/domain/types.ts';

const calibration: CalibrationProfile = { profileId: 'cal-1', channelId: 'ch-a', validFromNs: 0, adcScale: 2, iOffset: 0.1, qOffset: -0.2, gainCorrection: 1, phaseCorrectionRad: 0, temperatureCoefficientPerK: 0, referenceTemperatureK: 0.02, systematicUncertainty: 0.01, sampleUncertainty: 0.001 };
function sample(index: number): RawSample { return { captureId: `ch-a-${index}`, experimentId: 'exp-1', channelId: 'ch-a', role: 'readout-i', triggerId: `t-${Math.floor(index / 4)}`, timestampNs: index * 1_000_000, receivedAtNs: index * 1_000_000 + 100, sequence: index, sampleRateHz: 1_000, i: Math.cos(index / 4) + 0.1, q: Math.sin(index / 4) - 0.2, quality: 'good' }; }
const request: AnalysisRequest = { experimentId: 'exp-1', kind: 't1', samples: Array.from({ length: 32 }, (_, index) => sample(index)), calibrations: [calibration], analysis: { windowSize: 16 } };

async function withServer(run: (base: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'http-'));
  const server = createServer({ auditStore: new AuditStore({ dir }) });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
}

async function post(base: string, path: string, body: unknown, headers: Record<string, string> = {}): Promise<{ status: number; headers: Headers; json: any }> {
  const response = await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { status: response.status, headers: response.headers, json: await response.json() };
}
async function get(base: string, path: string): Promise<{ status: number; headers: Headers; json: any }> {
  const response = await fetch(base + path);
  return { status: response.status, headers: response.headers, json: await response.json() };
}

test('preview keeps the legacy response body fields and links evidence only via header', async () => {
  await withServer(async (base) => {
    const { status, headers, json } = await post(base, '/v1/experiments/preview', request);
    assert.equal(status, 200);
    // Old contract: no new audit fields appear in the body.
    assert.deepEqual(Object.keys(json).sort(), ['analysisId', 'calibrationVersions', 'crossSpectrum', 'experimentId', 'inputDigest', 'kind', 'metrics', 'noise', 'primarySpectrum', 'scanResults', 'warnings']);
    assert.equal(typeof json.analysisId, 'string');
    assert.ok(headers.get('x-audit-record-id'));

    const recordId = headers.get('x-audit-record-id')!;
    const recordResponse = await get(base, `/v1/audit/records/${recordId}`);
    assert.equal(recordResponse.status, 200);
    assert.equal(recordResponse.json.recordState, 'sealed');
    assert.equal(recordResponse.json.kind, 'preview');
    assert.equal(recordResponse.json.summary.sampleCount, 32);
  });
});

test('sealed replay over HTTP reproduces exactly and shows evidence + diff', async () => {
  await withServer(async (base) => {
    const sealed = await post(base, '/v1/experiments/preview', request);
    const recordId = sealed.headers.get('x-audit-record-id')!;

    const replay = await post(base, `/v1/audit/records/${recordId}/replay`, {});
    assert.equal(replay.status, 200);
    assert.equal(replay.json.status, 'reproduced');
    assert.equal(replay.json.reproducible, true);
    assert.deepEqual(replay.json.conditions, ['REPLAYED_EXACT']);
    assert.equal(replay.json.diff.match, 'exact');
    assert.equal(replay.json.evidence.chainIntegrity, 'verified');
    assert.equal(replay.json.evidence.recordIntegrity, 'sealed');
    assert.equal(replay.json.calibration.mode, 'sealed');
    assert.equal(replay.json.versions.currentAlgorithm, replay.json.versions.sealedAlgorithm);
  });
});

test('registry replay with missing calibration is 200 + unreplayable (a verdict, not a crash)', async () => {
  await withServer(async (base) => {
    const sealed = await post(base, '/v1/experiments/preview', request);
    const replay = await post(base, `/v1/audit/records/${sealed.headers.get('x-audit-record-id')!}/replay`, { calibration: { mode: 'registry', profiles: [] } });
    assert.equal(replay.status, 200);
    assert.equal(replay.json.status, 'unreplayable');
    assert.deepEqual(replay.json.conditions, ['CALIBRATION_MISSING']);
    assert.deepEqual(replay.json.calibration.missingProfileIds, ['cal-1']);
  });
});

test('replaying an unknown record returns 404 with RECORD_NOT_FOUND evidence state', async () => {
  await withServer(async (base) => {
    const replay = await post(base, '/v1/audit/records/nope/replay', {});
    assert.equal(replay.status, 404);
    assert.equal(replay.json.status, 'not-found');
    assert.deepEqual(replay.json.conditions, ['RECORD_NOT_FOUND']);
  });
});

test('a failed preview seals the rejected input and the failure replays identically', async () => {
  await withServer(async (base) => {
    const invalid = { ...request, samples: [] };
    const failed = await post(base, '/v1/experiments/preview', invalid);
    assert.equal(failed.status, 422);
    assert.equal(failed.json.error.code, 'EMPTY_SAMPLES');
    const recordId = failed.headers.get('x-audit-record-id');
    assert.ok(recordId);

    const replay = await post(base, `/v1/audit/records/${recordId}/replay`, {});
    assert.equal(replay.json.status, 'reproduced');
    assert.ok(replay.json.conditions.includes('OUTCOME_FAILED'));
    assert.equal(replay.json.replayOutcome.error.code, 'EMPTY_SAMPLES');
  });
});

test('async jobs keep the old 202/status body and gain evidence after completion', async () => {
  await withServer(async (base) => {
    const submitted = await post(base, '/v1/analyses', request);
    assert.equal(submitted.status, 202);
    assert.deepEqual(Object.keys(submitted.json).sort(), ['id', 'state']);
    const jobId = submitted.json.id;

    let status: any;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      status = await get(base, `/v1/analyses/${jobId}`);
      if (status.json.state === 'completed' || status.json.state === 'failed') break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(status.json.state, 'completed');
    assert.ok(!('auditRecordId' in status.json), 'job body must not grow audit fields');
    assert.equal(status.headers.get('x-audit-record-id') !== null, true);
    const list = await get(base, `/v1/audit/records?jobId=${jobId}`);
    assert.equal(list.json.records.length, 1);
    assert.equal(list.json.records[0].kind, 'async');

    // The completed job's evidence replays exactly.
    const replay = await post(base, `/v1/audit/records/${status.headers.get('x-audit-record-id')}/replay`, {});
    assert.equal(replay.json.status, 'reproduced');
  });
});

test('audit health and record listing endpoints expose recovery state', async () => {
  await withServer(async (base) => {
    await post(base, '/v1/experiments/preview', request);
    const health = await get(base, '/v1/audit/health');
    assert.equal(health.status, 200);
    assert.equal(health.json.recordsSealed, 1);
    assert.equal(health.json.recovery.chainBroken, false);

    const list = await get(base, '/v1/audit/records');
    assert.equal(list.json.records.length, 1);
    assert.equal(list.json.records[0].outcome.status, 'success');
  });
});
