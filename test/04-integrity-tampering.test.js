import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  writeFile,
  appendFile,
  readFile,
  mkdir,
  rm,
} from 'node:fs/promises';
import {
  buildSystem,
  cleanup,
  typicalRequest,
  canonicalJSON,
} from './helpers.js';
import { RECORD_PROBLEM } from '../src/index.js';

let root;
let sys;
let recordId;

beforeEach(async () => {
  sys = await buildSystem();
  root = sys.root;
  const resp = await sys.service.preview(typicalRequest());
  recordId = resp.audit.recordId;
});
afterEach(async () => {
  await cleanup(root);
});

async function recPath(name) {
  return `${root}/records/${recordId}/${name}`;
}

describe('partial writes are distinguishable from tampering', () => {
  test('leftover atomic-write temp file => REPLAY_BLOCKED_RECORD_PARTIAL', async () => {
    await writeFile(await recPath('result.json.tmp.9999.deadbeef'), '{"partial"');
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_PARTIAL');
    assert.equal(report.verdict, 'BLOCKED');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.PARTIAL_WRITE_DEBRIS));
    assert.deepEqual(report.evidence.debris.length >= 1, true);
  });

  test('torn (half-written) event line => REPLAY_BLOCKED_RECORD_PARTIAL', async () => {
    // Append garbage that cannot be a chained event.
    await appendFile(await recPath('events.log'), '{"seq":99,"payload":{');
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_PARTIAL');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.EVENT_TORN));
    // Valid chain up to the tear is still reported as evidence.
    const read = await sys.store.readRecord(recordId);
    assert.ok(read.events.valid.length >= 2);
    assert.equal(read.events.torn, true);
  });

  test('missing input snapshot => REPLAY_BLOCKED_INPUT_MISSING', async () => {
    await rm(await recPath('input.json'));
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_INPUT_MISSING');
    assert.equal(report.verdict, 'BLOCKED');
  });

  test('missing record directory entirely => corrupt/unknown record block', async () => {
    await rm(`${root}/records/${recordId}`, { recursive: true, force: true });
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_CORRUPT');
    assert.equal(report.verdict, 'BLOCKED');
  });
});

describe('tampering is detected by hashes and never forgiven', () => {
  test('altering result.json without the chain event => RESULT_DIGEST_MISMATCH => TAMPERED', async () => {
    const envelope = JSON.parse(await readFile(await recPath('result.json'), 'utf8'));
    envelope.result.metrics.mean = envelope.result.metrics.mean + 0.5;
    await writeFile(await recPath('result.json'), canonicalJSON(envelope));
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_TAMPERED');
    assert.equal(report.verdict, 'BLOCKED');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.RESULT_DIGEST_MISMATCH));
  });

  test('altering the recorded input => digest mismatch => CORRUPT (cannot trust evidence)', async () => {
    const req = JSON.parse(await readFile(await recPath('input.json'), 'utf8'));
    req.input.samples[0] = req.input.samples[0] + 1;
    await writeFile(await recPath('input.json'), canonicalJSON(req));
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_CORRUPT');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.INPUT_BLOB_CORRUPT));
  });

  test('rewriting an event breaks the chain and blocks replay', async () => {
    const raw = await readFile(await recPath('events.log'), 'utf8');
    const lines = raw.trim().split('\n');
    const first = JSON.parse(lines[0]);
    first.payload.kind = 'ASYNC_ANALYSIS'; // mutate history
    // recompute only this line's sha so the file parses but the chain lies
    lines[0] = JSON.stringify(first);
    await writeFile(await recPath('events.log'), lines.join('\n') + '\n');
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_CORRUPT');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.EVENT_CHAIN_BROKEN));
  });

  test('truncating the terminal event leaves result.json without a chain anchor', async () => {
    const raw = await readFile(await recPath('events.log'), 'utf8');
    const lines = raw.trim().split('\n');
    // Drop RESULT_PERSISTED while result.json remains on disk.
    await writeFile(await recPath('events.log'), lines.slice(0, -1).join('\n') + '\n');
    const read = await sys.store.readRecord(recordId);
    // Result envelope digest no longer has its RESULT_PERSISTED anchor; the
    // record is non-terminal and replay is blocked.
    assert.notEqual(read.status, 'COMPLETED');
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_INTERRUPTED');
  });

  test('swapping meta.json to point at different refs => META_REF_MISMATCH', async () => {
    const meta = JSON.parse(await readFile(await recPath('meta.json'), 'utf8'));
    meta.rule.version = '1.0.0';
    await writeFile(await recPath('meta.json'), canonicalJSON(meta));
    const report = await sys.replayer.replay(recordId);
    assert.equal(report.status, 'REPLAY_BLOCKED_RECORD_CORRUPT');
    assert.ok(report.state.problems.includes(RECORD_PROBLEM.META_REF_MISMATCH));
  });
});

describe('concurrent writers do not corrupt the journal', () => {
  test('many concurrent event appends produce one valid chain', async () => {
    const n = 25;
    await Promise.all(
      Array.from({ length: n }, (_, i) =>
        sys.store.appendEvent(recordId, { type: 'ANALYSIS_FAILED', at: new Date().toISOString(), errorCode: `E${i}` }),
      ),
    );
    const read = await sys.store.readRecord(recordId);
    assert.equal(read.events.brokenAt, -1);
    const raw = await readFile(await recPath('events.log'), 'utf8');
    const events = raw.trim().split('\n').map(JSON.parse);
    // seq must be contiguous 0..N-1, prev hashes linked.
    for (let i = 0; i < events.length; i++) {
      assert.equal(events[i].seq, i);
      assert.equal(events[i].prevSha, i === 0 ? null : events[i - 1].sha);
    }
  });
});
