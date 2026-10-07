import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AuditStore,
  AnalysisService,
  Replayer,
  CalibrationRegistry,
  NoiseRuleRegistry,
  registerBuiltinRules,
  currentEngineInfo,
} from '../src/index.js';

export async function makeTempRoot(label = 'audit') {
  return mkdtemp(join(tmpdir(), `${label}-`));
}

export async function cleanup(root) {
  await rm(root, { recursive: true, force: true });
}

/**
 * Build a fully wired system in a fresh temp directory.
 * @param {object} [opts]
 * @param {string} [opts.root]
 * @param {object} [opts.engineInfo]
 * @param {Function} [opts.scheduler]
 * @param {(rules:NoiseRuleRegistry, cal:CalibrationRegistry)=>void} [opts.setup]
 * @param {boolean} [opts.recover]
 */
export async function buildSystem(opts = {}) {
  const root = opts.root ?? await makeTempRoot();
  const calibrations = new CalibrationRegistry();
  const rules = new NoiseRuleRegistry();
  registerBuiltinRules(rules);
  calibrations.register({
    calibrationId: 'mic-array-A',
    version: 'v2025-09',
    payload: { gain: 1.0002, offset: -0.01, noiseFloor: 0.05 },
    metadata: { releasedAt: '2025-09-01' },
  });
  calibrations.publish('mic-array-A', 'v2025-09');
  const engineInfo = opts.engineInfo ?? {
    ...currentEngineInfo(),
  };
  const store = await new AuditStore({ root, engineInfo }).open({ recover: opts.recover ?? true });
  if (opts.setup) opts.setup(rules, calibrations);
  const service = new AnalysisService({
    store, calibrations, rules, engineInfo, scheduler: opts.scheduler,
  });
  const replayer = new Replayer({ store, calibrations, rules, engineInfo });
  return { root, store, service, replayer, calibrations, rules, engineInfo };
}

/** Deterministic PRNG (mulberry32) for reproducible test series. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function randomSeries(n, seed = 42, base = 0.11, spread = 0.02) {
  const rnd = mulberry32(seed);
  const samples = [];
  for (let i = 0; i < n; i++) {
    samples.push(base + (rnd() - 0.5) * 2 * spread + Math.sin(i / 17) * spread * 0.2);
  }
  return samples;
}

/**
 * Cancellation-style alternating series: 1, 1, -1, -1, 1, 1, ...
 * Naive left-to-right summation loses terms completely once the partial sum
 * exceeds 2^53; pairwise summation does not.  A realistic proxy for
 * accumulation-order float divergence on long acquisitions.
 */
export function cancellationSeries(n = 2000) {
  const samples = [];
  for (let i = 0; i < n; i++) samples.push(i % 4 < 2 ? 1 : -1);
  return samples;
}

export function typicalRequest(overrides = {}) {
  return {
    input: {
      seriesId: 'series-test-1',
      samples: randomSeries(64),
      baseline: 0,
      samplingRateHz: 1000,
    },
    params: {},
    ...overrides,
  };
}

export function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export { sha256Canonical, canonicalJSON, sha256Raw } from '../src/index.js';
