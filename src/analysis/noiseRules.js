/**
 * Built-in acoustic-noise analysis rule set, shipped in two versions:
 *
 *  - 1.0.0: basic level (mean / peak-to-peak / RMS / SNR), naive summation.
 *  - 2.0.0: adds stddev, linear drift slope and corrected SNR, pairwise
 *           summation for bounded round-off; stricter flagging.
 *
 * Rule implementations are PURE functions of (ctx, std): they close over
 * nothing, so their source text can be frozen at analysis time and
 * recompiled verbatim during faithful replay years later.
 *
 * ctx shape:
 *   { input: {seriesId, samples, baseline?, samplingRateHz?},
 *     params: object,
 *     calibrations: Record<name, {calibrationId, version, payload}> }
 */

export const RULE_SET_ID = 'acoustic-noise';

export const SPEC_V1 = Object.freeze({
  algorithm: 'acoustic-noise-basic',
  specVersion: 1,
  outputs: ['n', 'mean', 'min', 'max', 'peakToPeak', 'rms', 'snrDb'],
  thresholds: { noiseMarginDb: 6 },
});

export const SPEC_V2 = Object.freeze({
  algorithm: 'acoustic-noise-basic',
  specVersion: 2,
  outputs: [
    'n', 'mean', 'min', 'max', 'peakToPeak', 'rms', 'snrDb',
    'stddev', 'driftSlope', 'driftPerSample', 'correctedSnrDb',
  ],
  thresholds: { noiseMarginDb: 6, driftPerSample: 1e-6 },
});

/**
 * @param {{input:any, params:any, calibrations:Record<string,any>}} ctx
 * @param {import('../registries/rules.js').RULE_STDLIB} std
 */
export function analyzeV1(ctx, std) {
  const { input, calibrations } = ctx;
  const cal = calibrations.primary?.payload ?? { gain: 1, offset: 0, noiseFloor: 0 };
  const corrected = input.samples.map((v) => v * (cal.gain ?? 1) + (cal.offset ?? 0));
  const n = corrected.length;
  const sum = std.naiveSum(corrected);
  const mean = n ? sum / n : 0;
  const sq = corrected.map((v) => v * v);
  const rms = n ? Math.sqrt(std.naiveSum(sq) / n) : 0;
  let min = Infinity;
  let max = -Infinity;
  for (const v of corrected) { if (v < min) min = v; if (v > max) max = v; }
  if (n === 0) { min = 0; max = 0; }
  const peakToPeak = max - min;
  const baseline = input.baseline ?? 0;
  const signal = Math.abs(mean - baseline);
  const noiseFloor = cal.noiseFloor ?? 0;
  const snrDb = noiseFloor > 0 && signal > 0 ? 20 * std.log10(signal / noiseFloor) : null;
  // v1 threshold (inlined: frozen rule source must close over nothing).
  const margin = 6;
  const flags = [];
  if (snrDb !== null && snrDb < margin) flags.push('NOISE_MARGIN_BREACH');
  if (rms > (noiseFloor || 0) * std.pow(10, margin / 20)) flags.push('RMS_ABOVE_LIMIT');
  return {
    metrics: { n, mean, min, max, peakToPeak, rms, snrDb },
    flags,
  };
}

/**
 * @param {{input:any, params:any, calibrations:Record<string,any>}} ctx
 * @param {import('../registries/rules.js').RULE_STDLIB} std
 */
export function analyzeV2(ctx, std) {
  const { input, calibrations } = ctx;
  const cal = calibrations.primary?.payload ?? { gain: 1, offset: 0, noiseFloor: 0 };
  const corrected = input.samples.map((v) => v * (cal.gain ?? 1) + (cal.offset ?? 0));
  const n = corrected.length;
  const sum = std.pairwiseSum(corrected);
  const mean = n ? sum / n : 0;
  const sq = corrected.map((v) => v * v);
  const rms = n ? Math.sqrt(std.pairwiseSum(sq) / n) : 0;
  const variance = n ? std.pairwiseSum(corrected.map((v) => (v - mean) ** 2)) / n : 0;
  const stddev = Math.sqrt(variance);
  let min = Infinity;
  let max = -Infinity;
  for (const v of corrected) { if (v < min) min = v; if (v > max) max = v; }
  if (n === 0) { min = 0; max = 0; }
  const peakToPeak = max - min;
  // Simple least-squares drift slope (samples per index).
  let driftSlope = 0;
  if (n > 1) {
    const idx = corrected.map((_, i) => i);
    const mx = std.pairwiseSum(idx) / n;
    const my = mean;
    let num = 0;
    let den = 0;
    for (let i = 0; i < n; i++) {
      num += (i - mx) * (corrected[i] - my);
      den += (i - mx) ** 2;
    }
    driftSlope = den ? num / den : 0;
  }
  const baseline = input.baseline ?? 0;
  const signal = Math.abs(mean - baseline);
  const noiseFloor = cal.noiseFloor ?? 0;
  const snrDb = noiseFloor > 0 && signal > 0 ? 20 * std.log10(signal / noiseFloor) : null;
  const correctedSignal = Math.max(signal - driftSlope * n * 0.5, 0);
  const correctedSnrDb = noiseFloor > 0 && correctedSignal > 0
    ? 20 * std.log10(correctedSignal / noiseFloor)
    : null;
  const driftPerSample = Math.abs(driftSlope);
  // v2 thresholds (inlined so the frozen source is self-contained).
  const flags = [];
  if (snrDb !== null && snrDb < 6) {
    flags.push('NOISE_MARGIN_BREACH');
  }
  if (driftPerSample > 1e-6) flags.push('DRIFT_DETECTED');
  return {
    metrics: {
      n, mean, min, max, peakToPeak, rms, snrDb,
      stddev, driftSlope, driftPerSample, correctedSnrDb,
    },
    flags,
  };
}

/**
 * Register the built-in rule set at both versions and publish v2 as current.
 * @param {import('../registries/rules.js').NoiseRuleRegistry} registry
 */
export function registerBuiltinRules(registry) {
  registry.register({
    ruleSetId: RULE_SET_ID,
    version: '1.0.0',
    spec: SPEC_V1,
    analyze: analyzeV1,
    metadata: { releasedAt: '2023-01-15', note: 'legacy basic level' },
  });
  registry.register({
    ruleSetId: RULE_SET_ID,
    version: '2.0.0',
    spec: SPEC_V2,
    analyze: analyzeV2,
    metadata: { releasedAt: '2025-03-01', note: 'adds drift and corrected SNR' },
  });
  registry.publish(RULE_SET_ID, '2.0.0');
}
