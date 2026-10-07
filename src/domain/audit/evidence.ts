import { canonicalJson, digestOf, legacyInputDigest } from './canonical.ts';
import type { AnalysisRequest, AnalysisResult, CalibrationProfile } from '../types.ts';
import type { CalibrationRef, ResultSummary, StoredOutcome } from './types.ts';

/** analysisId is a random UUID per run — it must never participate in replay comparison. */
export type DeterministicResult = Omit<AnalysisResult, 'analysisId'>;

export function stripAnalysisId(result: AnalysisResult): DeterministicResult {
  const { analysisId: _analysisId, ...deterministic } = result;
  return deterministic;
}

export function buildCalibrationRefs(profiles: AnalysisRequest['calibrations']): CalibrationRef[] {
  return profiles
    .map((profile) => ({
      profileId: profile.profileId,
      channelId: profile.channelId,
      validFromNs: profile.validFromNs,
      ...(profile.validToNs === undefined ? {} : { validToNs: profile.validToNs }),
      contentDigest: digestOf(profile),
    }))
    .sort((a, b) => a.profileId.localeCompare(b.profileId) || a.channelId.localeCompare(b.channelId) || a.validFromNs - b.validFromNs);
}

export function calibrationProfileDigest(profile: CalibrationProfile): string {
  return digestOf(profile);
}

function summarizeSuccess(result: DeterministicResult): ResultSummary {
  return {
    resultDigest: digestOf(result),
    noiseClass: result.noise.class,
    amplitudeMean: result.metrics.amplitudeMean,
    amplitudeStdDev: result.metrics.amplitudeStdDev,
    phaseDriftRad: result.metrics.phaseDriftRad,
    decayTimeConstantNs: result.metrics.decay?.timeConstantNs ?? null,
    decayRSquared: result.metrics.decay?.rSquared ?? null,
    whiteLevel: result.noise.whiteLevel,
    integratedPower: result.noise.integratedPower,
    confidence: result.noise.confidence,
    dominantFrequencyHz: result.noise.dominantFrequencyHz,
    crossChannelCoherence: result.noise.crossChannelCoherence,
    sampleCount: result.metrics.sampleCount,
    channelCount: result.metrics.channelCount,
    spectrumBins: result.primarySpectrum.length,
    crossSpectrumBins: result.crossSpectrum.length,
    warnings: [...result.warnings],
  };
}

function failedSummary(error: { code: string; message: string }): ResultSummary {
  return {
    resultDigest: digestOf({ failed: error.code }),
    noiseClass: null,
    amplitudeMean: null,
    amplitudeStdDev: null,
    phaseDriftRad: null,
    decayTimeConstantNs: null,
    decayRSquared: null,
    whiteLevel: null,
    integratedPower: null,
    confidence: null,
    dominantFrequencyHz: null,
    crossChannelCoherence: null,
    sampleCount: null,
    channelCount: null,
    spectrumBins: null,
    crossSpectrumBins: null,
    warnings: [],
  };
}

export function summarizeOutcome(outcome: StoredOutcome): ResultSummary {
  return outcome.status === 'success' && outcome.result ? summarizeSuccess(outcome.result) : failedSummary(outcome.error ?? { code: 'UNKNOWN', message: 'Unknown failure' });
}

export function storeSuccess(result: AnalysisResult): StoredOutcome {
  const deterministic = stripAnalysisId(result);
  return { status: 'success', result: deterministic };
}

export function storeFailure(error: { code: string; message: string }): StoredOutcome {
  return { status: 'failed', error: { code: error.code, message: error.message } };
}

export { canonicalJson, digestOf, legacyInputDigest };
