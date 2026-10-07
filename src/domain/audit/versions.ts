/**
 * Pinned algorithm and rule versions. These are frozen into every audit record
 * so a replay can tell "same code, same result" apart from "algorithm changed":
 *
 * - ALGORITHM_VERSION: bump for any behavioral change in the analysis pipeline.
 * - rule versions: bump individual domain rule sets; the manifest maps every
 *   rule module to a version so partial upgrades remain distinguishable.
 *
 * The digest of the manifest is what `ruleVersion` pins; per-module versions
 * explain *which* rule changed when two replays differ.
 */
export const ALGORITHM_VERSION = 'analysis-algorithm-1.0.0';

export const RULE_VERSIONS = {
  'calibration.apply': 'calibration-1.0.0',
  'clock.synchronize': 'clock-sync-1.0.0',
  'signal.window': 'windowing-1.0.0',
  'signal.spectrum': 'spectrum-1.0.0',
  'noise.classify': 'noise-classify-1.0.0',
  'fit.decay': 'decay-fit-1.0.0',
} as const;

export type RuleModule = keyof typeof RULE_VERSIONS;

import { digestOf } from './canonical.ts';

export function getRuleManifest(): Record<string, string> {
  return { ...RULE_VERSIONS };
}

export function ruleManifestDigest(manifest: Record<string, string>): string {
  return digestOf(manifest);
}

export function currentRuleVersion(): string {
  return ruleManifestDigest(getRuleManifest());
}

export function diffRuleManifests(sealed: Record<string, string>, current: Record<string, string>): string[] {
  const modules = new Set([...Object.keys(sealed), ...Object.keys(current)]);
  return [...modules].filter((module) => sealed[module] !== current[module]).sort();
}
