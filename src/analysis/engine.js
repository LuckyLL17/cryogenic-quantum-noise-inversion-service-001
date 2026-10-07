import {
  RULE_STDLIB,
  compileFrozenImplementation,
  stdlibDigest,
} from '../registries/rules.js';
import { sha256Raw, sha256Canonical } from '../util/hash.js';

/**
 * Immutable description of the runtime that executed an analysis.  Captured
 * into every audit record and compared during replay.
 * @param {{name?:string, version?:string, stdlibDigest?:string}} [overrides]
 */
export function currentEngineInfo(overrides = {}) {
  return {
    name: overrides.name ?? 'noise-analysis-service',
    version: overrides.version ?? '1.0.0',
    engineFamily: overrides.engineFamily ?? (overrides.name ?? 'noise-analysis-service'),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    stdlibDigest: overrides.stdlibDigest ?? stdlibDigest(RULE_STDLIB),
  };
}

/**
 * Result of executing a rule: the summary that gets persisted and later
 * compared in replay.  Timestamps and other non-deterministic data are
 * deliberately excluded.
 * @typedef {Object} ExecutionResult
 * @property {object} metrics
 * @property {string[]} flags
 * @property {object} rule   {ruleSetId, version, specSha256, implDigest}
 * @property {object} calibrationVersions  legacy map: name -> version
 */

/**
 * Execute a live rule entry from the registry.
 * @param {object} args
 * @param {any} args.ruleEntry
 * @param {object} args.request
 * @param {Record<string,any>} args.calibrations resolved frozen/registry payloads
 * @param {typeof RULE_STDLIB} [args.std] numeric runtime (default built-in)
 * @returns {ExecutionResult}
 */
export function executeRule({ ruleEntry, request, calibrations, std = RULE_STDLIB }) {
  return _run(ruleEntry.analyze, ruleMetaOf(ruleEntry), { request, calibrations }, std);
}

/**
 * Execute a rule from frozen source — used by faithful replay when the live
 * implementation differs from the one recorded, or when the registry no
 * longer carries the historical version.
 * @param {object} args
 * @param {string} args.implSource
 * @param {object} args.ruleMeta {ruleSetId, version, specSha256, implDigest}
 * @param {object} args.request
 * @param {Record<string,any>} args.calibrations
 * @param {typeof RULE_STDLIB} [args.std]
 */
export function executeFrozenRule({ implSource, ruleMeta, request, calibrations, std = RULE_STDLIB }) {
  const analyze = compileFrozenImplementation(implSource);
  return _run(analyze, ruleMeta, { request, calibrations }, std);
}

function ruleMetaOf(entry) {
  return {
    ruleSetId: entry.ruleSetId,
    version: entry.version,
    specSha256: entry.specSha256,
    implDigest: entry.implDigest,
  };
}

function _run(analyze, ruleMeta, { request, calibrations }, std) {
  const ctx = {
    input: request.input,
    params: request.params ?? {},
    calibrations,
  };
  const out = analyze(ctx, std);
  const calibrationVersions = {};
  for (const [name, c] of Object.entries(calibrations)) {
    calibrationVersions[name] = c.version;
  }
  return {
    metrics: out.metrics ?? {},
    flags: out.flags ?? [],
    rule: {
      ruleSetId: ruleMeta.ruleSetId,
      version: ruleMeta.version,
      specSha256: ruleMeta.specSha256,
      implDigest: ruleMeta.implDigest,
    },
    calibrationVersions,
  };
}

export { sha256Raw, sha256Canonical };
