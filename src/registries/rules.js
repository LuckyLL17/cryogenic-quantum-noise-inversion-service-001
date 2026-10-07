import { sha256Canonical, sha256Raw } from '../util/hash.js';

/**
 * Versioned rule (analysis algorithm) registry.
 *
 * Two distinct hashes are tracked per rule version so that contract changes
 * and implementation rebuilds cannot be confused:
 *
 *  - specSha256: hash of the declarative rule SPEC (algorithm name, numeric
 *    parameters, feature definitions).  Same id+version must always mean the
 *    same spec; a conflicting registration throws.
 *  - implDigest: hash of the implementation function source.  Re-registering
 *    the same (id, version, spec) with rebuilt source is tracked
 *    (`implementationRebuilt`) rather than silently accepted.
 *
 * The audit store freezes BOTH the spec blob and the implementation source at
 * analysis time.  Faithful replay recompiles and executes the frozen source
 * when the live implementation differs — an upgraded algorithm never gets
 * used behind a replay's back.
 */

export class RuleSpecConflictError extends Error {
  constructor(ruleSetId, version) {
    super(`Rule ${ruleSetId}@${version} already registered with a different spec`);
    this.code = 'RULE_SPEC_CONFLICT';
  }
}

/** Pure helpers made available to rule implementations, including the
 * compiled-frozen ones.  Rule implementations must only depend on these
 * (plus their own arguments) so that frozen source stays executable. */
export const RULE_STDLIB = Object.freeze({
  naiveSum(values) {
    let s = 0;
    for (let i = 0; i < values.length; i++) s += values[i];
    return s;
  },
  /** Pairwise (cascade) summation — bounded relative error, order-stable. */
  pairwiseSum(values) {
    const n = values.length;
    if (n === 0) return 0;
    if (n <= 32) {
      let s = 0;
      for (let i = 0; i < n; i++) s += values[i];
      return s;
    }
    const half = n >> 1;
    return RULE_STDLIB.pairwiseSum(values.slice(0, half)) +
      RULE_STDLIB.pairwiseSum(values.slice(half));
  },
  mean(values, sum) {
    return values.length ? sum / values.length : 0;
  },
  log10(x) { return Math.log10(x); },
  pow(x, y) { return Math.pow(x, y); },
});

/**
 * Hash of a numeric-runtime (stdlib) implementation surface that rules rely
 * on.  A different value here means the numeric primitives under a replay
 * are not the ones the record was produced with (possible float drift
 * vector).
 * @param {typeof RULE_STDLIB} [std]
 */
export function stdlibDigest(std = RULE_STDLIB) {
  return sha256Raw(
    Object.keys(std).sort()
      .map((k) => `${k}:${std[k].toString()}`)
      .join('\n'),
  );
}

export class NoiseRuleRegistry {
  constructor() {
    /** @type {Map<string, Map<string, any>>} */
    this._rules = new Map();
    /** @type {Map<string, string>} ruleSetId -> current version */
    this._current = new Map();
  }

  /**
   * @param {object} args
   * @param {string} args.ruleSetId
   * @param {string} args.version
   * @param {object} args.spec declarative specification (must be JSON-able)
   * @param {(ctx:{input:any,params:any,calibration:Record<string,unknown>}, std:typeof RULE_STDLIB)=>unknown} args.analyze
   * @param {Record<string,string>} [args.metadata]
   */
  register({ ruleSetId, version, spec, analyze, metadata = {} }) {
    if (typeof analyze !== 'function') {
      throw new Error(`Rule ${ruleSetId}@${version} analyze must be a function`);
    }
    const specSha256 = sha256Canonical(spec);
    const implSource = analyze.toString();
    const implDigest = sha256Raw(implSource);
    let set = this._rules.get(ruleSetId);
    if (!set) {
      set = new Map();
      this._rules.set(ruleSetId, set);
    }
    const existing = set.get(version);
    if (existing) {
      if (existing.specSha256 !== specSha256) {
        throw new RuleSpecConflictError(ruleSetId, version);
      }
      if (existing.implDigest !== implDigest) {
        // Same contract, rebuilt implementation: keep history of impl digests.
        existing.implementationRebuilt = true;
        existing.knownImplDigests = [...new Set(
          [...(existing.knownImplDigests ?? [existing.implDigest]), implDigest],
        )];
        existing.analyze = analyze;
        existing.implSource = implSource;
        existing.implDigest = implDigest;
      }
      return existing;
    }
    const entry = {
      ruleSetId,
      version,
      spec,
      specSha256,
      analyze,
      implSource,
      implDigest,
      knownImplDigests: [implDigest],
      metadata,
    };
    set.set(version, entry);
    return entry;
  }

  /** Mark a registered rule version as the current default. */
  publish(ruleSetId, version) {
    if (!this.get(ruleSetId, version)) {
      throw new Error(`Cannot publish unknown rule ${ruleSetId}@${version}`);
    }
    this._current.set(ruleSetId, version);
  }

  get(ruleSetId, version) {
    return this._rules.get(ruleSetId)?.get(version);
  }

  require(ruleSetId, version) {
    const r = this.get(ruleSetId, version);
    if (!r) throw new Error(`Unknown rule ${ruleSetId}@${version}`);
    return r;
  }

  getCurrent(ruleSetId) {
    const v = this._current.get(ruleSetId);
    return v ? this.get(ruleSetId, v) : undefined;
  }

  currentVersion(ruleSetId) {
    return this._current.get(ruleSetId);
  }

  listVersions(ruleSetId) {
    return [...(this._rules.get(ruleSetId)?.values() ?? [])].map((e) => ({
      version: e.version,
      specSha256: e.specSha256,
      implDigest: e.implDigest,
      metadata: e.metadata,
    }));
  }

  ruleSetIds() {
    return [...this._rules.keys()];
  }
}

/**
 * Compile a frozen rule implementation source into an executable function.
 * Rule implementations are pure and receive all dependencies via arguments.
 * @param {string} source
 * @returns {(ctx:any, std:typeof RULE_STDLIB)=>unknown}
 */
export function compileFrozenImplementation(source) {
  // Wrapped in an expression so both function declarations/expressions and
  // arrow functions are valid.
  const factory = new Function('ctx', 'std', `return (${source})(ctx, std);`);
  return (ctx, std) => factory(ctx, std);
}
