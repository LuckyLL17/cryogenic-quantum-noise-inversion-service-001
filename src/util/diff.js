/**
 * Deterministic, tolerance-aware structural diff used to classify replay
 * results.  Three levels of numeric agreement are distinguished:
 *
 *   EXACT             - bit-for-bit identical (Object.is)
 *   WITHIN_TOLERANCE  - finite numbers differ but inside abs/rel/ULP budget
 *   MISMATCH          - numbers differ beyond the budget, or primitives differ
 *   STRUCTURAL_MISMATCH - shape differs (missing/extra keys, array length)
 *
 * Floating-point drift from a mathematically-equivalent implementation
 * (different summation order, fused operations, platform libm) therefore
 * never masquerades as "reproduced", and hard algorithmic divergence is not
 * excused by the tolerance budget.
 */

/**
 * @typedef {Object} DiffOptions
 * @property {number} [absTol] absolute tolerance (default 1e-9)
 * @property {number} [relTol] relative tolerance (default 1e-9)
 * @property {number} [ulpTol] max Float64 ULP distance considered tolerance (default 8)
 * @property {number} [maxReportedFields] cap on detailed field entries
 */

const DEFAULTS = Object.freeze({
  absTol: 1e-9,
  relTol: 1e-9,
  ulpTol: 8,
  maxReportedFields: 50,
});

export const DIFF_STATUS = Object.freeze({
  EXACT: 'EXACT',
  WITHIN_TOLERANCE: 'WITHIN_TOLERANCE',
  MISMATCH: 'MISMATCH',
  STRUCTURAL_MISMATCH: 'STRUCTURAL_MISMATCH',
});

/**
 * @param {unknown} expected value captured in the audit record
 * @param {unknown} actual   value produced by the replay run
 * @param {DiffOptions} [options]
 */
export function diffResults(expected, actual, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const acc = {
    opts,
    exactFields: 0,
    numericFields: 0,
    toleranceFields: 0,
    mismatchFields: 0,
    fields: [],
    structuralIssues: [],
    maxAbsError: 0,
    maxRelError: 0,
    maxUlps: 0,
  };
  _walk(expected, actual, '$', acc);

  let status;
  if (acc.structuralIssues.length > 0) status = DIFF_STATUS.STRUCTURAL_MISMATCH;
  else if (acc.mismatchFields > 0) status = DIFF_STATUS.MISMATCH;
  else if (acc.toleranceFields > 0) status = DIFF_STATUS.WITHIN_TOLERANCE;
  else status = DIFF_STATUS.EXACT;

  return {
    status,
    tolerance: { absTol: opts.absTol, relTol: opts.relTol, ulpTol: opts.ulpTol },
    counts: {
      exactFields: acc.exactFields,
      numericFields: acc.numericFields,
      toleranceFields: acc.toleranceFields,
      mismatchFields: acc.mismatchFields,
      structuralIssues: acc.structuralIssues.length,
    },
    maxAbsError: acc.maxAbsError,
    maxRelError: acc.maxRelError,
    maxUlps: acc.maxUlps,
    differingFields: acc.fields,
    structuralIssues: acc.structuralIssues,
  };
}

function _walk(expected, actual, path, acc) {
  if (typeof expected === 'number' || typeof actual === 'number') {
    _compareNumber(expected, actual, path, acc);
    return;
  }
  if (expected === null || actual === null ||
      typeof expected !== 'object' || typeof actual !== 'object') {
    if (Object.is(expected, actual)) {
      acc.exactFields++;
    } else {
      acc.mismatchFields++;
      _report(acc, { path, kind: 'value', expected, actual });
    }
    return;
  }
  const expArr = Array.isArray(expected);
  const actArr = Array.isArray(actual);
  if (expArr !== actArr) {
    acc.structuralIssues.push({
      path, kind: 'type', expected: expArr ? 'array' : 'object',
      actual: actArr ? 'array' : 'object',
    });
    return;
  }
  if (expArr) {
    if (expected.length !== actual.length) {
      acc.structuralIssues.push({
        path, kind: 'array-length', expected: expected.length, actual: actual.length,
      });
      return;
    }
    for (let i = 0; i < expected.length; i++) {
      _walk(expected[i], actual[i], `${path}[${i}]`, acc);
    }
    return;
  }
  const expKeys = Object.keys(expected);
  const actKeys = new Set(Object.keys(actual));
  for (const k of expKeys) {
    if (!actKeys.has(k)) {
      acc.structuralIssues.push({ path, kind: 'missing-key', key: k });
      continue;
    }
    _walk(expected[k], actual[k], `${path}.${k}`, acc);
  }
  for (const k of actKeys) {
    if (!Object.prototype.hasOwnProperty.call(expected, k)) {
      acc.structuralIssues.push({ path, kind: 'extra-key', key: k });
    }
  }
}

function _compareNumber(expected, actual, path, acc) {
  if (typeof expected !== 'number' || typeof actual !== 'number') {
    acc.mismatchFields++;
    _report(acc, { path, kind: 'value', expected, actual });
    return;
  }
  acc.numericFields++;
  if (Object.is(expected, actual)) {
    acc.exactFields++;
    return;
  }
  // Two NaNs were equal via Object.is; mixed finiteness is a hard mismatch.
  if (!Number.isFinite(expected) || !Number.isFinite(actual)) {
    acc.mismatchFields++;
    _report(acc, { path, kind: 'non-finite', expected, actual });
    return;
  }
  const absError = Math.abs(actual - expected);
  const relError = absError / Math.max(1, Math.abs(expected), Math.abs(actual));
  const ulps = ulpDistance(expected, actual);
  acc.maxAbsError = Math.max(acc.maxAbsError, absError);
  acc.maxRelError = Math.max(acc.maxRelError, relError);
  acc.maxUlps = Math.max(acc.maxUlps, ulps);

  const within =
    absError <= acc.opts.absTol ||
    relError <= acc.opts.relTol ||
    ulps <= acc.opts.ulpTol;
  if (within) {
    acc.toleranceFields++;
  } else {
    acc.mismatchFields++;
  }
  _report(acc, {
    path, kind: within ? 'numeric-tolerance' : 'numeric',
    expected, actual, absError, relError, ulps, withinTolerance: within,
  });
}

/** Distance between two finite Float64 values measured in ULP. */
export function ulpDistance(a, b) {
  if (Object.is(a, b)) return 0;
  const ba = floatToOrderedBigInt(a);
  const bb = floatToOrderedBigInt(b);
  return ba > bb ? Number(ba - bb) : Number(bb - ba);
}

function floatToOrderedBigInt(x) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setFloat64(0, x, false);
  let bits = new DataView(buf).getBigInt64(0, false);
  // Map to a monotonically ordered integer space.
  bits = bits < 0n ? ~bits : bits ^ (1n << 63n);
  return bits;
}

function _report(acc, entry) {
  if (acc.fields.length < acc.opts.maxReportedFields) acc.fields.push(entry);
}
