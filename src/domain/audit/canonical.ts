import { createHash } from 'node:crypto';

/**
 * Deterministic JSON serialization with object keys sorted recursively.
 * Array order is preserved (it is semantically meaningful for samples/windows).
 * This canonical form is the only representation ever hashed into evidence.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(serialize).join(',')}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${serialize(record[key])}`).join(',')}}`;
}

export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function digestOf(value: unknown): string {
  return sha256(canonicalJson(value));
}

/**
 * The legacy digest embedded in AnalysisResult must stay byte-for-byte
 * identical to the previous implementation so old clients keep working:
 * it hashes JSON.stringify(request) without key sorting.
 */
export function legacyInputDigest(request: unknown): string {
  return createHash('sha256').update(JSON.stringify(request)).digest('hex');
}
