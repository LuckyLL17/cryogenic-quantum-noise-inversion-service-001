import { createHash, randomUUID } from 'node:crypto';
import {
  rm,
  rename,
  open,
  mkdir,
} from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * Canonical JSON: object keys sorted recursively, no insignificant
 * whitespace.  Used so that hashes depend on content, not on key order or
 * formatting.  Non-finite numbers are rejected (they have no stable JSON
 * representation and must never appear in a persisted result).
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJSON(value) {
  return JSON.stringify(_canonical(value));
}

function _canonical(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('Cannot canonicalize non-finite number');
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(_canonical);
  const out = {};
  for (const key of Object.keys(value).sort()) out[key] = _canonical(value[key]);
  return out;
}

/**
 * SHA-256 hex digest of a value's canonical JSON encoding.
 * @param {unknown} value
 */
export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJSON(value), 'utf8').digest('hex');
}

/** SHA-256 hex digest of a raw string/Buffer. */
export function sha256Raw(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Content descriptor: hash + length for an arbitrary JSON-able value.
 * @param {unknown} value
 * @returns {{sha256:string, bytes:number, encoding:'canonical-json'}}
 */
export function contentRef(value) {
  const body = canonicalJSON(value);
  return {
    sha256: createHash('sha256').update(body, 'utf8').digest('hex'),
    bytes: Buffer.byteLength(body, 'utf8'),
    encoding: 'canonical-json',
  };
}

export function uuid() {
  return randomUUID();
}

/**
 * Atomic file write: write to a unique temp file in the same directory,
 * fsync it, then rename over the target.  A crash leaves either the old file
 * or the new one — never a torn target.  The temp file may survive as
 * detectable "partial write debris".
 * @param {string} path
 * @param {string|Buffer} data
 */
export async function atomicWrite(path, data) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${uuid()}`;
  let fh;
  try {
    fh = await open(tmp, 'wx');
    await fh.writeFile(data);
    // Flush file contents before the rename so the new name never points at
    // unflushed blocks.
    await fh.sync();
    await fh.close();
    fh = undefined;
    await rename(tmp, path);
  } catch (err) {
    if (fh) await fh.close().catch(() => {});
    await rm(tmp, { force: true }).catch(() => {});
    throw err;
  }
}

/** Best-effort fsync of a directory (needed for durable renames). */
export async function fsyncDir(dir) {
  try {
    const fh = await open(dir, 'r');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch {
    // Some platforms do not support sync on directories; the rename itself
    // is still atomic, durability is best-effort there.
  }
}
